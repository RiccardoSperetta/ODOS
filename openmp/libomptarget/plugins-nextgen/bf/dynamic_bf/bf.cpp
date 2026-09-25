#include "bf.hpp"
#include "doca_comch.h"
#include "doca_ctx.h"
#include "doca_dev.h"
#include "doca_error.h"
#include "doca_log.h"
#include "doca_pe.h"
#include <cstddef>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

//TODO: add the DOCA sdk logs
//	ret = doca_log_backend_create_with_file_sdk(stdout, &sdk_log);


DOCA_LOG_REGISTER("libomptarget bf");
// Automatically executed when libomptarget.rtl.bf.so is loaded by dlopen()
__attribute__((constructor)) static void init_doca_logging() {
	int ret;
	ret = doca_log_backend_create_standard();
  if (ret != DOCA_SUCCESS)
    return;
  // Set global level to DEBUG (or INFO) to see everything
  doca_log_level_set_global_sdk_limit(DOCA_LOG_LEVEL_DEBUG);
}

// Essential callbacks used by DOCA comch send and receive tasks
void BlueFieldConnection::send_completion_cb(doca_comch_task_send *task,
                                union doca_data task_user_data,
                                union doca_data ctx_user_data) {
    doca_task_free(doca_comch_task_send_as_task(task));
}

void BlueFieldConnection::send_error_cb(doca_comch_task_send *task,
                           union doca_data task_user_data,
                           union doca_data ctx_user_data) {
    //auto *conn = static_cast<BlueFieldConnection *>(ctx_user_data.ptr);
    //conn->send_result  = doca_task_get_status(doca_comch_task_send_as_task(task));

		DOCA_LOG_ERR("async send failed: %s", doca_error_get_name(doca_task_get_status(doca_comch_task_send_as_task(task))));
    doca_task_free(doca_comch_task_send_as_task(task));
}

void BlueFieldConnection::message_recv_cb(doca_comch_event_msg_recv *event,
                           uint8_t *recv_buffer,
                           uint32_t msg_len,
                           doca_comch_connection *connection) {
    auto conn_data = doca_comch_connection_get_user_data(connection);
    auto *conn = static_cast<BlueFieldConnection *>(conn_data.ptr);

    memcpy(conn->rbuf, recv_buffer, msg_len); 
    conn->recv_got   = msg_len;
    conn->recv_ready = true;
}

int BlueField::send_buf(const void *buf, size_t sz)
{
	doca_error_t ret;
	size_t len, sent_len, ack_reset = 0;
	struct doca_comch_task_send *task;

	for (sent_len = 0; sent_len < sz;) {
		if (sz - sent_len > __MAX_SZ__)
			len = __MAX_SZ__;
		else
			len = sz - sent_len;

		//alloc task
		ret = doca_comch_client_task_send_alloc_init(
            this->conn.client, this->conn.connection,
            (const uint8_t *)buf + sent_len, len,
            &task);

		// Pool exhausted — the one case where we DO need to drain 
		// - HOPEFULLY we've built the system, revolving around __ACK_RESET__, in a way that we don't need this check
		//TODO: maybe make it cleaner... and log something
		while (ret == DOCA_ERROR_NO_MEMORY) {
				doca_pe_progress(conn.pe);   // let some in-flight sends complete, freeing slots
				ret = doca_comch_client_task_send_alloc_init(
						conn.client, conn.connection,
						(const uint8_t *)buf + sent_len, len,
						&task);
		}
		if (ret != DOCA_SUCCESS) {
			DOCA_LOG_ERR("bf send failed (alloc). %ld bytes", sz);
			return -1;
		}

		//TODO: verify if the submission happens in order, otherwise we would have to enforce it
		ret = doca_task_submit(doca_comch_task_send_as_task(task));
		if (ret != DOCA_SUCCESS) {
				DOCA_LOG_ERR("bf send failed (submit). %ld bytes", sz);
				doca_task_free(doca_comch_task_send_as_task(task));
				return -1;
		}

		if (ack_reset > __ACK_RESET__) {
			recv_buf(this->conn.rbuf, __MAX_SZ__);
			DOCA_LOG_DBG("ack after %ld bytes\n", sent_len);
			ack_reset = 0;
		}
		ack_reset += len;
		sent_len += len;
	}
	DOCA_LOG_DBG("buf sent: %ld of %ld bytes\n", sent_len, sz);

	return 0;
}

int BlueField::recv_buf(void *buf, size_t sz)
{
	size_t len, recvd_len, ack_reset = 0;

	for (recvd_len = 0; recvd_len < sz;) {
		if (sz - recvd_len > __MAX_SZ__)
			len = __MAX_SZ__;
		else
			len = sz - recvd_len;

		//wait for the receive callback to take place
		while (!this->conn.recv_ready)
			doca_pe_progress(this->conn.pe); //safe, since this is invoking the callbacks synchronously

		memcpy((char *)buf + recvd_len, this->conn.rbuf, conn.recv_got);
		recvd_len      += this->conn.recv_got;
		this->conn.recv_ready = false;   // clear the mailbox before asking pe_progress again

		if (ack_reset > __ACK_RESET__) {
			send_buf(this->conn.sbuf, __MAX_SZ__);
			DOCA_LOG_DBG("ack after %ld bytes\n", recvd_len);
			ack_reset = 0;
		}

		ack_reset += this->conn.recv_got;
	}
	DOCA_LOG_DBG("buf recvd: %ld of %ld\n", recvd_len, sz);

	return 0;
}

int DynamicLibrary::init(struct BlueField *bf)
{
  this->bf = bf;
  return 0;
}

/// ask for symbol address contained in binary image loaded on the DPU
void *DynamicLibrary::getAddressOfSymbol(const char *Sym)
{
  size_t entries_addr;

	struct bf_openmp_cmd cmd;
	cmd.cmd          = Command::CMD_GET_SYMADDR;
	cmd.load.hndl    = this->hndl;

	// first send for the command itself
  this->bf->send_buf(&cmd, sizeof(cmd));

	// second send to specify symbol name
	sprintf(this->bf->conn.sbuf, _DEM_ "%s\r\n" _DEM_, Sym);
	this->bf->send_buf(this->bf->conn.sbuf,  __MAX_SZ__);

	// reception for symbol address
	this->bf->recv_buf(this->bf->conn.rbuf, __MAX_SZ__);
	sscanf(this->bf->conn.rbuf, _DEM_ "%ld" _DEM_, &entries_addr);

	//Entry.addr = (void *)entries_addr;
	//lib->entries_table[i] = Entry;
	
  return (void *)entries_addr;
}

/// send binary image through DOCA comch to the DPU as a CMD_WRITE_IMAGE command
int DynamicLibrary::writeImage(void *Image, std::size_t ImageSize)
{
	int ret;
	struct bf_openmp_cmd cmd;
	cmd.cmd                = Command::CMD_WRITE_IMAGE;
	cmd.load.imglen        = (int64_t)ImageSize;
	//cmd.load.total_entries = (int64_t)lib->total_entries;

	ret = this->bf->send_buf((void*)&cmd, sizeof(cmd));
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("load binary cmd failed to send.");
		return 0;
	}

	this->bf->send_buf(Image, ImageSize);
	// wait for receivement of handle
	this->bf->recv_buf(this->bf->conn.rbuf, __MAX_SZ__);
	sscanf(this->bf->conn.rbuf, _DEM_ "%ld" _DEM_, (long *)&this->hndl);
	//printf("hndl %ld", (unsigned long)this->hndl);
	if (this->hndl == NULL) {
		DOCA_LOG_ERR("failed to get a valid hndl from DPU about the sent Image");
		return -1;
	}

	return 0;
}

void BlueField::getInfo(std::vector<std::string> &labels, std::vector<std::string> &info)
{
	DOCA_LOG_INFO("Gathering info for device");

  char     pci_buf[DOCA_DEVINFO_PCI_ADDR_SIZE];
  uint8_t ipv4_buf[8*DOCA_DEVINFO_IPV4_ADDR_SIZE];
  char   iface_buf[DOCA_DEVINFO_IFACE_NAME_SIZE];
  char   ibdev_buf[DOCA_DEVINFO_IBDEV_NAME_SIZE];
  //int dpa_support;
  //TODO: may as well change the max_sq_sz name
  uint32_t max_msg_sz, max_sq_sz, max_rq_sz, max_num_conns;

	doca_devinfo* local_info = doca_dev_as_devinfo(this->dev);
	if (local_info == NULL) {
		DOCA_LOG_ERR("Could not obtain info for this device");
		return;
	}

  doca_devinfo_get_pci_addr_str(local_info, pci_buf);
  doca_devinfo_get_ipv4_addr(local_info, ipv4_buf, DOCA_DEVINFO_IPV4_ADDR_SIZE);
  doca_devinfo_get_iface_name(local_info, iface_buf, DOCA_DEVINFO_IFACE_NAME_SIZE);
  doca_devinfo_get_ibdev_name(local_info, ibdev_buf, DOCA_DEVINFO_IBDEV_NAME_SIZE);
  //dpa_support = doca_devinfo_get_is_dpa_supported(doca_dev_as_devinfo(this->dev));

  doca_comch_cap_get_max_msg_size(local_info,    &max_msg_sz);
  //NOTE: max_sq_sz now describes the maximum number of in-flight, asynchronous send tasks the application 
  // can submit to the DOCA Progress Engine before having to wait for completion callbacks
  doca_comch_cap_get_max_send_tasks(local_info, &max_sq_sz);
  doca_comch_cap_get_max_recv_queue_size(local_info, &max_rq_sz);
  doca_comch_cap_get_max_clients(local_info,  &max_num_conns);

  //labels.push_back("PCI Address");
  //info.push_back(std::string(pci_buf));
  labels.push_back("IPv4 Address");
  info.push_back(std::string((char *)ipv4_buf));
  labels.push_back("iface");
  info.push_back(std::string(iface_buf));
  //labels.push_back("ibdev");
  //info.push_back(std::string(ibdev_buf));

  labels.push_back("cc max msg size");
  info.push_back(std::to_string(max_msg_sz));
  labels.push_back("cc max number of in-flight send tasks");
  info.push_back(std::to_string(max_sq_sz));
  labels.push_back("cc max recv queue size");
  info.push_back(std::to_string(max_rq_sz));
  labels.push_back("cc max num connections");
  info.push_back(std::to_string(max_num_conns));
}

/// Initialize the device as intended by DOCADeviceTy: 
int BlueField::init(int id, int mode)
{
	DOCA_LOG_INFO("Initializing device [%d]", id);
	
  int ret;
	uint32_t tmp_total_devices = 0;

  struct doca_devinfo **dev_list = NULL;

	this->dev = NULL;
  this->mode = mode;

  ret = doca_devinfo_create_list(&dev_list, &tmp_total_devices);
  if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Could not create devinfo list");
    return -1;
  }
  
	int req_device = 0;

	for (uint32_t i = 0; i < tmp_total_devices; ++i) {
		// guarantees to only count actually valid devices from the provided list
		if (doca_dma_cap_task_memcpy_is_supported(dev_list[i]) != DOCA_SUCCESS) {
				continue;
		}

		if (req_device == id) {
			this->id = id;
			break;
		}
			
		++req_device;
	}

	//FIXME: handle out of bound ids

	char pci_addr_str[DOCA_DEVINFO_PCI_ADDR_SIZE] = {0};
	doca_devinfo_get_pci_addr_str(dev_list[req_device], pci_addr_str);
	DOCA_LOG_INFO("Working on device [%d] - PCI address = %s", req_device, pci_addr_str);

	// opens the device for later use
  ret = doca_dev_open(dev_list[req_device], &this->dev);
  if (ret != DOCA_SUCCESS || this->dev == NULL) {
    DOCA_LOG_ERR("failed to open DOCA device");
    return -1;
  }

  doca_devinfo_destroy_list(dev_list);

  DynLib.init(this);

  return 0;
}

int BlueField::deinit() {
  DOCA_LOG_INFO("Deinitializing device [%d]\n", this->id);
	doca_error_t ret;
  // Teardown communication channel connection
  ret = (doca_error_t)this->disconnect();
	if (ret != 0) {
		return -1;
	}

  // Safely close the primary DOCA device handle
  if (this->dev != nullptr) {
    ret = doca_dev_close(this->dev);
    if (ret != DOCA_SUCCESS)
      fprintf(stderr, "[BF Host] Failed to close DOCA device: %s\n", doca_error_get_descr(ret));
    this->dev = nullptr;
  }

	DOCA_LOG_INFO("Deinitialization completed for device [%d]\n", this->id);

  return 0;
}

// NOTE: host (client) side ODOS is always in CLIENTMODE
int BlueField::connect()
{
	DOCA_LOG_INFO("Connecting device [%d] - A", this->id);

  doca_error_t ret;

	this->conn.client = nullptr;
	this->conn.ctx = nullptr;
	this->conn.pe = nullptr;
	this->conn.connection = nullptr;

	//context init
	ret = doca_pe_create(&this->conn.pe);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed creating pe, [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	ret = doca_comch_client_create(this->dev, SERVER_NAME, &this->conn.client);
	if (ret != DOCA_SUCCESS) {
			DOCA_LOG_ERR("failed to create comch client, [%s]", doca_error_get_name(ret));
			this->disconnect();
			return -1;
	}

	this->conn.ctx = doca_comch_client_as_ctx(this->conn.client);

	ret = doca_pe_connect_ctx(this->conn.pe, this->conn.ctx);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed adding pe context to client, [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	//ctx config: callbacks upons sending task completion
	ret = doca_comch_client_task_send_set_conf(
							this->conn.client, 
							this->conn.send_completion_cb, 
							this->conn.send_error_cb, 
							(__ACK_RESET__ / __MAX_SZ__ + 4)); //to match the __ACK_RESET__ = 32*__MAX_SZ__ (we allow for extra room)
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("doca_comch_client_task_send_set_conf failed, [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	// and receivement event
	ret = doca_comch_client_event_msg_recv_register(this->conn.client, this->conn.message_recv_cb);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("doca_comch_client_event_msg_recv_register failed, [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	//TODO: not mandatory, but doca_ctx_set_state_changed_cb could be nice to have

	ret = doca_ctx_start(this->conn.ctx);
	if (ret != DOCA_SUCCESS && ret != DOCA_ERROR_IN_PROGRESS) {
		DOCA_LOG_ERR("Failed to start client context (right at the start), [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	// Handshake Loop for connection establishment
	enum doca_ctx_states state;
	do {
		//FIXME: may write a better loop with timeout + checking return of doca_ctx_get_state
			doca_pe_progress(this->conn.pe);
			doca_ctx_get_state(this->conn.ctx, &state);
	} while (state == DOCA_CTX_STATE_STARTING);

	if (state != DOCA_CTX_STATE_RUNNING) {
			DOCA_LOG_ERR("Failed to start client context (even after waiting, but reached %d state)", state);
			this->disconnect();
			return -1;
	}

	// Precisely because we're on client we're sure (once context is running) that the connection has been established
	ret = doca_comch_client_get_connection(this->conn.client, &this->conn.connection);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get connection from client, [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	union doca_data user_data;
	//user_data needed upon receivement: callback will store buffer in BlueFieldConnection.rbuf buffer
	user_data.ptr = static_cast<void *>(&this->conn);
	ret = doca_comch_connection_set_user_data(this->conn.connection, user_data);
	if (ret != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set user_data for connection, [%s]", doca_error_get_name(ret));
		this->disconnect();
		return -1;
	}

	DOCA_LOG_INFO("connection established");
	return 0;
}

int BlueField::disconnect() {
  doca_error_t ret;
  enum doca_ctx_states state = DOCA_CTX_STATE_IDLE;

  // 1. Initiate context stop safely
  if (this->conn.ctx != nullptr) {
    ret = doca_ctx_stop(this->conn.ctx);
    if (ret != DOCA_SUCCESS && ret != DOCA_ERROR_IN_PROGRESS) {
      DOCA_LOG_ERR("[BF Host] Warning: Failed to initiate context stop: %s\n", doca_error_get_descr(ret));
			return -1;
    }

    // 2. Draining loop with a timeout guard to prevent locking up LLVM host threads
		// = wait for the pe to process all pending tasks/events -> actually bringing the state to IDLE
    int timeout_counter = 1000;
    do {
      if (this->conn.pe != nullptr)
        doca_pe_progress(this->conn.pe);

      ret = doca_ctx_get_state(this->conn.ctx, &state);
      if (ret != DOCA_SUCCESS) {
        DOCA_LOG_ERR( "[BF Host] Failed to query context state: %s\n", doca_error_get_descr(ret));
        return -1;
      }

      if (--timeout_counter <= 0) {
        DOCA_LOG_ERR( "[BF Host] Timed out waiting for context state IDLE (current: %d)\n", state);
        break;
      }
			usleep(100);
    } while (state != DOCA_CTX_STATE_IDLE);
  }

  // 3. Destroy client and progress engine (sets handles to nullptr for idempotency)
  if (this->conn.client != nullptr) {
    ret = doca_comch_client_destroy(this->conn.client);
    if (ret != DOCA_SUCCESS) {
			DOCA_LOG_ERR( "[BF Host] Failed to destroy comch client: %s\n", doca_error_get_descr(ret));
			return -1;
		}
    this->conn.client = nullptr;
    this->conn.ctx = nullptr; // Released by comch_client_destroy
  }

  if (this->conn.pe != nullptr) {
    ret = doca_pe_destroy(this->conn.pe);
    if (ret != DOCA_SUCCESS) {
      DOCA_LOG_ERR( "[BF Host] Failed to destroy PE: %s\n", doca_error_get_descr(ret));
			return -1;
		}
    this->conn.pe = nullptr;
  }

  return 0;
}

// needed for DOCAPluginTy implementation of initImpl
std::size_t bfGetTotalDevices()
{
  int i, ret;
  unsigned int total_devices, tmp_total_devices;

  struct doca_devinfo **dev_list;
  ret = doca_devinfo_create_list(&dev_list, &tmp_total_devices);
  if (ret != DOCA_SUCCESS) {
    return 0;
  }
  
  for (i = 0, total_devices = 0; i < tmp_total_devices; ++i) {
    ret = doca_dma_cap_task_memcpy_is_supported(dev_list[i]);
    if (ret != DOCA_SUCCESS) {
      continue;
    }
  
    ++total_devices;
  }
  doca_devinfo_destroy_list(dev_list);

  return total_devices;
}
