/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <glib.h>

#include "vconf.h"
#include "security-server.h"

#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_service_private.h"
#include "net_nfc_service_llcp_private.h"
#include "net_nfc_service_llcp_handover_private.h"
#include "net_nfc_service_tag_private.h"
#include "net_nfc_service_se_private.h"
#include "net_nfc_service_test_private.h"
#include "net_nfc_manager_util_private.h"
#include "net_nfc_server_context_private.h"

static GQueue *g_dispatcher_queue;
static pthread_cond_t g_dispatcher_queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_dispatcher_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_dispatcher_thread;

static void *_net_nfc_dispatcher_thread_func(void *data);

static bool _net_nfc_check_dispatcher_privilege(net_nfc_request_msg_t *msg);

static net_nfc_request_msg_t *_net_nfc_dispatcher_queue_pop();

static net_nfc_request_msg_t *_net_nfc_dispatcher_queue_pop()
{
	net_nfc_request_msg_t *msg = NULL;
	msg = g_queue_pop_head(g_dispatcher_queue);
	return msg;
}

void net_nfc_dispatcher_queue_push(net_nfc_request_msg_t *req_msg)
{
	pthread_mutex_lock(&g_dispatcher_queue_lock);
	g_queue_push_tail(g_dispatcher_queue, req_msg);
	pthread_cond_signal(&g_dispatcher_queue_cond);
	pthread_mutex_unlock(&g_dispatcher_queue_lock);
}

void net_nfc_dispatcher_cleanup_queue(void)
{
	net_nfc_request_msg_t *req_msg = NULL;

	pthread_mutex_lock(&g_dispatcher_queue_lock);

	DEBUG_SERVER_MSG("cleanup dispatcher Q start");

	while ((req_msg = _net_nfc_dispatcher_queue_pop()) != NULL)
	{
		DEBUG_ERR_MSG("abandon request : %d", req_msg->request_type);
		_net_nfc_util_free_mem(req_msg);
	}

	DEBUG_SERVER_MSG("cleanup dispatcher Q end");

	pthread_mutex_unlock(&g_dispatcher_queue_lock);
}

void net_nfc_dispatcher_put_cleaner(void)
{
	net_nfc_request_msg_t *req_msg = NULL;

	_net_nfc_util_alloc_mem(req_msg, sizeof(net_nfc_request_msg_t));
	if (req_msg != NULL)
	{
		DEBUG_SERVER_MSG("put cleaner request");

		req_msg->length = sizeof(net_nfc_request_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_CLEANER;
		net_nfc_dispatcher_queue_push(req_msg);
	}
}

static void *_net_nfc_dispatcher_copy_message(void *msg)
{
	net_nfc_request_msg_t *origin = (net_nfc_request_msg_t *)msg;
	net_nfc_request_msg_t *result = NULL;

	if (origin == NULL || origin->length == 0)
	{
		return result;
	}

	_net_nfc_util_alloc_mem(result, origin->length);
	if (result != NULL)
	{
		memcpy(result, origin, origin->length);
	}

	return result;
}

bool net_nfc_dispatcher_start_thread()
{
	net_nfc_request_msg_t *req_msg = NULL;
	pthread_attr_t attr;
	int result, state;

	DEBUG_SERVER_MSG("init queue");

	g_dispatcher_queue = g_queue_new();

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &state);
	if (result != 0)
	{
		DEBUG_SERVER_MSG("VCONFKEY_NFC_STATE is not exist: %d ", result);
		return false;
	}

	DEBUG_SERVER_MSG("net_nfc_dispatcher_start_thread vconf state value [%d]", state);

	if (state == TRUE)
	{
		_net_nfc_util_alloc_mem(req_msg, sizeof(net_nfc_request_msg_t));
		if (req_msg == NULL)
		{
			DEBUG_ERR_MSG("alloc failed");
			return false;
		}

		req_msg->length = sizeof(net_nfc_request_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_INIT;

		DEBUG_SERVER_MSG("put controller init request");
		net_nfc_dispatcher_queue_push(req_msg);
	}
	else
	{
		/*Don't need to initialize the stack!!*/
	}

	if (pthread_create(&g_dispatcher_thread, &attr, _net_nfc_dispatcher_thread_func, NULL) != 0)
	{
		net_nfc_dispatcher_cleanup_queue();
		DEBUG_ERR_MSG("pthread_create failed");
		return false;
	}

	usleep(0); /* switch to new thread */
	return true;
}

static void *_net_nfc_dispatcher_thread_func(void *data)
{
	net_nfc_request_msg_t *req_msg;

	DEBUG_SERVER_MSG("net_nfc_controller_thread is created ");

	while (1)
	{
		pthread_mutex_lock(&g_dispatcher_queue_lock);
		if ((req_msg = _net_nfc_dispatcher_queue_pop()) == NULL)
		{
			pthread_cond_wait(&g_dispatcher_queue_cond, &g_dispatcher_queue_lock);
			pthread_mutex_unlock(&g_dispatcher_queue_lock);
			continue;
		}
		pthread_mutex_unlock(&g_dispatcher_queue_lock);

//		DEBUG_SERVER_MSG("net_nfc_controller get command = [%d]", req_msg->request_type);

#if 1
		if (!_net_nfc_check_dispatcher_privilege(req_msg))
		{
//			_net_nfc_util_free_mem(req_msg);
//			continue;
		}
#endif

		switch (req_msg->request_type)
		{
		case NET_NFC_MESSAGE_SERVICE_CLEANER :
			{
				net_nfc_service_se_cleanup();
			}
			break;

		case NET_NFC_MESSAGE_SEND_APDU_SE :
			{
				net_nfc_service_se_send_apdu(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_GET_ATR_SE :
			{
				net_nfc_service_se_get_atr(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_CLOSE_INTERNAL_SE :
			{
				net_nfc_service_se_close_se(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_OPEN_INTERNAL_SE :
			{
				net_nfc_service_se_open_se(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SET_SE :
			{
				net_nfc_service_se_set_se(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_GET_SE :
			{
				net_nfc_service_se_get_se(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_CARD_EMULATION_CHANGE_SE :
			{
				net_nfc_service_se_change_card_emulation_mode(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_P2P_SEND :
			{
				net_nfc_request_p2p_send_t *exchanger = (net_nfc_request_p2p_send_t *)req_msg;

				if (net_nfc_server_is_target_connected(exchanger->handle))
				{
					if (net_nfc_service_send_exchanger_msg(exchanger) != NET_NFC_OK)
					{
						DEBUG_SERVER_MSG("net_nfc_service_send_exchanger_msg is failed");

						/*send result to client*/
						net_nfc_response_p2p_send_t resp_msg = { 0, };

						resp_msg.handle = exchanger->handle;
						resp_msg.result = NET_NFC_P2P_SEND_FAIL;
						resp_msg.trans_param = (void *)exchanger->user_param;

						if (net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, &resp_msg, sizeof(net_nfc_response_p2p_send_t), NULL) == true)
						{
							DEBUG_SERVER_MSG("send exchange failed message to client");
						}
					}
				}
				else
				{
					net_nfc_response_p2p_send_t resp_msg = { 0, };

					resp_msg.handle = exchanger->handle;
					resp_msg.result = NET_NFC_TARGET_IS_MOVED_AWAY;
					resp_msg.trans_param = (void *)exchanger->user_param;

					net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, &resp_msg, sizeof(net_nfc_response_p2p_send_t), NULL);
				}
			}
			break;

		case NET_NFC_MESSAGE_TRANSCEIVE :
			{
				net_nfc_request_transceive_t *detail = (net_nfc_request_transceive_t *)req_msg;
				net_nfc_error_e result = NET_NFC_OK;
				data_s *data = NULL;

				if (net_nfc_server_is_target_connected(detail->handle))
				{
					net_nfc_transceive_info_s info;

					if (net_nfc_util_duplicate_data(&info.trans_data, &detail->info.trans_data) == true)
					{
						bool success;

						DEBUG_MSG("call transceive");
						if ((success = net_nfc_controller_transceive(detail->handle, &info, &data, &result)) == true)
						{
							if (data != NULL)
								DEBUG_SERVER_MSG("trasceive data recieved [%d], Success = %d", data->length, success);
						}
						else
						{
							DEBUG_SERVER_MSG("trasceive is failed = [%d]", result);
						}
						net_nfc_util_free_data(&info.trans_data);
					}
				}
				else
				{
					result = NET_NFC_TARGET_IS_MOVED_AWAY;
				}

				if (net_nfc_server_check_client_is_running(req_msg->client_fd))
				{
					net_nfc_response_transceive_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_transceive_t);
					resp.flags = detail->flags;
					resp.trans_param = detail->trans_param;
					resp.result = result;

					if (result == NET_NFC_OK && data != NULL)
					{
						resp.data.length = data->length;

						DEBUG_SERVER_MSG("send response trans msg");
						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_transceive_t),
								data->buffer, data->length, NULL);
					}
					else
					{
						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_transceive_t), NULL);
					}
				}

				if (data != NULL)
				{
					net_nfc_util_free_data(data);
					_net_nfc_util_free_mem(data);
				}
			}
			break;

		case NET_NFC_MESSAGE_MAKE_READ_ONLY_NDEF :
			{
				net_nfc_service_tag_make_readonly(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_IS_TAG_CONNECTED :
			{
				net_nfc_service_is_tag_connected(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO :
			{
				net_nfc_service_get_current_tag_info(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE :
			{
				net_nfc_service_get_current_target_handle(req_msg);
			}
			break;

		case NET_NFC_GET_SERVER_STATE :
			{
				net_nfc_service_get_server_state(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_READ_NDEF :
			{
				net_nfc_service_tag_read_ndef(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_WRITE_NDEF :
			{
				net_nfc_service_tag_write_ndef(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_FORMAT_NDEF :
			{
				net_nfc_service_tag_format_ndef(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SIM_TEST :
			{
				net_nfc_service_test_sim_test(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_GET_FIRMWARE_VERSION :
			{
				net_nfc_service_test_get_firmware_version(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_PRBS_TEST :
			{
				net_nfc_service_test_prbs_test(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SET_EEDATA :
			{
				net_nfc_service_test_set_eedata(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_DEINIT :
			{
				net_nfc_service_deinit(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_INIT :
			{
				net_nfc_service_init(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_STANDALONE_TARGET_DETECTED :
			{
#ifndef BROADCAST_MESSAGE
				net_nfc_service_standalone_mode_target_detected(req_msg);
#endif
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_RESTART_POLLING_LOOP :
			{
				net_nfc_service_restart_polling(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SE_START_TRANSACTION :
			{
				net_nfc_service_se_transaction_receive(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_ACCEPT :
			{
				net_nfc_service_llcp_process_accept(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_DEACTIVATED :
			{
				net_nfc_service_llcp_disconnect_target(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ERROR :
			{
				net_nfc_service_llcp_process_socket_error(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ACCEPTED_ERROR :
			{
				net_nfc_service_llcp_process_accepted_socket_error(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_SEND :
			{
				net_nfc_service_llcp_process_send_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_SEND_TO :
			{
				net_nfc_service_llcp_process_send_to_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE :
			{
				net_nfc_service_llcp_process_receive_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE_FROM :
			{
				net_nfc_service_llcp_process_receive_from_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT :
			{
				net_nfc_service_llcp_process_connect_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT_SAP :
			{
				net_nfc_service_llcp_process_connect_sap_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_DISCONNECT :
			{
				net_nfc_service_llcp_process_disconnect_socket(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_SE :
			{
				net_nfc_service_se_set_se(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_TERMINATION :
			{
				net_nfc_service_termination(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_SLAVE_TARGET_DETECTED :
			{
				net_nfc_service_slave_mode_target_detected(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_SLAVE_ESE_DETECTED :
			{
				net_nfc_service_se_detected(req_msg);
			}
			break;

		case NET_NFC_MESSAGE_LLCP_LISTEN :
			{
				net_nfc_request_listen_socket_t *detail = (net_nfc_request_listen_socket_t *)req_msg;
				net_nfc_response_llcp_socket_error_t *error = NULL;
				net_nfc_error_e result = NET_NFC_OK;
				bool success = false;

				_net_nfc_util_alloc_mem(error, sizeof (net_nfc_response_llcp_socket_error_t));
				if (error == NULL)
				{
					DEBUG_SERVER_MSG("ERROR: allocation is failed");
					break;
				}

				error->length = sizeof(net_nfc_response_llcp_socket_error_t);
				error->client_socket = detail->client_socket;
				error->handle = detail->handle;

				success = net_nfc_controller_llcp_create_socket(&(detail->oal_socket), detail->type, detail->miu, detail->rw, &result, error);
				if (success == true)
				{
					error->oal_socket = detail->oal_socket;
					success = net_nfc_controller_llcp_bind(detail->oal_socket, detail->sap, &result);
				}
				else
				{
					_net_nfc_util_free_mem(error);
				}

				if (success == true)
				{
					DEBUG_SERVER_MSG("OAL socket in Listen :%d", detail->oal_socket);
					success = net_nfc_controller_llcp_listen(detail->handle, detail->service_name.buffer, detail->oal_socket, &result, error);
				}

				if (net_nfc_server_check_client_is_running(req_msg->client_fd))
				{
					net_nfc_response_listen_socket_t resp = { 0 };

					resp.length = sizeof(net_nfc_response_listen_socket_t);
					resp.flags = detail->flags;
					resp.result = result;
					resp.oal_socket = detail->oal_socket;
					resp.client_socket = detail->client_socket;
					resp.trans_param = detail->trans_param;

					net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_listen_socket_t), NULL);
				}
			}
			break;

		case NET_NFC_MESSAGE_LLCP_CONNECT :
			{
				net_nfc_request_connect_socket_t *detail = (net_nfc_request_connect_socket_t *)req_msg;
				net_nfc_response_connect_socket_t *resp = NULL;
				net_nfc_response_llcp_socket_error_t *error = NULL;
				bool success = false;

				_net_nfc_util_alloc_mem(error, sizeof (net_nfc_response_llcp_socket_error_t));
				if (error == NULL)
				{
					DEBUG_SERVER_MSG("ERROR: invalid detail info or allocation is failed");
					break;
				}

				_net_nfc_util_alloc_mem(resp, sizeof (net_nfc_response_connect_socket_t));
				if (resp == NULL)
				{
					DEBUG_SERVER_MSG("ERROR: invalid detail info or allocation is failed");
					_net_nfc_util_free_mem(error);
					break;
				}

				error->length = sizeof(net_nfc_response_llcp_socket_error_t);
				error->client_socket = detail->client_socket;
				error->handle = detail->handle;

				resp->length = sizeof(net_nfc_response_connect_socket_t);
				resp->flags = detail->flags;
				resp->result = NET_NFC_IPC_FAIL;

				success = net_nfc_controller_llcp_create_socket(&(detail->oal_socket), detail->type, detail->miu, detail->rw, &(resp->result), error);
				if (success == true)
				{
					error->oal_socket = resp->oal_socket = detail->oal_socket;
					DEBUG_SERVER_MSG("connect client socket [%d]", detail->client_socket);
					resp->client_socket = detail->client_socket;
					resp->trans_param = detail->trans_param;

					success = net_nfc_controller_llcp_connect_by_url(detail->handle, detail->oal_socket, detail->service_name.buffer, &(resp->result), resp);
					if (success == false)
					{
						DEBUG_ERR_MSG("connect client socket is failed");

						net_nfc_controller_llcp_socket_close(resp->oal_socket, &(resp->result));

						if (net_nfc_server_check_client_is_running(req_msg->client_fd))
						{
							net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)resp, sizeof(net_nfc_response_connect_socket_t), NULL);
						}
						_net_nfc_util_free_mem(resp);
					}
				}
				else
				{
					if (net_nfc_server_check_client_is_running(req_msg->client_fd))
					{
						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)resp, sizeof(net_nfc_response_connect_socket_t), NULL);
					}

					_net_nfc_util_free_mem(error);
					_net_nfc_util_free_mem(resp);
				}
			}
			break;

		case NET_NFC_MESSAGE_LLCP_CONNECT_SAP :
			{
				net_nfc_request_connect_sap_socket_t *detail = (net_nfc_request_connect_sap_socket_t *)req_msg;
				net_nfc_response_connect_sap_socket_t *resp = NULL;
				bool success = false;

				_net_nfc_util_alloc_mem(resp, sizeof(net_nfc_response_connect_sap_socket_t));
				if (resp == NULL)
				{
					DEBUG_SERVER_MSG("ERROR: allocation is failed");
					break;
				}

				resp->length = sizeof(net_nfc_response_connect_sap_socket_t);
				resp->flags = detail->flags;
				resp->result = NET_NFC_IPC_FAIL;

				success = net_nfc_controller_llcp_create_socket(&(detail->oal_socket), detail->type, detail->miu, detail->rw, &(resp->result), NULL);
				if (success == true)
				{
					resp->oal_socket = detail->oal_socket;
					resp->client_socket = detail->client_socket;
					resp->trans_param = detail->trans_param;

					success = net_nfc_controller_llcp_connect(detail->handle, detail->oal_socket, detail->sap, &(resp->result), resp);
				}

				if (success == false)
				{
					if (net_nfc_server_check_client_is_running(req_msg->client_fd))
					{
						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)resp, sizeof(net_nfc_response_connect_sap_socket_t), NULL);
					}
					_net_nfc_util_free_mem(resp);
				}
			}
			break;

		case NET_NFC_MESSAGE_LLCP_SEND :
			{
				net_nfc_request_send_socket_t *detail = (net_nfc_request_send_socket_t *)req_msg;
				data_s data = { NULL, 0 };

				if (net_nfc_util_duplicate_data(&data, &detail->data) == true)
				{
					net_nfc_response_send_socket_t *resp = NULL;

					_net_nfc_util_alloc_mem(resp, sizeof (net_nfc_response_send_socket_t));
					if (resp != NULL)
					{
						resp->length = sizeof(net_nfc_response_send_socket_t);
						resp->flags = detail->flags;
						resp->result = NET_NFC_IPC_FAIL;
						resp->client_socket = detail->client_socket;
						resp->trans_param = detail->trans_param;

						if (net_nfc_controller_llcp_send(detail->handle, detail->oal_socket, &data, &(resp->result), resp) == false)
						{
							if (net_nfc_server_check_client_is_running(req_msg->client_fd))
							{
								net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)resp, sizeof(net_nfc_response_send_socket_t), NULL);
							}
							_net_nfc_util_free_mem(resp);
						}
					}

					net_nfc_util_free_data(&data);
				}
			}
			break;

		case NET_NFC_MESSAGE_LLCP_RECEIVE :
			{
				net_nfc_request_receive_socket_t *detail = (net_nfc_request_receive_socket_t *)req_msg;
				net_nfc_response_receive_socket_t *resp = NULL;

				_net_nfc_util_alloc_mem(resp, sizeof (net_nfc_response_receive_socket_t));
				if (resp == NULL)
				{
					DEBUG_SERVER_MSG("ERROR: allocation is failed");
					break;
				}

				resp->length = sizeof(net_nfc_response_receive_socket_t);
				resp->flags = detail->flags;
				resp->result = NET_NFC_IPC_FAIL;
				resp->client_socket = detail->client_socket;
				resp->trans_param = detail->trans_param;
				resp->data.length = detail->req_length;
				_net_nfc_util_alloc_mem(resp->data.buffer, detail->req_length);
				if (resp->data.buffer == NULL)
				{
					DEBUG_SERVER_MSG("ERROR: allocation is failed");
					_net_nfc_util_free_mem(resp);
					break;
				}

				if (net_nfc_controller_llcp_recv(detail->handle, detail->oal_socket, &(resp->data), &(resp->result), resp) == false)
				{
					if (net_nfc_server_check_client_is_running(req_msg->client_fd))
					{
						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)resp, sizeof(net_nfc_response_receive_socket_t), NULL);
					}
					_net_nfc_util_free_mem(resp->data.buffer);
					_net_nfc_util_free_mem(resp);
				}
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_LLCP_CLOSE :
			{
				net_nfc_request_close_socket_t *detail = (net_nfc_request_close_socket_t *)req_msg;
				net_nfc_error_e result = NET_NFC_OK;

				DEBUG_SERVER_MSG("socket close :: NET_NFC_MESSAGE_SERVICE_LLCP_CLOSE");
				net_nfc_controller_llcp_socket_close(detail->oal_socket, &result);

				if (net_nfc_server_check_client_is_running(req_msg->client_fd))
				{
					net_nfc_response_close_socket_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_close_socket_t);
					resp.flags = detail->flags;
					resp.result = result;
					resp.client_socket = detail->client_socket;
					resp.trans_param = detail->trans_param;

					net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_close_socket_t), NULL);
				}
			}
			break;

		case NET_NFC_MESSAGE_LLCP_DISCONNECT : /* change resp to local variable. if there is some problem, check this first. */
			{
				net_nfc_request_disconnect_socket_t *detail = (net_nfc_request_disconnect_socket_t *)req_msg;
				net_nfc_request_disconnect_socket_t *context = NULL;
				net_nfc_error_e result = NET_NFC_OK;

				context = _net_nfc_dispatcher_copy_message(detail);
				if (context == NULL)
				{
					DEBUG_ERR_MSG("alloc failed");
					break;
				}

				if (net_nfc_controller_llcp_disconnect(detail->handle, detail->oal_socket, &result, &context) == false)
				{
					if (net_nfc_server_check_client_is_running(req_msg->client_fd))
					{
						net_nfc_response_disconnect_socket_t resp = { 0, };

						resp.length = sizeof(net_nfc_response_disconnect_socket_t);
						resp.flags = detail->flags;
						resp.result = result;
						resp.client_socket = detail->client_socket;
						resp.trans_param = detail->trans_param;

						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_disconnect_socket_t), NULL);
					}

					_net_nfc_util_free_mem(context);
				}

			}
			break;

		case NET_NFC_MESSAGE_LLCP_ACCEPTED :
			{
				net_nfc_request_accept_socket_t *detail = (net_nfc_request_accept_socket_t *)req_msg;
				net_nfc_error_e result = NET_NFC_OK;

				net_nfc_controller_llcp_accept(detail->incomming_socket, &result);

				if (net_nfc_server_check_client_is_running(req_msg->client_fd))
				{
					net_nfc_response_accept_socket_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_accept_socket_t);
					resp.flags = detail->flags;
					resp.trans_param = detail->trans_param;
					resp.result = result;
					resp.client_socket = detail->client_socket;

					net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_accept_socket_t), NULL);
				}
			}
			break;

		case NET_NFC_MESSAGE_LLCP_CONFIG :
			{
				net_nfc_request_config_llcp_t *detail = (net_nfc_request_config_llcp_t *)req_msg;
				net_nfc_error_e result = NET_NFC_OK;

				net_nfc_controller_llcp_config(&(detail->config), &result);

				if (net_nfc_server_check_client_is_running(detail->client_fd))
				{
					net_nfc_response_config_llcp_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_config_llcp_t);
					resp.flags = detail->flags;
					resp.trans_param = detail->trans_param;
					resp.result = result;

					net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_config_llcp_t), NULL);
				}
			}
			break;

		case NET_NFC_MESSAGE_CONNECTION_HANDOVER :
			{
				net_nfc_request_connection_handover_t *detail = (net_nfc_request_connection_handover_t *)req_msg;
				net_nfc_error_e result = NET_NFC_OK;

				net_nfc_request_msg_t *param = NULL;

				if ((param = _net_nfc_dispatcher_copy_message(detail)) == NULL)
				{
					DEBUG_ERR_MSG("alloc failed");
					break;
				}

				if ((result = net_nfc_service_llcp_handover_send_request_msg((net_nfc_request_connection_handover_t *)param)) != NET_NFC_OK)
				{
					if (net_nfc_server_check_client_is_running(req_msg->client_fd))
					{
						net_nfc_response_connection_handover_t resp = { 0, };

						resp.length = sizeof(net_nfc_response_connection_handover_t);
						resp.flags = detail->flags;
						resp.user_param = detail->user_param;
						resp.result = result;
						resp.event = NET_NFC_OPERATION_FAIL;
						resp.type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;

						net_nfc_send_response_msg(req_msg->client_fd, req_msg->request_type, (void *)&resp, sizeof(net_nfc_response_connection_handover_t), NULL);
					}
				}

				_net_nfc_util_free_mem(param);
			}
			break;

		case NET_NFC_MESSAGE_SERVICE_WATCH_DOG :
			{
				net_nfc_service_watch_dog(req_msg);
				continue;
			}
			break;

		default :
			break;
		}

		/*need to free req_msg*/
		_net_nfc_util_free_mem(req_msg);
	}

	return (void *)NULL;
}

/* return true to authentication success; false to fail to authenticate */
bool _net_nfc_check_dispatcher_privilege(net_nfc_request_msg_t *request_msg)
{
	int client_fd_request = request_msg->client_fd;
	int ret_value;

	switch(request_msg->request_type)
	{
#if 0
		case NET_NFC_MESSAGE_SERVICE_ACTIVATE:
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_SERVICE_ACTIVATE...");
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::admin","w");
			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");

				if (net_nfc_server_check_client_is_running(client_fd_request)){
					net_nfc_response_test_t resp = { 0, };
					resp.length = sizeof(net_nfc_response_test_t);
					resp.flags = request_msg->flags;
					resp.result = NET_NFC_SECURITY_FAIL;
					resp.trans_param = (void *)request_msg->user_param;
					net_nfc_send_response_msg(request_msg->client_fd, request_msg->request_type,(void *)&resp, sizeof(net_nfc_response_test_t), NULL);

				}
				return false;
			}
			DEBUG_SERVER_MSG("checking success");
			break;

#endif
		case NET_NFC_MESSAGE_TRANSCEIVE:
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_TRANSCEIVE...");
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::tag","w");

			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");
#if 0

				if (net_nfc_server_check_client_is_running(client_fd_request))
				{
					net_nfc_request_transceive_t *detail = (net_nfc_request_transceive_t *)request_msg;
					net_nfc_response_transceive_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_transceive_t);
					resp.flags = detail->flags;
					resp.trans_param = detail->trans_param;
					resp.result = NET_NFC_SECURITY_FAIL;

					net_nfc_send_response_msg(request_msg->client_fd, request_msg->request_type, (void *)&resp, sizeof(net_nfc_response_transceive_t), NULL);

				}
				return false;
#endif
			}
			DEBUG_SERVER_MSG("checking success");
			break;

		case NET_NFC_MESSAGE_READ_NDEF:

			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_READ_NDEF...");
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::tag","w");

			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");
#if 0

				if (net_nfc_server_check_client_is_running(client_fd_request))
				{
					net_nfc_request_read_ndef_t *detail = (net_nfc_request_read_ndef_t *)request_msg;
					net_nfc_response_write_ndef_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_read_ndef_t);
					resp.flags = detail->flags;
					resp.trans_param = detail->trans_param;
					resp.result = NET_NFC_SECURITY_FAIL;

					net_nfc_send_response_msg(request_msg->client_fd, request_msg->request_type, (void *)&resp, sizeof(net_nfc_response_write_ndef_t), NULL);

				}
				return false;
#endif
			}
			DEBUG_SERVER_MSG("checking success");
			break;

		case NET_NFC_MESSAGE_WRITE_NDEF:
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_WRITE_NDEF...");
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::tag","w");

			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");
#if 0

				if (net_nfc_server_check_client_is_running(client_fd_request))
				{
					net_nfc_request_write_ndef_t *detail = (net_nfc_request_write_ndef_t *)request_msg;
					net_nfc_response_write_ndef_t resp = { 0, };

					resp.length = sizeof(net_nfc_response_write_ndef_t);
					resp.flags = detail->flags;
					resp.trans_param = detail->trans_param;
					resp.result = NET_NFC_SECURITY_FAIL;

					net_nfc_send_response_msg(request_msg->client_fd, request_msg->request_type, (void *)&resp, sizeof(net_nfc_response_write_ndef_t), NULL);

				}
				return false;
#endif
			}
			DEBUG_SERVER_MSG("checking success");
			break;

		case NET_NFC_MESSAGE_P2P_SEND:
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_P2P_SEND...");
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::p2p","w");

			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");
#if 0

				if (net_nfc_server_check_client_is_running(client_fd_request))
				{
					net_nfc_request_p2p_send_t *exchanger = (net_nfc_request_p2p_send_t *)request_msg;

					net_nfc_response_p2p_send_t resp_msg = { 0, };

					resp_msg.length = sizeof(resp_msg);
					resp_msg.response_type = NET_NFC_MESSAGE_P2P_SEND;
					resp_msg.handle = exchanger->handle;
					resp_msg.result = NET_NFC_SECURITY_FAIL;
					resp_msg.trans_param = (void *)exchanger->user_param;

					net_nfc_send_response_msg(request_msg->client_fd,NET_NFC_MESSAGE_P2P_SEND, &resp_msg,sizeof(resp_msg), NULL);

				}
				return false;
#endif
			}
			DEBUG_SERVER_MSG("checking success");
			break;

#if 0
		case NET_NFC_MESSAGE_SNEP_START_SERVER :
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_SNEP_START_SERVER...");
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::p2p","rw");

			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");
				if (net_nfc_server_check_client_is_running(client_fd_request))
				{
					net_nfc_request_listen_socket_t *msg = (net_nfc_request_listen_socket_t *)request_msg;
					net_nfc_response_receive_socket_t resp = { 0 };
					resp.length = sizeof(resp);
					resp.response_type = NET_NFC_MESSAGE_SNEP_START_SERVER;
					resp.user_param = msg->user_param;
					resp.result = NET_NFC_SECURITY_FAIL;
					net_nfc_send_response_msg(request_msg->client_fd, request_msg->request_type, (void *)&resp, sizeof(net_nfc_response_receive_socket_t), NULL);
				}
				return false;
			}
			DEBUG_SERVER_MSG("checking success");
			break;

#endif
#if 0
		case NET_NFC_MESSAGE_SNEP_START_CLIENT :
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_SNEP_START_CLIENT...");

			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::p2p","rw");
			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking failed, and then send response to client");
				if (net_nfc_server_check_client_is_running(client_fd_request))
				{
					net_nfc_request_snep_client_t *msg =(net_nfc_request_snep_client_t *)request_msg;
					net_nfc_response_receive_socket_t resp_msg = { 0, };
					resp_msg.length = sizeof(resp_msg);
					resp_msg.response_type = NET_NFC_MESSAGE_SNEP_START_CLIENT;
					resp_msg.user_param = msg->user_param;
					resp_msg.result = NET_NFC_SECURITY_FAIL;
					net_nfc_send_response_msg(request_msg->client_fd, request_msg->request_type, (void *)&resp_msg, sizeof(net_nfc_response_receive_socket_t), NULL);
				}
				return false;
			}
			DEBUG_SERVER_MSG("checking success");
			break;

#endif
#if 0
		case NET_NFC_MESSAGE_SNEP_STOP_SERVICE :
			ret_value = security_server_check_privilege_by_sockfd(client_fd_request,"nfc-manager::p2p","rw");
			if (ret_value == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				return false;

			}
			break;

#endif
		default :
			return true;
	}

	return true;
}
