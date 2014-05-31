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

#include <pthread.h>
#include <malloc.h>
#include <netinet/in.h>

#include "net_nfc_controller_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_typedef.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_service_private.h"
#include "net_nfc_app_util_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_manager_util_private.h"
#include "net_nfc_service_llcp_private.h"
#include "net_nfc_service_llcp_handover_private.h"
#include "net_nfc_server_context_private.h"

static uint8_t snep_server_buffer[SNEP_MAX_BUFFER] = { 0, };
static uint8_t snep_client_buffer[SNEP_MAX_BUFFER] = { 0, };

static data_s snep_server_data = { snep_server_buffer, SNEP_MAX_BUFFER };
static data_s snep_client_data = { snep_client_buffer, SNEP_MAX_BUFFER };

static net_nfc_llcp_state_t current_llcp_client_state;
static net_nfc_llcp_state_t current_llcp_server_state;

/* static callback function */

#if 0
net_nfc_error_e _net_nfc_service_llcp_get_server_configuration_value(char* service_name, char* attr_name, char* attr_value);
#endif
static bool _net_nfc_service_llcp_state_process(net_nfc_request_msg_t *msg);

static bool _net_nfc_service_llcp_snep_server(net_nfc_llcp_state_t * state, net_nfc_error_e* result);
static bool _net_nfc_service_llcp_client(net_nfc_llcp_state_t * state, net_nfc_error_e* result);
static data_s* _net_nfc_service_llcp_snep_create_msg(snep_command_field_e resp_field, data_s* information);
static net_nfc_error_e _net_nfc_service_llcp_snep_check_req_msg(data_s* snep_msg, uint8_t* resp_code);
static net_nfc_error_e _net_nfc_service_llcp_snep_get_code(data_s* snep_msg, uint8_t* code);
static net_nfc_error_e _net_nfc_service_llcp_snep_get_information_length(data_s* snep_msg, uint32_t* length);
static net_nfc_error_e _net_nfc_service_llcp_snep_check_resp_msg(data_s* snep_msg);

static bool _net_nfc_service_llcp_npp_server(net_nfc_llcp_state_t * state, net_nfc_error_e* result);
static data_s* _net_nfc_service_llcp_npp_create_msg(data_s* information);
static net_nfc_error_e _net_nfc_service_llcp_npp_check_req_msg(data_s* npp_msg, uint8_t* resp_code);
static net_nfc_error_e _net_nfc_service_llcp_npp_get_information_length(data_s* npp_msg, uint32_t* length);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

GList * state_list = NULL;
static bool net_nfc_service_llcp_is_valid_state(net_nfc_llcp_state_t * state)
{
	if (g_list_find(state_list, state) != NULL)
	{
		return true;
	}
	return false;
}
void net_nfc_service_llcp_remove_state(net_nfc_llcp_state_t * state)
{
	if (state != NULL)
	{
		state_list = g_list_remove(state_list, state);
	}
}
void net_nfc_service_llcp_add_state(net_nfc_llcp_state_t * state)
{
	if (state != NULL)
	{
		state_list = g_list_append(state_list, state);
	}
}

bool net_nfc_service_llcp_process(net_nfc_target_handle_s* handle, int devType, net_nfc_error_e* result)
{
	*result = NET_NFC_OK;

	DEBUG_SERVER_MSG("connection type = [%d]", handle->connection_type);

	if (devType == NET_NFC_NFCIP1_TARGET)
	{
		DEBUG_SERVER_MSG("trying to connect to tag = [0x%p]", handle);

		if (net_nfc_controller_connect(handle, result) != true)
		{
			DEBUG_SERVER_MSG("connect failed");

			if (net_nfc_controller_confiure_discovery(NET_NFC_DISCOVERY_MODE_RESUME, NET_NFC_ALL_ENABLE, result) == false)
			{
				net_nfc_controller_exception_handler();

			}

			return false;
		}
	}

	DEBUG_SERVER_MSG("check LLCP");

	if (net_nfc_controller_llcp_check_llcp(handle, result) == true)
	{
		DEBUG_SERVER_MSG("activate LLCP");
		if (net_nfc_controller_llcp_activate_llcp(handle, result) == true)
		{
#ifdef SUPPORT_CONFIG_FILE
			char value[64] =
			{	0,};
			if (net_nfc_service_get_configuration_value("service", "exchange_service", value) == NET_NFC_OK)
			{
				if (strcmp(value, "true") == 0)
				{
					net_nfc_llcp_state_t * exchange_state_server = NULL;
					_net_nfc_util_alloc_mem(exchange_state_server, sizeof (net_nfc_llcp_state_t));

					exchange_state_server->handle = handle;
					exchange_state_server->state = NET_NFC_STATE_EXCHANGER_SERVER;
					exchange_state_server->step = NET_NFC_LLCP_STEP_01;
					exchange_state_server->user_data = NULL;

					net_nfc_service_llcp_add_state(exchange_state_server);

					if (_net_nfc_service_llcp_snep_server(exchange_state_server, result) == false)
					{
						return false;
					}

					handle->app_type = exchange_state_server->type_app_protocol;
					DEBUG_SERVER_MSG("handle->app_type = [%d]", handle->app_type);
				}
				else
				{
					DEBUG_SERVER_MSG("llcp exchange service is trunned off");
				}
			}
			else
			{
				net_nfc_llcp_state_t * exchange_state_server = NULL;
				_net_nfc_util_alloc_mem(exchange_state_server, sizeof (net_nfc_llcp_state_t));

				exchange_state_server->handle = handle;
				exchange_state_server->state = NET_NFC_STATE_EXCHANGER_SERVER;
				exchange_state_server->step = NET_NFC_LLCP_STEP_01;
				exchange_state_server->user_data = NULL;

				net_nfc_service_llcp_add_state(exchange_state_server);

				if (_net_nfc_service_llcp_npp_server(exchange_state_server, result) == false)
				{
					DEBUG_SERVER_MSG("ERROR!!!!!!!!!!!!!!!");
					return false;
				}
				else
				{
					handle->app_type = exchange_state_server->type_app_protocol;
					DEBUG_SERVER_MSG("handle->app_type = [%d]", handle->app_type);
				}
			}

			memset(value, 0x00, 64);

			if (net_nfc_service_get_configuration_value("service", "connection_handover", value) == NET_NFC_OK)
			{
				if (strcmp(value, "true") == 0)
				{
					net_nfc_llcp_state_t * conn_handover_selector = NULL;
					_net_nfc_util_alloc_mem(conn_handover_selector, sizeof (net_nfc_llcp_state_t));

					conn_handover_selector->handle = handle;
					conn_handover_selector->state = NET_NFC_STATE_CONN_HANDOVER_SELECT;
					conn_handover_selector->step = NET_NFC_LLCP_STEP_01;
					conn_handover_selector->user_data = NULL;

					net_nfc_service_llcp_add_state(conn_handover_selector);

					if (_net_nfc_service_llcp_stand_alone_conn_handover_selector(conn_handover_selector, result) == false)
					{
						return false;
					}
				}
				else
				{
					DEBUG_SERVER_MSG("llcp connection handover is trunned off");
				}
			}
#else/* Use the NPP & the SNEP FOR LLCP , Handover*/
			/* NPP */
			net_nfc_llcp_state_t * exchange_state_server_NPP = NULL;
			_net_nfc_util_alloc_mem(exchange_state_server_NPP, sizeof (net_nfc_llcp_state_t));
			exchange_state_server_NPP->handle = handle;
			exchange_state_server_NPP->state = NET_NFC_STATE_EXCHANGER_SERVER_NPP;
			exchange_state_server_NPP->step = NET_NFC_LLCP_STEP_01;
			exchange_state_server_NPP->user_data = NULL;

			net_nfc_service_llcp_add_state(exchange_state_server_NPP);

			if (_net_nfc_service_llcp_npp_server(exchange_state_server_NPP, result) == false)
			{
				return false;
			}

			/* SNEP */
			net_nfc_llcp_state_t * exchange_state_server_SNEP = NULL;
			_net_nfc_util_alloc_mem(exchange_state_server_SNEP, sizeof (net_nfc_llcp_state_t));
			exchange_state_server_SNEP->handle = handle;
			exchange_state_server_SNEP->state = NET_NFC_STATE_EXCHANGER_SERVER;
			exchange_state_server_SNEP->step = NET_NFC_LLCP_STEP_01;
			exchange_state_server_SNEP->user_data = NULL;

			net_nfc_service_llcp_add_state(exchange_state_server_SNEP);

			if (_net_nfc_service_llcp_snep_server(exchange_state_server_SNEP, result) == false)
			{
				return false;
			}

			net_nfc_llcp_state_t * conn_handover_selector = NULL;
			_net_nfc_util_alloc_mem(conn_handover_selector, sizeof (net_nfc_llcp_state_t));
			conn_handover_selector->handle = handle;
			conn_handover_selector->state = NET_NFC_STATE_CONN_HANDOVER_SELECT;
			conn_handover_selector->step = NET_NFC_LLCP_STEP_01;
			conn_handover_selector->user_data = NULL;

			net_nfc_service_llcp_add_state(conn_handover_selector);

			if (net_nfc_service_llcp_connection_handover_selector(conn_handover_selector, result) == false)
			{
				return false;
			}
#endif
		}
	}

	DEBUG_SERVER_MSG("handle->app_type = [%d]", handle->app_type);

	{
		net_nfc_response_p2p_discovered_t req_msg = { 0, };
		req_msg.handle = handle;
		req_msg.result = NET_NFC_OK;

		net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_P2P_DISCOVERED, &req_msg, sizeof(net_nfc_response_p2p_discovered_t), NULL);
	}

	DEBUG_SERVER_MSG("stand alone llcp service is finished");

	return false;
}

static bool _net_nfc_service_llcp_state_process(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	net_nfc_llcp_state_t *state = NULL;
	bool result;
	net_nfc_error_e error;

	DEBUG_SERVER_MSG("llcp service by nfc-manager");

	if (msg == NULL)
	{
		DEBUG_SERVER_MSG("msg is NULL");
		return false;
	}

	state = (net_nfc_llcp_state_t *)(llcp_msg->user_param);

	if (state == NULL || !net_nfc_service_llcp_is_valid_state(state))
	{
		DEBUG_SERVER_MSG("state is NULL");
		return false;
	}

	switch (msg->request_type)
	{
	case NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ACCEPTED_ERROR :
	case NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ERROR :
		state->step = NET_NFC_STATE_SOCKET_ERROR;
		break;

	default :
		break;
	}

	state->prev_result = llcp_msg->result;

	DEBUG_SERVER_MSG("service type = [%d]", state->state);

	switch (state->state)
	{
	case NET_NFC_STATE_EXCHANGER_SERVER :
		DEBUG_SERVER_MSG("exchanger server service");
		net_nfc_server_set_server_state(NET_NFC_SNEP_SERVER_CONNECTED);
		result = _net_nfc_service_llcp_snep_server(state, &error);
		break;

	case NET_NFC_STATE_EXCHANGER_CLIENT :
		DEBUG_SERVER_MSG("exchanger client service");
		memcpy(&current_llcp_client_state, state, sizeof(net_nfc_llcp_state_t));
		result = _net_nfc_service_llcp_client(state, &error);
		break;

	case NET_NFC_STATE_EXCHANGER_SERVER_NPP :
		DEBUG_SERVER_MSG("exchanger sesrver npp");
		net_nfc_server_set_server_state(NET_NFC_SNEP_SERVER_CONNECTED);
		result = _net_nfc_service_llcp_npp_server(state, &error);
		break;

	case NET_NFC_STATE_CONN_HANDOVER_REQUEST :
		DEBUG_SERVER_MSG("NET_NFC_STATE_CONN_HANDOVER_REQUEST");
		result = net_nfc_service_llcp_connection_handover_requester(state, &error);
		break;

	case NET_NFC_STATE_CONN_HANDOVER_SELECT :
		DEBUG_SERVER_MSG("NET_NFC_STATE_CONN_HANDOVER_SELECT");
		result = net_nfc_service_llcp_connection_handover_selector(state, &error);
		break;

	default :
		DEBUG_SERVER_MSG("Unkown state state name: %d", state->state);
		return false;
	}

	return result;
}

bool net_nfc_service_llcp_process_accept(net_nfc_request_msg_t *msg)
{
	bool res = false;
	net_nfc_request_accept_socket_t *accept = (net_nfc_request_accept_socket_t *)msg;
	net_nfc_llcp_state_t *state = NULL;

	if (accept == NULL || (void *)accept->user_param == NULL)
	{
		return false;
	}

	if (msg->request_type == NET_NFC_MESSAGE_SERVICE_LLCP_ACCEPT)
	{
		state = (net_nfc_llcp_state_t *)accept->user_param;

		state->incomming_socket = accept->incomming_socket;

		DEBUG_SERVER_MSG("Incomming socket : %X", state->incomming_socket);

		res = _net_nfc_service_llcp_state_process(msg);
	}

	return res;
}

bool net_nfc_service_llcp_disconnect_target(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	net_nfc_target_handle_s *handle = NULL;

	DEBUG_SERVER_MSG("llcp disconnect target");

	if (llcp_msg == NULL)
		return false;

	handle = (net_nfc_target_handle_s *)llcp_msg->user_param;
	if (handle != NULL)
	{
		net_nfc_error_e result = NET_NFC_OK;

		if (net_nfc_controller_disconnect(handle, &result) == false)
		{
			if (result != NET_NFC_NOT_CONNECTED)
			{
				net_nfc_controller_exception_handler();
			}
			else
			{
				DEBUG_SERVER_MSG("target was not connected.");
			}
		}
		net_nfc_server_set_server_state(NET_NFC_SERVER_IDLE);
	}
	else
	{
		DEBUG_SERVER_MSG("the target ID = [0x%p] was not connected before. current device may be a TARGET", handle);
	}

	{
		net_nfc_response_llcp_detached_t message = { 0, };
		message.result = NET_NFC_OK;
		net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_P2P_DETACHED, &message, sizeof(net_nfc_response_llcp_detached_t), NULL);
	}

	llcp_msg->user_param = 0; /*detail message should be NULL, because the handle is already freed in disconnect function */

	return true;
}

bool net_nfc_service_llcp_process_socket_error(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	if (net_nfc_server_check_client_is_running(llcp_msg->client_fd))
	{
		/* in case of slave mode */
		net_nfc_response_llcp_socket_error_t *error = (net_nfc_response_llcp_socket_error_t *)llcp_msg->user_param;

		error->error = llcp_msg->result;
		DEBUG_SERVER_MSG("Socket error returned [%d]", error->error);
		return net_nfc_send_response_msg(llcp_msg->client_fd, NET_NFC_MESSAGE_LLCP_ERROR, error, sizeof(net_nfc_response_llcp_socket_error_t), NULL);
	}

	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_accepted_socket_error(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	if (net_nfc_server_check_client_is_running(llcp_msg->client_fd))
	{
		/* in case of slave mode the error message will be deliver to client stub*/
		net_nfc_response_llcp_socket_error_t *error = (net_nfc_response_llcp_socket_error_t *)llcp_msg->user_param;
		error->error = llcp_msg->result;
		return net_nfc_send_response_msg(llcp_msg->client_fd, NET_NFC_MESSAGE_LLCP_ERROR, error, sizeof(net_nfc_response_llcp_socket_error_t), NULL);
	}

	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_connect_socket(net_nfc_request_msg_t *msg)
{
	net_nfc_request_msg_t *llcp_msg = (net_nfc_request_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_connect_sap_socket(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	if (net_nfc_server_check_client_is_running(llcp_msg->client_fd))
	{
		net_nfc_response_connect_sap_socket_t *detail = (net_nfc_response_connect_sap_socket_t *)llcp_msg->user_param;
		detail->result = llcp_msg->result;
		return net_nfc_send_response_msg(llcp_msg->client_fd, NET_NFC_MESSAGE_LLCP_CONNECT_SAP, detail, sizeof(net_nfc_response_connect_sap_socket_t), NULL);
	}
	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_send_socket(net_nfc_request_msg_t *msg)
{
	net_nfc_request_msg_t *llcp_msg = (net_nfc_request_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_send_to_socket(net_nfc_request_msg_t* msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	if (net_nfc_server_check_client_is_running(llcp_msg->client_fd))
	{
		/* in case of slave mode the error message will be deliver to client stub*/
		net_nfc_response_send_socket_t *detail = (net_nfc_response_send_socket_t *)llcp_msg->user_param;
		detail->result = llcp_msg->result;
		return net_nfc_send_response_msg(llcp_msg->client_fd, NET_NFC_MESSAGE_LLCP_SEND_TO, detail, sizeof(net_nfc_response_send_socket_t), NULL);
	}
	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_receive_socket(net_nfc_request_msg_t *msg)
{
	net_nfc_request_msg_t *llcp_msg = (net_nfc_request_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_receive_from_socket(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	if (net_nfc_server_check_client_is_running(llcp_msg->client_fd))
	{
		net_nfc_response_receive_socket_t *detail = (net_nfc_response_receive_socket_t *)llcp_msg->user_param;
		detail->result = llcp_msg->result;
		return net_nfc_send_response_msg(llcp_msg->client_fd, NET_NFC_MESSAGE_LLCP_RECEIVE_FROM, detail, sizeof(net_nfc_response_receive_socket_t),
			detail->data.buffer, detail->data.length, NULL);
	}
	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

bool net_nfc_service_llcp_process_disconnect_socket(net_nfc_request_msg_t *msg)
{
	net_nfc_request_llcp_msg_t *llcp_msg = (net_nfc_request_llcp_msg_t *)msg;
	bool res = false;

	if (msg == NULL)
		return false;

	if (net_nfc_server_check_client_is_running(llcp_msg->client_fd))
	{
		net_nfc_response_disconnect_socket_t *detail = (net_nfc_response_disconnect_socket_t *)llcp_msg->user_param;
		detail->result = llcp_msg->result;
		return net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_LLCP_DISCONNECT, detail, sizeof(net_nfc_response_disconnect_socket_t), NULL);
	}

	res = _net_nfc_service_llcp_state_process(msg);

	llcp_msg->user_param = 0;

	return res;
}

net_nfc_error_e net_nfc_service_send_exchanger_msg(net_nfc_request_p2p_send_t *msg)
{
	net_nfc_error_e error = NET_NFC_OK;
	data_s *ex_data = NULL;
	net_nfc_llcp_state_t * exchange_state_client = NULL;

	DEBUG_SERVER_MSG("send exchanger msg to remote client");

	if (msg == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (msg->handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(ex_data, sizeof(data_s));
	if (ex_data == NULL)
	{
		DEBUG_SERVER_MSG(" alocation is failed");
		return NET_NFC_ALLOC_FAIL;
	}
	ex_data->length = msg->data.length;

	_net_nfc_util_alloc_mem(ex_data->buffer, ex_data->length);
	if (ex_data->buffer == NULL)
	{
		DEBUG_SERVER_MSG(" alocation is failed");
		_net_nfc_util_free_mem(ex_data);
		return NET_NFC_ALLOC_FAIL;
	}
	memcpy(ex_data->buffer, &msg->data.buffer, msg->data.length);

	_net_nfc_util_alloc_mem(exchange_state_client, sizeof(net_nfc_llcp_state_t));
	if (exchange_state_client == NULL)
	{
		DEBUG_SERVER_MSG(" alocation is failed");
		_net_nfc_util_free_mem(ex_data);
		_net_nfc_util_free_mem(ex_data->buffer);
		return NET_NFC_ALLOC_FAIL;
	}

	exchange_state_client->client_fd = msg->client_fd;
	exchange_state_client->handle = msg->handle;
	exchange_state_client->state = NET_NFC_STATE_EXCHANGER_CLIENT;
	exchange_state_client->step = NET_NFC_LLCP_STEP_01;
	exchange_state_client->payload = ex_data;
	exchange_state_client->user_data = (void *)msg->user_param;

	net_nfc_service_llcp_add_state(exchange_state_client);

	if (_net_nfc_service_llcp_client(exchange_state_client, &error) == true)
	{
		return NET_NFC_OK;
	}
	else
	{
		DEBUG_SERVER_MSG("exchange client operation is failed");
		return NET_NFC_OPERATION_FAIL;
	}
}

#if 0
net_nfc_error_e _net_nfc_service_llcp_get_server_configuration_value(char* service_name, char* attr_name, char* attr_value)
{
	if (service_name == NULL || attr_name == NULL || attr_value == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	FILE* fp = NULL;
	char file_path[512] = { 0, };

	snprintf(file_path, 512, "%s/%s/%s", NET_NFC_MANAGER_DATA_PATH, NET_NFC_MANAGER_DATA_PATH_CONFIG, NET_NFC_MANAGER_LLCP_CONFIG_FILE_NAME);

	if ((fp = fopen(file_path, "r")) == NULL)
	{
		return NET_NFC_UNKNOWN_ERROR;
	}

	char temp[128] = { 0, };
	while (fgets(temp, sizeof(temp), fp) != NULL)
	{
		net_nfc_util_strip_string(temp, 128);
		char service_name_temp[128] = { 0, };

		if (temp[0] == '#')
			continue;

		if (temp[0] == '[')
		{
			int i = 0;
			char ch = 0;

			while (i < sizeof(temp) && (ch = temp[i++]) != '\n')
			{
				if (ch == ']')
				{
					memcpy(service_name_temp, &temp[1], i - 2);
					break;
				}
			}

			if (strlen(service_name_temp) != 0)
			{
				DEBUG_SERVER_MSG("[%s] is found", service_name_temp);
				if (strcmp(service_name_temp, service_name) == 0)
				{
					DEBUG_SERVER_MSG("[%s] and [%s] are matched", service_name_temp, service_name);

					while (fgets(temp, sizeof(temp), fp) != NULL)
					{
						if (strcmp(temp, "\n") == 0)
							break;

						net_nfc_util_strip_string(temp, 128);

						char* pos = NULL;

						if ((pos = strstr(temp, "=")) != NULL)
						{
							char attr_name_temp[64] = { 0, };

							memcpy(attr_name_temp, temp, pos - temp);

							DEBUG_SERVER_MSG("attr_name = [%s]", attr_name);

							if (strcmp(attr_name, attr_name_temp) == 0)
							{
								memcpy(attr_value, pos + 1, strlen(pos + 1) - 1);
								DEBUG_SERVER_MSG("attr_value = [%s]", attr_value);

								if (fp != NULL)
									fclose(fp);

								return NET_NFC_OK;
							}

						}
						else
							break;

					}
				}
			}
		}
	}

	if (fp != NULL)
		fclose(fp);

	return NET_NFC_NO_DATA_FOUND;

}
#endif

static bool _net_nfc_service_llcp_snep_server(net_nfc_llcp_state_t *state, net_nfc_error_e* result)
{
	bool need_clean_up = false;

	if (result == NULL)
	{
		DEBUG_SERVER_MSG("result is NULL");
		return false;
	}

	*result = NET_NFC_OK;

	switch (state->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		{
			DEBUG_SERVER_MSG("step 1");

			if (net_nfc_controller_llcp_create_socket(&(state->socket), NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED, SNEP_MAX_BUFFER, 1, result, state) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			DEBUG_SERVER_MSG("bind server socket with service acess point = [0x%x]", SNEP_SAP);
			if (net_nfc_controller_llcp_bind(state->socket, SNEP_SAP, result) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			DEBUG_SERVER_MSG("listen server socket with service access name = [%s]", SNEP_SAN);
			state->step = NET_NFC_LLCP_STEP_02;
			if (net_nfc_controller_llcp_listen(state->handle, (uint8_t *)SNEP_SAN, state->socket, result, state) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->type_app_protocol = NET_NFC_SNEP;
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			DEBUG_SERVER_MSG("step 2");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep: listen is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			net_nfc_llcp_state_t * new_client = NULL;
			_net_nfc_util_alloc_mem(new_client, sizeof (net_nfc_llcp_state_t));

			new_client->handle = state->handle;
			new_client->state = state->state;
			new_client->socket = state->incomming_socket;
			new_client->step = NET_NFC_LLCP_STEP_03;
			new_client->user_data = NULL;

			memset(snep_server_data.buffer, 0x00, SNEP_MAX_BUFFER);
			snep_server_data.length = SNEP_MAX_BUFFER;

			current_llcp_server_state.handle = state->handle;
			current_llcp_server_state.socket = state->incomming_socket;

			net_nfc_service_llcp_add_state(new_client);

			if (net_nfc_controller_llcp_recv(new_client->handle, new_client->socket, &snep_server_data, result, new_client) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		{
			DEBUG_SERVER_MSG("step 3");
			DEBUG_SERVER_MSG("receive request msg from snep client");

			state->step = NET_NFC_LLCP_STEP_04;

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep : recevie is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			uint8_t resp_code = 0;
			data_s* resp_msg = NULL;

			if (_net_nfc_service_llcp_snep_check_req_msg(&snep_server_data, &resp_code) != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("Not valid request msg = [0x%X]", resp_code);
				resp_msg = _net_nfc_service_llcp_snep_create_msg(resp_code, NULL);

				if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
				{
					_net_nfc_util_free_mem(resp_msg->buffer);
					_net_nfc_util_free_mem(resp_msg);
				}
			}
			else
			{
				uint32_t information_length = 0;
				if (_net_nfc_service_llcp_snep_get_information_length(&snep_server_data, &information_length) == NET_NFC_OK)
				{
					DEBUG_SERVER_MSG("MAX capa of server is = [%d] and received byte is = [%d]", SNEP_MAX_BUFFER, snep_server_data.length);

					/* msg = header(fixed 6 byte) + information(changable) */
					if (information_length + 6 > SNEP_MAX_BUFFER)
					{
						DEBUG_SERVER_MSG("request msg length is too long to receive at a time");
						DEBUG_SERVER_MSG("total msg length is = [%d]", information_length + 6);

						data_s* fragment = NULL;

						_net_nfc_util_alloc_mem(fragment, sizeof(data_s));
						if (fragment == NULL)
						{
							state->step = NET_NFC_STATE_ERROR;
							break;
						}

						_net_nfc_util_alloc_mem(fragment->buffer, (information_length + 6) * sizeof(uint8_t));
						if (fragment->buffer == NULL)
						{
							state->step = NET_NFC_STATE_ERROR;
							_net_nfc_util_free_mem(fragment);
							break;
						}

						state->step = NET_NFC_LLCP_STEP_05;

						fragment->length = information_length + 6;
						state->payload = fragment;

						memcpy(fragment->buffer, snep_server_data.buffer, snep_server_data.length);

						/* set zero. this is first time */
						state->fragment_offset = 0;
						state->fragment_offset += snep_server_data.length;

						resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_CONT, NULL);

						DEBUG_SERVER_MSG("send continue response msg");

						if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
						{
							_net_nfc_util_free_mem(resp_msg->buffer);
							_net_nfc_util_free_mem(resp_msg);
						}
					}
					else
					{
						resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_SUCCESS, NULL);

						DEBUG_SERVER_MSG("send success response msg");

						if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
						{
							_net_nfc_util_free_mem(resp_msg->buffer);
							_net_nfc_util_free_mem(resp_msg);
						}

						net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

						data_s temp = { NULL, 0 };

						/* version, command, information_length are head. */
						temp.buffer = snep_server_data.buffer + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
						if ((_net_nfc_service_llcp_snep_get_information_length(&snep_server_data, &(temp.length))) == NET_NFC_OK)
						{
							net_nfc_response_p2p_receive_t resp = { 0 };
							data_s data;

							DEBUG_SERVER_MSG("process received msg");

							_net_nfc_util_alloc_mem(data.buffer, temp.length);

							memcpy(data.buffer, temp.buffer, temp.length);

							resp.data.length = temp.length;
							resp.result = NET_NFC_OK;

							net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_P2P_RECEIVE, (void*)&resp, sizeof(net_nfc_response_p2p_receive_t),
								data.buffer, resp.data.length, NULL);

							net_nfc_service_msg_processing(&temp);
						}
					}
				}
			}
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		{
			DEBUG_SERVER_MSG("step 4");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep : sending is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
			else
			{
				net_nfc_error_e error;

				DEBUG_SERVER_MSG("snep : sending response is success...");
				state->step = NET_NFC_LLCP_STEP_02;
				state->handle = current_llcp_server_state.handle;
				state->incomming_socket = current_llcp_server_state.socket;

				_net_nfc_service_llcp_snep_server(state, &error);
			}
		}
		break;

	case NET_NFC_LLCP_STEP_05 :
		{
			DEBUG_SERVER_MSG("step 5");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep: sending CONT response is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_06;

			memset(snep_server_data.buffer, 0x00, SNEP_MAX_BUFFER);
			snep_server_data.length = SNEP_MAX_BUFFER;

			if (net_nfc_controller_llcp_recv(state->handle, state->socket, &snep_server_data, result, state) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_06 :
		{
			DEBUG_SERVER_MSG("step 6");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep: recv is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			if (((data_s*)state->payload)->length > (snep_server_data.length + state->fragment_offset))
			{
				/* receive more */
				/* copy fragment to buffer. */
				data_s* fragment = state->payload;
				if (fragment != NULL)
				{
					memcpy(fragment->buffer + state->fragment_offset, snep_server_data.buffer, snep_server_data.length);
					state->fragment_offset += snep_server_data.length;
				}

				state->step = NET_NFC_LLCP_STEP_06;

				memset(snep_server_data.buffer, 0x00, SNEP_MAX_BUFFER);
				snep_server_data.length = SNEP_MAX_BUFFER;

				if (net_nfc_controller_llcp_recv(state->handle, state->socket, &snep_server_data, result, state) == false)
				{
					state->step = NET_NFC_STATE_ERROR;
					break;
				}
			}
			else if (((data_s*)state->payload)->length == (snep_server_data.length + state->fragment_offset))
			{
				/* receving is completed */
				DEBUG_SERVER_MSG("recv is completed");

				data_s* fragment = state->payload;

				if (fragment != NULL)
				{
					memcpy(fragment->buffer + state->fragment_offset, snep_server_data.buffer, snep_server_data.length);
					state->fragment_offset += snep_server_data.length;
				}

				data_s* resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_SUCCESS, NULL);

				if (resp_msg != NULL)
				{
					if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
					{

						_net_nfc_util_free_mem(resp_msg->buffer);
						_net_nfc_util_free_mem(resp_msg);
					}
				}

				net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

				data_s temp = { NULL, 0 };

				/* version, command, information_length are head. */
				temp.buffer = ((data_s*)(state->payload))->buffer + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
				if ((_net_nfc_service_llcp_snep_get_information_length(((data_s*)(state->payload)), &(temp.length))) == NET_NFC_OK)
				{
					net_nfc_response_p2p_receive_t resp = { 0 };
					data_s data;

					_net_nfc_util_alloc_mem(data.buffer, temp.length);

					memcpy(data.buffer, temp.buffer, temp.length);

					resp.data.length = temp.length;
					resp.result = NET_NFC_OK;

					net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_P2P_RECEIVE, (void*)&resp, sizeof(net_nfc_response_p2p_receive_t),
						data.buffer, resp.data.length, NULL);

					net_nfc_service_msg_processing(&temp);
				}

				_net_nfc_util_free_mem(((data_s*)(state->payload))->buffer);
				_net_nfc_util_free_mem(state->payload);
				state->payload = NULL;
				state->step = 0;
			}
			else
			{
				DEBUG_SERVER_MSG("msg length is not matched. we have got more message");

				data_s* resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_BAD_REQ, NULL);

				if (resp_msg != NULL)
				{
					if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
					{

						_net_nfc_util_free_mem(resp_msg->buffer);
						_net_nfc_util_free_mem(resp_msg);
					}
				}
				_net_nfc_util_free_mem(((data_s*)(state->payload))->buffer);
				_net_nfc_util_free_mem(state->payload);
				state->payload = NULL;
				state->step = 0;
			}
		}
		break;

	case NET_NFC_STATE_SOCKET_ERROR :
		{
			DEBUG_SERVER_MSG("snep : socket error is received %d", state->prev_result);
			need_clean_up = true;
		}
		break;

	default :
		{
			DEBUG_SERVER_MSG("unknown step = [%d]", state->step);
			need_clean_up = true;
		}
		break;

	}

	if (state->step == NET_NFC_STATE_ERROR)
	{
		net_nfc_manager_util_play_sound(NET_NFC_TASK_ERROR);
		DEBUG_SERVER_MSG("nfc state error");
		state->step = 0;
	}

	if (need_clean_up == true)
	{
		DEBUG_SERVER_MSG("socket close :: snep server");

		net_nfc_server_unset_server_state(NET_NFC_SNEP_SERVER_CONNECTED);

		net_nfc_controller_llcp_socket_close(state->socket, result);
		net_nfc_service_llcp_remove_state(state);
		_net_nfc_util_free_mem(state);
	}

	if (*result != NET_NFC_OK)
	{
		return false;
	}
	return true;
}

static bool _net_nfc_service_llcp_npp_server(net_nfc_llcp_state_t * state, net_nfc_error_e* result)
{
	bool need_clean_up = false;

	DEBUG_SERVER_MSG("_net_nfc_service_llcp_npp_server");

	if (result == NULL)
	{
		DEBUG_SERVER_MSG("result is NULL");
		return false;
	}
	*result = NET_NFC_OK;

	switch (state->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		{
			DEBUG_SERVER_MSG("NPP step 1");

			if (net_nfc_controller_llcp_create_socket(&(state->socket), NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED, SNEP_MAX_BUFFER, 1, result, state) == false)
			{
				DEBUG_SERVER_MSG("creaete socket for npp FAIL");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			if (net_nfc_controller_llcp_bind(state->socket, NPP_SAP, result) == false)
			{
				DEBUG_SERVER_MSG("bind socket for npp FAIL");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_02;
			if (net_nfc_controller_llcp_listen(state->handle, (uint8_t *)NPP_SAN, state->socket, result, state) == false)
			{
				DEBUG_SERVER_MSG("listen socket for npp FAIL");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
			state->type_app_protocol = NET_NFC_NPP;
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			DEBUG_SERVER_MSG("step 2");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("NPP: listen is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			net_nfc_llcp_state_t * new_client = NULL;
			_net_nfc_util_alloc_mem(new_client, sizeof (net_nfc_llcp_state_t));

			new_client->handle = state->handle;
			new_client->state = state->state;
			new_client->socket = state->incomming_socket;
			new_client->step = NET_NFC_LLCP_STEP_03;
			new_client->user_data = NULL;

			memset(snep_server_data.buffer, 0x00, SNEP_MAX_BUFFER);
			snep_server_data.length = SNEP_MAX_BUFFER;

			current_llcp_server_state.handle = state->handle;
			current_llcp_server_state.socket = state->incomming_socket;
			net_nfc_service_llcp_add_state(new_client);

			if (net_nfc_controller_llcp_recv(new_client->handle, new_client->socket, &snep_server_data, result, new_client) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		{
			/* send back success response */
			DEBUG_SERVER_MSG("step 3");
			DEBUG_SERVER_MSG("receive request msg from snep client");

			state->step = NET_NFC_LLCP_STEP_04;

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep : recevie is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			uint8_t resp_code = 0;
			data_s* resp_msg = NULL;

			if (_net_nfc_service_llcp_npp_check_req_msg(&snep_server_data, &resp_code) != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("Not valid request msg = [0x%X]", resp_code);
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
			else
			{
				uint32_t information_length = 0;
				if (_net_nfc_service_llcp_npp_get_information_length(&snep_server_data, &information_length) == NET_NFC_OK)
				{
					DEBUG_SERVER_MSG("MAX capa of server is = [%d] and received byte is = [%d]", SNEP_MAX_BUFFER, snep_server_data.length);

					/* msg = header(fixed 10 byte) + information(changable) */
					if (information_length + 10 > SNEP_MAX_BUFFER)
					{
						DEBUG_SERVER_MSG("request msg length is too long to receive at a time");

						DEBUG_SERVER_MSG("total msg length is = [%d]", information_length + 10);

						data_s* fragment = NULL;

						_net_nfc_util_alloc_mem(fragment, sizeof(data_s));
						if (fragment == NULL)
						{
							state->step = NET_NFC_STATE_ERROR;
							break;
						}

						_net_nfc_util_alloc_mem(fragment->buffer, (information_length + 10) * sizeof(uint8_t));
						if (fragment->buffer == NULL)
						{
							state->step = NET_NFC_STATE_ERROR;
							_net_nfc_util_free_mem(fragment);
							break;
						}

						state->step = NET_NFC_LLCP_STEP_05;

						fragment->length = information_length + 10;
						state->payload = fragment;

						memcpy(fragment->buffer, snep_server_data.buffer, snep_server_data.length);

						/* set zero. this is first time */
						state->fragment_offset = 0;
						state->fragment_offset += snep_server_data.length;

						resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_CONT, NULL);

						DEBUG_SERVER_MSG("send continue response msg");

						if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
						{

							_net_nfc_util_free_mem(resp_msg->buffer);
							_net_nfc_util_free_mem(resp_msg);
						}
					}
					else /*the size of the ndef is smaller than the max size*/
					{
						DEBUG_SERVER_MSG("Success to receive the msg");

						net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

						data_s temp = { NULL, 0 };

						/* version, command, information_length are head. */
						temp.buffer = snep_server_data.buffer + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t);
						DEBUG_SERVER_MSG("check the string = [%s]", temp.buffer);
						if ((_net_nfc_service_llcp_npp_get_information_length(&snep_server_data, &(temp.length))) == NET_NFC_OK)
						{
							net_nfc_response_p2p_receive_t resp = { 0 };
							data_s data;

							DEBUG_SERVER_MSG("process received msg");

							_net_nfc_util_alloc_mem(data.buffer, temp.length);

							memcpy(data.buffer, temp.buffer, temp.length);

							resp.data.length = temp.length;
							resp.result = NET_NFC_OK;

							net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_P2P_RECEIVE, (void*)&resp, sizeof(net_nfc_response_p2p_receive_t),
								data.buffer, resp.data.length, NULL);

							net_nfc_service_msg_processing(&temp);
						}
					}
				}
			}
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		{
			DEBUG_SERVER_MSG("step 4");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("NPP : sending is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
			else
			{
				net_nfc_error_e error;

				DEBUG_SERVER_MSG("NPP : Receiving the message is success...");
				state->step = NET_NFC_LLCP_STEP_02;
				state->handle = current_llcp_server_state.handle;
				state->incomming_socket = current_llcp_server_state.socket;
				_net_nfc_service_llcp_npp_server(state, &error);
			}
		}
		break;

	case NET_NFC_LLCP_STEP_05 :
		{
			DEBUG_SERVER_MSG("step 5");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("NPP: sending CONT response is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_06;

			memset(snep_server_data.buffer, 0x00, SNEP_MAX_BUFFER);
			snep_server_data.length = SNEP_MAX_BUFFER;

			if (net_nfc_controller_llcp_recv(state->handle, state->socket, &snep_server_data, result, state) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_06 :
		{
			DEBUG_SERVER_MSG("step 6");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep: recv is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			if (((data_s*)state->payload)->length > (snep_server_data.length + state->fragment_offset))
			{
				/* receive more */
				/* copy fragment to buffer. */
				data_s* fragment = state->payload;
				if (fragment != NULL)
				{
					memcpy(fragment->buffer + state->fragment_offset, snep_server_data.buffer, snep_server_data.length);
					state->fragment_offset += snep_server_data.length;
				}

				state->step = NET_NFC_LLCP_STEP_06;

				memset(snep_server_data.buffer, 0x00, SNEP_MAX_BUFFER);
				snep_server_data.length = SNEP_MAX_BUFFER;

				if (net_nfc_controller_llcp_recv(state->handle, state->socket, &snep_server_data, result, state) == false)
				{
					state->step = NET_NFC_STATE_ERROR;
					break;
				}
			}
			else if (((data_s*)state->payload)->length == (snep_server_data.length + state->fragment_offset))
			{
				/* receving is completed  */
				DEBUG_SERVER_MSG("recv is completed");
				data_s* fragment = state->payload;
				if (fragment != NULL)
				{
					memcpy(fragment->buffer + state->fragment_offset, snep_server_data.buffer, snep_server_data.length);
					state->fragment_offset += snep_server_data.length;
				}

				data_s* resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_SUCCESS, NULL);

				if (resp_msg != NULL)
				{
					if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
					{
						_net_nfc_util_free_mem(resp_msg->buffer);
						_net_nfc_util_free_mem(resp_msg);
					}
				}

				net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

				data_s temp = { NULL, 0 };

				/* version, command, information_length are head. */
				temp.buffer = ((data_s*)(state->payload))->buffer + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
				if ((_net_nfc_service_llcp_snep_get_information_length(((data_s*)(state->payload)), &(temp.length))) == NET_NFC_OK)
				{
					net_nfc_response_p2p_receive_t resp = { 0 };
					data_s data;

					_net_nfc_util_alloc_mem(data.buffer, temp.length);

					memcpy(data.buffer, temp.buffer, temp.length);

					resp.data.length = temp.length;
					resp.result = NET_NFC_OK;

					net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_P2P_RECEIVE, (void*)&resp, sizeof(net_nfc_response_p2p_receive_t),
						data.buffer, resp.data.length, NULL);

					net_nfc_service_msg_processing(&temp);
				}

				_net_nfc_util_free_mem(((data_s*)(state->payload))->buffer);
				_net_nfc_util_free_mem(state->payload);
				state->payload = NULL;
				state->step = 0;
			}
			else
			{
				DEBUG_SERVER_MSG("msg length is not matched. we have got more message");

				data_s* resp_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_RESP_BAD_REQ, NULL);

				if (resp_msg != NULL)
				{
					if (net_nfc_controller_llcp_send(state->handle, state->socket, resp_msg, result, state) == false)
					{
						_net_nfc_util_free_mem(resp_msg->buffer);
						_net_nfc_util_free_mem(resp_msg);
					}
				}

				_net_nfc_util_free_mem(((data_s*)(state->payload))->buffer);
				_net_nfc_util_free_mem(state->payload);
				state->payload = NULL;
				state->step = 0;
			}

			net_nfc_error_e error;

			state->step = NET_NFC_LLCP_STEP_02;
			state->handle = current_llcp_server_state.handle;
			state->incomming_socket = current_llcp_server_state.socket;
			_net_nfc_service_llcp_npp_server(state, &error);
		}
		break;

	case NET_NFC_STATE_SOCKET_ERROR :
		{
			DEBUG_SERVER_MSG("snep : socket error is received %d", state->prev_result);
			need_clean_up = true;
		}
		break;

	default :
		{
			DEBUG_SERVER_MSG("unknown step = [%d]", state->step);
			need_clean_up = true;
		}
		break;
	}

	if (state->step == NET_NFC_STATE_ERROR)
	{
		/* server should not notify exchanger result to client application. it MUST be handled in nfc-manager side */
		net_nfc_manager_util_play_sound(NET_NFC_TASK_ERROR);
		DEBUG_SERVER_MSG("nfc state error");
		state->step = 0;
	}

	if (need_clean_up == true)
	{
		DEBUG_SERVER_MSG("socket close :: NPP server");

		net_nfc_server_unset_server_state(NET_NFC_NPP_SERVER_CONNECTED);

		net_nfc_controller_llcp_socket_close(state->socket, result);
		net_nfc_service_llcp_remove_state(state);
		_net_nfc_util_free_mem(state);
	}

	if (*result != NET_NFC_OK)
	{
		return false;
	}
	return true;
}

static bool _net_nfc_service_llcp_client(net_nfc_llcp_state_t * state, net_nfc_error_e* result)
{
	bool need_clean_up = false;

	DEBUG_SERVER_MSG("_net_nfc_service_llcp_client [%d]", state->step);

	if (result == NULL)
	{
		DEBUG_SERVER_MSG("result is NULL");
		return false;
	}

	*result = NET_NFC_OK;

	if (((net_nfc_server_get_server_state() & NET_NFC_SNEP_CLIENT_CONNECTED) || (net_nfc_server_get_server_state() & NET_NFC_NPP_CLIENT_CONNECTED))
		&& state->step == NET_NFC_LLCP_STEP_01)
	{
		state->socket = current_llcp_client_state.socket;
		state->type_app_protocol = current_llcp_client_state.type_app_protocol;
		state->step = NET_NFC_LLCP_STEP_02;
	}

	switch (state->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		{
			DEBUG_SERVER_MSG("step 1");

			if (net_nfc_controller_llcp_create_socket(&(state->socket), NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED, SNEP_MAX_BUFFER, 1, result, state) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				DEBUG_SERVER_MSG(" Fail to Create socket for SNEP in client.");
				break;
			}

			DEBUG_SERVER_MSG("connect to remote server with socket = [0x%x]", state->socket);

			state->step = NET_NFC_LLCP_STEP_02;

			if (net_nfc_controller_llcp_connect_by_url(state->handle, state->socket, (uint8_t *)SNEP_SAN, result, state) == true)
			{
				DEBUG_SERVER_MSG("Success to connect by url  for SNEP in client.");
				net_nfc_server_set_server_state(NET_NFC_SNEP_CLIENT_CONNECTED);
				state->type_app_protocol = NET_NFC_SNEP;
				break;
			}
			else
			{
				state->step = NET_NFC_STATE_ERROR;
				DEBUG_SERVER_MSG("Fail to connect to  socket for snep & npp in client.");
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			DEBUG_SERVER_MSG("step 2");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep client: connect is failed [%d]", state->prev_result);

				if (NET_NFC_OPERATION_FAIL == state->prev_result)
				{
					if (net_nfc_controller_llcp_connect_by_url(state->handle, state->socket, (uint8_t *)"com.android.npp", result, state) == true)
					{
						DEBUG_SERVER_MSG("Success to connect by url  for NPP in client.");
						state->type_app_protocol = NET_NFC_NPP;
						state->step = NET_NFC_LLCP_STEP_02;
						net_nfc_server_set_server_state(NET_NFC_NPP_CLIENT_CONNECTED);

						break;
					}
				}
				else
				{
					state->step = NET_NFC_STATE_ERROR;
				}
				break;
			}

			if (state->payload == NULL)
			{
				DEBUG_SERVER_MSG("no data to send to server. just terminate client thread");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			net_nfc_llcp_socket_option_s retmoe_socket_info = { 0, 0, 0 };
			if (net_nfc_controller_llcp_get_remote_socket_info(state->handle, state->socket, &retmoe_socket_info, result) == true)
			{
				state->max_capability = retmoe_socket_info.miu;
				DEBUG_SERVER_MSG("SERVER MIU = [%d]", state->max_capability);
			}
			else
			{
				state->max_capability = SNEP_MAX_BUFFER;
				DEBUG_SERVER_MSG("SERVER MIU = [%d]", state->max_capability);
			}

			data_s* req_msg = NULL;

			if (state->type_app_protocol == NET_NFC_SNEP)
			{
				req_msg = _net_nfc_service_llcp_snep_create_msg(SNEP_REQ_PUT, (data_s *)state->payload);
			}
			else
			{
				req_msg = _net_nfc_service_llcp_npp_create_msg((data_s *)state->payload);
			}

			_net_nfc_util_free_mem(((data_s *)state->payload)->buffer);
			_net_nfc_util_free_mem(state->payload);

			state->payload = NULL;

			if (req_msg == NULL)
			{
				DEBUG_SERVER_MSG("failed to create req msg");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_03;

			if (req_msg->length <= state->max_capability)
			{
				DEBUG_SERVER_MSG("send req data");

				if (net_nfc_controller_llcp_send(state->handle, state->socket, req_msg, result, state) == false)
				{
					DEBUG_SERVER_MSG("failed to send req msg");
					_net_nfc_util_free_mem(req_msg->buffer);
					_net_nfc_util_free_mem(req_msg);
					state->step = NET_NFC_STATE_ERROR;
					break;
				}
				else
				{
					_net_nfc_util_free_mem(req_msg->buffer);
					_net_nfc_util_free_mem(req_msg);
				}
			}
			else
			{
				/* send first fragment */
				DEBUG_SERVER_MSG("send first fragment");

				data_s fragment = { NULL, 0 };

				_net_nfc_util_alloc_mem(fragment.buffer, state->max_capability * sizeof(uint8_t));
				if (fragment.buffer == NULL)
				{
					_net_nfc_util_free_mem(req_msg->buffer);
					_net_nfc_util_free_mem(req_msg);
					state->payload = NULL;
					state->step = NET_NFC_STATE_ERROR;
					break;
				}

				memcpy(fragment.buffer, req_msg->buffer, state->max_capability);
				fragment.length = state->max_capability;

				data_s* extra_msg = NULL;

				_net_nfc_util_alloc_mem(extra_msg, sizeof(data_s));
				if (extra_msg == NULL)
				{
					_net_nfc_util_free_mem(req_msg->buffer);
					_net_nfc_util_free_mem(req_msg);
					_net_nfc_util_free_mem(fragment.buffer);
					state->payload = NULL;
					state->step = NET_NFC_STATE_ERROR;
					break;
				}

				_net_nfc_util_alloc_mem(extra_msg->buffer, (req_msg->length - state->max_capability) * sizeof(uint8_t));
				if (extra_msg->buffer == NULL)
				{
					_net_nfc_util_free_mem(req_msg->buffer);
					_net_nfc_util_free_mem(req_msg);
					_net_nfc_util_free_mem(extra_msg);
					_net_nfc_util_free_mem(fragment.buffer);
					state->payload = NULL;
					state->step = NET_NFC_STATE_ERROR;
					break;
				}

				extra_msg->length = req_msg->length - state->max_capability;
				memcpy(extra_msg->buffer, req_msg->buffer + state->max_capability, extra_msg->length);

				state->payload = extra_msg;

				net_nfc_controller_llcp_send(state->handle, state->socket, &fragment, result, state);

				_net_nfc_util_free_mem(req_msg->buffer);
				_net_nfc_util_free_mem(req_msg);
				_net_nfc_util_free_mem(fragment.buffer);
			}
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		{
			DEBUG_SERVER_MSG("step 3");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep client: llcp send is failed [%d]", state->prev_result);
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_04;

			if (state->type_app_protocol == NET_NFC_SNEP)
			{
				memset(snep_client_data.buffer, 0x00, SNEP_MAX_BUFFER);
				snep_client_data.length = SNEP_MAX_BUFFER;

				DEBUG_SERVER_MSG("try to recv server response");

				if (net_nfc_controller_llcp_recv(state->handle, state->socket, &snep_client_data, result, state) == false)
				{
					DEBUG_SERVER_MSG("recv operation is failed");
					state->step = NET_NFC_STATE_ERROR;
					break;
				}
			}
			else
			{
				DEBUG_SERVER_MSG("NET_NFC_NPP. Don't use the response message. So we skip it!");
			}
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		{
			DEBUG_SERVER_MSG("step 4");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep client: llcp recv is failed [%d]", state->prev_result);
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			if (state->type_app_protocol == NET_NFC_NPP)
			{
				net_nfc_response_p2p_send_t req_msg = { 0, };

				DEBUG_SERVER_MSG("It's NET_NFC_NPP. Send completed event to client!");
				net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

				req_msg.handle = state->handle;
				req_msg.result = NET_NFC_OK;
				req_msg.trans_param = state->user_data;

				net_nfc_send_response_msg(state->client_fd, NET_NFC_MESSAGE_P2P_SEND, &req_msg, sizeof(net_nfc_response_p2p_send_t), NULL);
				break;
			}

			uint8_t code = 0;

			if (_net_nfc_service_llcp_snep_check_resp_msg(&snep_client_data) == NET_NFC_OK)
			{
				if (_net_nfc_service_llcp_snep_get_code(&snep_client_data, &code) == NET_NFC_OK)
				{
					if (code == SNEP_RESP_SUCCESS)
					{
						DEBUG_SERVER_MSG("success response");
						net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

						net_nfc_response_p2p_send_t req_msg = { 0, };

						req_msg.handle = state->handle;
						req_msg.result = NET_NFC_OK;
						req_msg.trans_param = state->user_data;

						net_nfc_send_response_msg(state->client_fd, NET_NFC_MESSAGE_P2P_SEND, &req_msg, sizeof(net_nfc_response_p2p_send_t), NULL);
					}
					else if (code == SNEP_RESP_CONT)
					{
						DEBUG_SERVER_MSG("continue response");

						data_s* msg = state->payload;

						if (msg == NULL)
						{
							state->step = NET_NFC_STATE_ERROR;
							break;
						}

						if (msg->length > state->max_capability)
						{
							state->step = NET_NFC_LLCP_STEP_05;

							data_s fragment = { NULL, 0 };
							data_s* extra_msg = NULL;

							_net_nfc_util_alloc_mem(fragment.buffer, state->max_capability * sizeof(uint8_t));
							if (fragment.buffer == NULL)
							{
								_net_nfc_util_free_mem(msg->buffer);
								_net_nfc_util_free_mem(msg);
								state->payload = NULL;
								state->step = NET_NFC_STATE_ERROR;
								break;
							}

							fragment.length = state->max_capability;
							memcpy(fragment.buffer, msg->buffer, state->max_capability);

							_net_nfc_util_alloc_mem(extra_msg, sizeof(data_s));
							if (extra_msg == NULL)
							{
								_net_nfc_util_free_mem(fragment.buffer);
								_net_nfc_util_free_mem(msg->buffer);
								_net_nfc_util_free_mem(msg);
								state->step = NET_NFC_STATE_ERROR;
								state->payload = NULL;
								break;
							}

							_net_nfc_util_alloc_mem(extra_msg->buffer, (msg->length - state->max_capability) * sizeof(uint8_t));
							if (extra_msg->buffer == NULL)
							{
								_net_nfc_util_free_mem(extra_msg);
								_net_nfc_util_free_mem(fragment.buffer);
								_net_nfc_util_free_mem(msg->buffer);
								_net_nfc_util_free_mem(msg);
								state->step = NET_NFC_STATE_ERROR;
								state->payload = NULL;
								break;
							}

							extra_msg->length = msg->length - state->max_capability;
							memcpy(extra_msg->buffer, msg->buffer + state->max_capability, msg->length - state->max_capability);

							state->payload = extra_msg;

							DEBUG_SERVER_MSG("send next fragment msg");
							net_nfc_controller_llcp_send(state->handle, state->socket, &fragment, result, state);

							_net_nfc_util_free_mem(fragment.buffer);
							_net_nfc_util_free_mem(msg->buffer);
							_net_nfc_util_free_mem(msg);
						}
						else
						{
							DEBUG_SERVER_MSG("send last fragment msg");

							state->step = NET_NFC_LLCP_STEP_06;

							net_nfc_controller_llcp_send(state->handle, state->socket, msg, result, state);

							_net_nfc_util_free_mem(msg->buffer);
							_net_nfc_util_free_mem(msg);

							state->payload = NULL;
						}
					}
					else
					{
						DEBUG_SERVER_MSG("error response = [%d] from server", code);
					}
				}
			}
			else
			{
				DEBUG_SERVER_MSG("we have got error response");
			}
		}
		break;

	case NET_NFC_LLCP_STEP_05 :
		{
			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep client: llcp send is failed [%d]", state->prev_result);
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			/* check extra data */
			if (state->payload == NULL)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			data_s* msg = state->payload;

			if (msg->length > state->max_capability)
			{
				state->step = NET_NFC_LLCP_STEP_05;

				data_s fragment = { NULL, 0 };
				data_s* extra_msg = NULL;

				_net_nfc_util_alloc_mem(fragment.buffer, state->max_capability * sizeof(uint8_t));
				fragment.length = state->max_capability;
				memcpy(fragment.buffer, msg->buffer, state->max_capability);

				_net_nfc_util_alloc_mem(extra_msg, sizeof(data_s));

				_net_nfc_util_alloc_mem(extra_msg->buffer, (msg->length - state->max_capability) * sizeof(uint8_t));
				extra_msg->length = msg->length - state->max_capability;
				memcpy(extra_msg->buffer, msg->buffer + state->max_capability, msg->length - state->max_capability);

				state->payload = extra_msg;

				DEBUG_SERVER_MSG("send next fragment msg");
				net_nfc_controller_llcp_send(state->handle, state->socket, &fragment, result, state);

				_net_nfc_util_free_mem(fragment.buffer);
				_net_nfc_util_free_mem(msg->buffer);
				_net_nfc_util_free_mem(msg);
			}
			else
			{
				state->step = NET_NFC_LLCP_STEP_06;

				DEBUG_SERVER_MSG("send last fragment msg");

				net_nfc_controller_llcp_send(state->handle, state->socket, msg, result, state);

				_net_nfc_util_free_mem(msg->buffer);
				_net_nfc_util_free_mem(msg);

				state->payload = NULL;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_06 :
		{
			net_nfc_response_p2p_send_t req_msg = { 0, };

			req_msg.handle = state->handle;

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("snep client: llcp send is failed [%d]", state->prev_result);

				req_msg.result = NET_NFC_P2P_SEND_FAIL;
				req_msg.trans_param = state->user_data;

				net_nfc_send_response_msg(state->client_fd, NET_NFC_MESSAGE_P2P_SEND, &req_msg, sizeof(net_nfc_response_p2p_send_t), NULL);
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
			else
			{
				net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

				req_msg.result = NET_NFC_OK;
				req_msg.trans_param = state->user_data;

				net_nfc_send_response_msg(state->client_fd, NET_NFC_MESSAGE_P2P_SEND, &req_msg, sizeof(net_nfc_response_p2p_send_t), NULL);
			}

			DEBUG_SERVER_MSG("sending last fragment msg is ok");
		}
		break;

	case NET_NFC_STATE_SOCKET_ERROR :
		{
			DEBUG_SERVER_MSG("snep client: socket error is received [%d]", state->prev_result);
			need_clean_up = true;
		}
		break;

	default :
		need_clean_up = true;
		break;
	}

	if (state->step == NET_NFC_STATE_ERROR)
	{
		net_nfc_response_p2p_send_t req_msg = { 0, };

		req_msg.handle = state->handle;
		req_msg.result = NET_NFC_P2P_SEND_FAIL;
		req_msg.trans_param = state->user_data;

		net_nfc_manager_util_play_sound(NET_NFC_TASK_ERROR);
		net_nfc_send_response_msg(state->client_fd, NET_NFC_MESSAGE_P2P_SEND, &req_msg, sizeof(net_nfc_response_p2p_send_t), NULL);

		net_nfc_server_unset_server_state(NET_NFC_SNEP_CLIENT_CONNECTED | NET_NFC_NPP_CLIENT_CONNECTED);

		need_clean_up = true;
	}

	if (need_clean_up == true)
	{
		DEBUG_SERVER_MSG("socket close :: LLCP client");

		net_nfc_controller_llcp_socket_close(state->socket, result);
		net_nfc_service_llcp_remove_state(state);
		_net_nfc_util_free_mem(state);

		net_nfc_server_unset_server_state(NET_NFC_SNEP_CLIENT_CONNECTED | NET_NFC_NPP_CLIENT_CONNECTED);
	}

	if (*result != NET_NFC_OK && *result != NET_NFC_BUSY)
	{
		DEBUG_SERVER_MSG("error = [%d]", *result);
		return false;
	}

	return true;
}

static data_s* _net_nfc_service_llcp_snep_create_msg(snep_command_field_e resp_field, data_s* information)
{
	uint8_t response = (uint8_t)resp_field;
	uint8_t version = 0;
	uint32_t length_field = 0;

	version = SNEP_MAJOR_VER;
	version = (((version << 4) & 0xf0) | (SNEP_MINOR_VER & 0x0f));

	data_s* snep_msg = NULL;

	if (information == NULL)
	{
		length_field = 0;

		_net_nfc_util_alloc_mem(snep_msg, sizeof(data_s));
		if (snep_msg == NULL)
		{
			return NULL;
		}

		snep_msg->length = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t);
		_net_nfc_util_alloc_mem(snep_msg->buffer, snep_msg->length * sizeof(uint8_t));
		if (snep_msg->buffer == NULL)
		{

			_net_nfc_util_free_mem(snep_msg);
			return NULL;
		}

		uint8_t* temp = snep_msg->buffer;

		/* copy version */
		*temp = version;
		temp++;

		/* copy response */
		*temp = response;
		temp++;
	}
	else
	{
		_net_nfc_util_alloc_mem(snep_msg, sizeof(data_s));
		if (snep_msg == NULL)
		{
			return NULL;
		}
		/* version 	  response		length	 	             payload*/
		snep_msg->length = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + information->length;

		_net_nfc_util_alloc_mem(snep_msg->buffer, snep_msg->length * sizeof(uint8_t));
		if (snep_msg->buffer == NULL)
		{
			_net_nfc_util_free_mem(snep_msg);
			return NULL;
		}

		memset(snep_msg->buffer, 0x00, snep_msg->length);

		uint8_t* temp = snep_msg->buffer;

		/* copy version */
		*temp = version;
		temp++;

		/* copy response */
		*temp = response;
		temp++;

		DEBUG_SERVER_MSG("information->length[%d]", information->length);
		/* change the length data as network order for compatibility with android */
		length_field = htonl(information->length);

		/* length will be se 0. so we don't need to copy value */
		memcpy(temp, &length_field, sizeof(uint32_t));
		temp += sizeof(uint32_t);

		/* copy ndef information to response msg */
		memcpy(temp, information->buffer, information->length);
	}
	return snep_msg;
}

static data_s* _net_nfc_service_llcp_npp_create_msg(data_s* information)
{
	uint8_t version;
	uint32_t length_field = 0;
	uint32_t npp_ndef_entry = NPP_NDEF_ENTRY;
	uint32_t big_endian_npp_ndef_entry = 0;

	version = NPP_MAJOR_VER;
	version = (((version << 4) & 0xf0) | (NPP_MINOR_VER & 0x0f));

	data_s* npp_msg = NULL;

	if (information == NULL)
	{
		length_field = 0;

		_net_nfc_util_alloc_mem(npp_msg, sizeof(data_s));
		if (npp_msg == NULL)
		{
			return NULL;
		}
		/* version               ndef entry       action code      message length*/
		npp_msg->length = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);
		_net_nfc_util_alloc_mem(npp_msg->buffer, npp_msg->length * sizeof(uint8_t));
		if (npp_msg->buffer == NULL)
		{

			_net_nfc_util_free_mem(npp_msg);
			return NULL;
		}

		uint8_t* temp = npp_msg->buffer;

		/* copy version */
		*temp = version;
		temp++;

		/* copy npp ndef entry */
		big_endian_npp_ndef_entry = htonl(npp_ndef_entry);
		memcpy((void *)temp, (void *)&big_endian_npp_ndef_entry, sizeof(uint32_t));
		temp += sizeof(uint32_t);
	}
	else
	{

		/*Make the npp header*/
		net_nfc_llcp_npp_t npp_header_buffer;

		npp_header_buffer.npp_version = version;
		npp_header_buffer.npp_ndef_entry = htonl(NPP_NDEF_ENTRY);
		npp_header_buffer.npp_action_code = NPP_ACTION_CODE;
		npp_header_buffer.npp_ndef_length = htonl(information->length);

		/*Make the npp message*/
		_net_nfc_util_alloc_mem(npp_msg, sizeof(data_s));
		if (npp_msg == NULL)
		{
			return NULL;
		}

		npp_msg->length = sizeof(net_nfc_llcp_npp_t) + information->length;

		_net_nfc_util_alloc_mem(npp_msg->buffer, npp_msg->length * sizeof(uint8_t));
		if (npp_msg->buffer == NULL)
		{
			_net_nfc_util_free_mem(npp_msg);
			return NULL;
		}

		memset(npp_msg->buffer, 0x00, npp_msg->length);

		memcpy(npp_msg->buffer, &npp_header_buffer, sizeof(net_nfc_llcp_npp_t));

		memcpy((npp_msg->buffer) + sizeof(net_nfc_llcp_npp_t), information->buffer, information->length);

	}

	return npp_msg;
}

static net_nfc_error_e _net_nfc_service_llcp_snep_check_req_msg(data_s* snep_msg, uint8_t* resp_code)
{
	/* version check */
	/* command check */

	if (snep_msg == NULL || snep_msg->buffer == NULL || resp_code == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*resp_code = 0;

	uint8_t* temp = NULL;
	uint8_t version = 0;
	bool is_supported_req = false;
	uint8_t req = 0;

	temp = snep_msg->buffer;

	/* get vesrion. and compare it with ours */
	version = *temp;

	if (version == 0)
	{
		DEBUG_SERVER_MSG("no version is set");
		*resp_code = SNEP_RESP_UNSUPPORTED_VER;
		return NET_NFC_UNKNOWN_ERROR;
	}
	else
	{
		uint8_t major = (version & 0xf0) >> 4;
		uint8_t minor = (version & 0x0f);

		DEBUG_SERVER_MSG("major = [%d], minor = [%d]", major, minor);

		if (major != SNEP_MAJOR_VER || minor > SNEP_MINOR_VER)
		{
			DEBUG_SERVER_MSG("version is not matched");
			*resp_code = SNEP_RESP_UNSUPPORTED_VER;
			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	temp++;

	/* get command */
	req = *temp;
	temp++;

	switch (req)
	{
	case SNEP_REQ_CONTINUE :
	case SNEP_REQ_PUT :
	case SNEP_REQ_REJECT :
		is_supported_req = true;
		break;

	case SNEP_REQ_GET :
		default :
		is_supported_req = false;
		break;

	}

	if (is_supported_req == false)
	{

		DEBUG_SERVER_MSG("not supported req command");
		*resp_code = SNEP_RESP_NOT_IMPLEMENT;
		return NET_NFC_UNKNOWN_ERROR;
	}

	uint32_t information_length = 0;

	memcpy(&information_length, temp, sizeof(uint32_t));

	if (req == SNEP_REQ_PUT && information_length == 0)
	{

		DEBUG_SERVER_MSG("no information data is exist");
		*resp_code = SNEP_RESP_BAD_REQ;
		return NET_NFC_UNKNOWN_ERROR;
	}

	return NET_NFC_OK;
}

static net_nfc_error_e _net_nfc_service_llcp_npp_check_req_msg(data_s* npp_msg, uint8_t* resp_code)
{
	/* version check */
	/* action code  check */

	if (npp_msg == NULL || npp_msg->buffer == NULL || resp_code == NULL)
	{

		return NET_NFC_NULL_PARAMETER;
	}

	*resp_code = 0;

	uint8_t* temp = NULL;
	uint8_t version = 0;
	bool is_supported_req = false;
	uint32_t ndef_entry_number = 0;
	uint8_t action_codes = 0;

	temp = npp_msg->buffer;

	/* get vesrion. and compare it with ours */
	version = *temp;

	if (version == 0)
	{
		DEBUG_SERVER_MSG("no version is set");
		*resp_code = NPP_RESP_UNSUPPORTED_VER;
		return NET_NFC_UNKNOWN_ERROR;
	}
	else
	{
		uint8_t major = (version & 0xf0) >> 4;
		uint8_t minor = (version & 0x0f);

		DEBUG_SERVER_MSG("major = [%d], minor = [%d]", major, minor);

		if (major != 0x00 || minor > 0x01)
		{
			DEBUG_SERVER_MSG("version is not matched");
			*resp_code = NPP_RESP_UNSUPPORTED_VER;
			return NET_NFC_UNKNOWN_ERROR;
		}

	}

	/*Increase the address. Because we already get the version of the npp. so we have to get the "number of ndef entry" */
	temp++;

	/* get command */
	ndef_entry_number = ntohl(*((uint32_t *)(temp)));

	DEBUG_SERVER_MSG("check the number of ndef entry = [%d]", ndef_entry_number);
	temp += 4;

	/* action code*/
	memcpy(&action_codes, temp, sizeof(uint8_t));

	DEBUG_SERVER_MSG("check the action_codes = [%d]", action_codes);

	switch (action_codes)
	{
	case 0x01 :
		is_supported_req = true;
		break;
	default :
		is_supported_req = false;
		break;

	}

	if (is_supported_req == false)
	{

		DEBUG_SERVER_MSG("not supported action codes");
		*resp_code = NPP_RESP_NOT_IMPLEMEN;
		return NET_NFC_UNKNOWN_ERROR;
	}

	temp++;

	uint32_t information_length = 0;

	memcpy(&information_length, temp, sizeof(uint32_t));

	if (action_codes != 0x01 || information_length == 0)
	{

		DEBUG_SERVER_MSG("no information data is exist");
		*resp_code = NPP_RESP_UNSUPPORTED_VER;
		return NET_NFC_UNKNOWN_ERROR;
	}
	return NET_NFC_OK;
}

static net_nfc_error_e _net_nfc_service_llcp_snep_get_code(data_s* snep_msg, uint8_t* code)
{
	if (snep_msg == NULL || snep_msg->buffer == NULL || code == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	uint8_t* temp = NULL;

	temp = snep_msg->buffer;

	temp++;

	*code = *temp;

	return NET_NFC_OK;
}

static net_nfc_error_e _net_nfc_service_llcp_snep_get_information_length(data_s* snep_msg, uint32_t* length)
{
	if (snep_msg == NULL || snep_msg->buffer == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	uint8_t* temp = NULL;
	uint32_t temp_length = 0;

	temp = snep_msg->buffer;
	temp += 2;

	/* change the length data as host order for compatibility with android */
	temp_length = ntohl(*((uint32_t *)(temp)));
	memcpy(length, &temp_length, sizeof(uint32_t));

	DEBUG_SERVER_MSG("check the snep ndef length [%d]", *length);

	return NET_NFC_OK;
}

static net_nfc_error_e _net_nfc_service_llcp_npp_get_information_length(data_s* npp_msg, uint32_t* length)
{
	if (npp_msg == NULL || npp_msg->buffer == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	uint8_t* temp = NULL;
	uint32_t temp_length = 0;

	temp = npp_msg->buffer;
	temp += 6;

	DEBUG_SERVER_MSG("check the npp ndef length address= [%p]", temp);

	temp_length = ntohl(*((uint32_t *)(temp)));
	memcpy(length, &temp_length, sizeof(uint32_t));

	DEBUG_SERVER_MSG("check the npp ndef temp_length= [%d]", temp_length);

	DEBUG_SERVER_MSG("check the npp ndef length= [%d]", *length);

	return NET_NFC_OK;
}

static net_nfc_error_e _net_nfc_service_llcp_snep_check_resp_msg(data_s* snep_msg)
{
	/* version check */
	/* command check */

	if (snep_msg == NULL || snep_msg->buffer == NULL)
	{

		return NET_NFC_NULL_PARAMETER;
	}

	uint8_t* temp = NULL;
	uint8_t version = 0;
	bool is_supported_resp = false;
	uint8_t resp = 0;

	temp = snep_msg->buffer;

	/* get vesrion. and compare it with ours */
	version = *temp;

	if (version == 0)
	{
		DEBUG_SERVER_MSG("version is wrong");
		return NET_NFC_UNKNOWN_ERROR;
	}
	else
	{
		uint8_t major = (version & 0xf0) >> 4;
		uint8_t minor = (version & 0x0f);

		DEBUG_SERVER_MSG("major[%d], minor[%d]", major, minor);

		if (major != SNEP_MAJOR_VER || minor > SNEP_MINOR_VER)
		{
			DEBUG_SERVER_MSG("version is not matched");
			return NET_NFC_UNKNOWN_ERROR;
		}

	}

	temp++;

	/* get command */
	resp = *temp;
	temp++;

	DEBUG_SERVER_MSG("result = [%d]", resp);

	switch (resp)
	{
	case SNEP_RESP_CONT :
	case SNEP_RESP_SUCCESS :
	case SNEP_RESP_NOT_FOUND :
	case SNEP_RESP_EXCESS_DATA :
	case SNEP_RESP_BAD_REQ :
	case SNEP_RESP_NOT_IMPLEMENT :
	case SNEP_RESP_UNSUPPORTED_VER :
	case SNEP_RESP_REJECT :
		is_supported_resp = true;
		break;
	default :
		is_supported_resp = false;
		break;

	}

	if (is_supported_resp == false)
	{
		DEBUG_SERVER_MSG("not supported resp command = [%d]", resp);
		return NET_NFC_UNKNOWN_ERROR;
	}

	uint32_t information_length = 0;

	memcpy(&information_length, temp, sizeof(uint32_t));

	if (resp != SNEP_RESP_SUCCESS && information_length != 0)
	{
		DEBUG_SERVER_MSG("error response should not have any information data");
		return NET_NFC_UNKNOWN_ERROR;
	}

	return NET_NFC_OK;
}
