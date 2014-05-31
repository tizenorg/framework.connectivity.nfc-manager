/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.1 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://floralicense.org/license/
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */


#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_util_handover.h"

#include "net_nfc_manager_util_private.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_service_private.h"
#include "net_nfc_service_llcp_private.h"
#include "net_nfc_service_llcp_handover_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_server_context_private.h"

#include "bluetooth-api.h"

static uint8_t conn_handover_req_buffer[CH_MAX_BUFFER] = {0,};
static uint8_t conn_handover_sel_buffer[CH_MAX_BUFFER] = {0,};

static data_s conn_handover_req_data = {conn_handover_req_buffer, CH_MAX_BUFFER};
static data_s conn_handover_sel_data = {conn_handover_sel_buffer, CH_MAX_BUFFER};

static bool _net_nfc_service_llcp_check_hr_record_validation(ndef_message_s * message);
static bool _net_nfc_service_llcp_check_hs_record_validation(ndef_message_s * message);

net_nfc_error_e _net_nfc_service_llcp_create_low_power_selector_message(ndef_message_s *request_msg, ndef_message_s *select_msg);
net_nfc_error_e net_nfc_service_llcp_handover_get_oob_data(net_nfc_carrier_config_s *config, bt_oob_data_t *oob);

net_nfc_error_e net_nfc_service_llcp_handover_create_carrier_configs(ndef_message_s *msg, net_nfc_conn_handover_carrier_type_e type, bool requester, net_nfc_llcp_state_t *state, int next_step);
int net_nfc_service_llcp_handover_append_bt_carrier_config(net_nfc_handover_create_config_context_t *context);
int net_nfc_service_llcp_handover_append_wifi_carrier_config(net_nfc_handover_create_config_context_t *context);
int net_nfc_service_llcp_handover_iterate_carrier_configs(net_nfc_handover_create_config_context_t *context);
int net_nfc_service_llcp_handover_go_to_next_config(net_nfc_handover_create_config_context_t *context);
static void _net_nfc_service_llcp_bt_create_config_cb(int event, bluetooth_event_param_t *param, void *user_data);

net_nfc_error_e net_nfc_service_llcp_handover_process_carrier_config(net_nfc_carrier_config_s *config, bool requester, net_nfc_llcp_state_t *state, int next_step);
int net_nfc_service_llcp_handover_process_bt_config(net_nfc_handover_process_config_context_t *context);

int net_nfc_service_llcp_handover_return_to_step(net_nfc_handover_context_t *context);
net_nfc_error_e net_nfc_service_llcp_handover_bt_change_data_order(net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_service_llcp_handover_send_request_msg(net_nfc_request_connection_handover_t *msg)
{
	net_nfc_error_e error = NET_NFC_OK;

	DEBUG_SERVER_MSG("start");

	if (msg == NULL || msg->handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_state_t *conn_handover_requester = NULL;
	_net_nfc_util_alloc_mem(conn_handover_requester, sizeof(net_nfc_llcp_state_t));
	if (conn_handover_requester == NULL)
	{
		DEBUG_SERVER_MSG("conn_handover_requester is NULL");
		return NET_NFC_ALLOC_FAIL;
	}

	conn_handover_requester->client_fd = msg->client_fd;
	conn_handover_requester->handle = msg->handle;
	conn_handover_requester->state = NET_NFC_STATE_CONN_HANDOVER_REQUEST;
	conn_handover_requester->step = NET_NFC_LLCP_STEP_01;
	conn_handover_requester->type = msg->type;

	net_nfc_service_llcp_add_state(conn_handover_requester);

	if (net_nfc_service_llcp_connection_handover_requester(conn_handover_requester, &error) == true)
	{
		error = NET_NFC_OK;
	}
	else
	{
		DEBUG_SERVER_MSG("connection handover request is failed = [%d]", error);
		error = NET_NFC_OPERATION_FAIL;
	}

	return error;
}

bool net_nfc_service_llcp_create_server_socket(net_nfc_llcp_state_t *state, net_nfc_socket_type_e socket_type, uint16_t miu, uint8_t rw, int sap, char *san, net_nfc_error_e *result)
{
	bool ret = false;

	if (result == NULL)
	{
		return ret;
	}

	if (state == NULL || san == NULL)
	{
		*result = NET_NFC_NULL_PARAMETER;
		return ret;
	}

	DEBUG_SERVER_MSG("begin net_nfc_service_llcp_create_server_socket");

	if ((ret = net_nfc_controller_llcp_create_socket(&(state->socket), socket_type, miu, rw, result, state)) == true)
	{
		DEBUG_SERVER_MSG("bind server socket with service acess point = [0x%x]", sap);

		if ((ret = net_nfc_controller_llcp_bind(state->socket, sap, result)) == true)
		{
			DEBUG_SERVER_MSG("listen server socket with service access name = [%s]", san);

			if ((ret = net_nfc_controller_llcp_listen(state->handle, (uint8_t *)san, state->socket, result, state)) == true)
			{
				DEBUG_SERVER_MSG("net_nfc_controller_llcp_listen success!!");
			}
			else
			{
				DEBUG_ERR_MSG("net_nfc_controller_llcp_listen failed [%d]", *result);
				net_nfc_controller_llcp_socket_close(state->socket, result);
				state->socket = 0;
			}
		}
		else
		{
			DEBUG_ERR_MSG("net_nfc_controller_llcp_bind failed [%d]", *result);
			net_nfc_controller_llcp_socket_close(state->socket, result);
			state->socket = 0;
		}
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_create_socket failed [%d]", *result);
	}

	return ret;
}

static net_nfc_llcp_state_t *_net_nfc_service_llcp_add_new_state(int client_fd, net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, llcp_state_e state, unsigned int step, void *user_data)
{
	net_nfc_llcp_state_t *context = NULL;

	LOGD("[%s] START", __func__);

	if (handle == NULL)
	{
		return context;
	}

	_net_nfc_util_alloc_mem(context, sizeof(net_nfc_llcp_state_t));
	if (context != NULL)
	{
		context->client_fd = client_fd;
		context->handle = handle;
		context->socket = socket;
		context->state = state;
		context->step = step;
		context->user_data = user_data;

		net_nfc_service_llcp_add_state(context);
	}

	LOGD("[%s] END", __func__);

	return context;
}

static void _net_nfc_service_llcp_handover_send_response(int socket, net_nfc_exchanger_event_e event, net_nfc_conn_handover_carrier_type_e type, data_s *data)
{
	LOGD("[%s] START", __func__);

	if (net_nfc_server_check_client_is_running(socket) == true)
	{
		net_nfc_response_connection_handover_t resp_msg = { 0, };

		resp_msg.result = NET_NFC_OK;
		resp_msg.event = event;

		resp_msg.type = type;
		if (data != NULL && data->buffer != NULL && data->length != 0)
		{
			resp_msg.data.length = data->length;
			if (net_nfc_send_response_msg(socket, NET_NFC_MESSAGE_CONNECTION_HANDOVER, &resp_msg, sizeof(net_nfc_response_connection_handover_t), data->buffer, data->length, NULL) == true)
			{
				DEBUG_SERVER_MSG("send exchange message to client");
			}
		}
		else
		{
			if (net_nfc_send_response_msg(socket, NET_NFC_MESSAGE_CONNECTION_HANDOVER, &resp_msg, sizeof(net_nfc_response_connection_handover_t), NULL) == true)
			{
				DEBUG_SERVER_MSG("send exchange message to client");
			}
		}
	}

	LOGD("[%s] END", __func__);
}

static bool _net_nfc_service_llcp_send_ndef_message(net_nfc_llcp_state_t *state, ndef_message_s *msg, net_nfc_error_e *result)
{
	bool ret = false;
	data_s send_data = { NULL, 0 };

	LOGD("[%s] START", __func__);

	if (result == NULL)
	{
		return ret;
	}

	if (state == NULL || msg == NULL)
	{
		*result = NET_NFC_NULL_PARAMETER;
		return ret;
	}

	send_data.length = net_nfc_util_get_ndef_message_length(msg);

	if (send_data.length > 0)
	{
		_net_nfc_util_alloc_mem(send_data.buffer, send_data.length);
		if (send_data.buffer != NULL)
		{
			if ((*result =net_nfc_util_convert_ndef_message_to_rawdata(msg, &send_data)) == NET_NFC_OK)
			{
				if ((ret = net_nfc_controller_llcp_send(state->handle, state->socket, &send_data, result, state)) == true)
				{
					DEBUG_SERVER_MSG("net_nfc_controller_llcp_send success!!");
				}
				else
				{
					DEBUG_ERR_MSG("net_nfc_controller_llcp_send failed [%d]", *result);
				}
			}
			else
			{
				DEBUG_ERR_MSG("_net_nfc_ndef_to_rawdata failed [%d]", *result);
			}

			_net_nfc_util_free_mem(send_data.buffer);
		}
		else
		{
			*result = NET_NFC_ALLOC_FAIL;
		}
	}
	else
	{
		*result = NET_NFC_INVALID_PARAM;
	}

	LOGD("[%s] END", __func__);

	return ret;
}

net_nfc_error_e _net_nfc_service_llcp_get_carrier_record_by_priority_order(ndef_message_s *request_msg, ndef_record_s **record)
{
	net_nfc_error_e result = NET_NFC_INVALID_PARAM;
	unsigned int carrier_count = 0;

	LOGD("[%s] START", __func__);

	if (request_msg == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((result = net_nfc_util_get_alternative_carrier_record_count(request_msg, &carrier_count)) == NET_NFC_OK)
	{
		int idx, priority;
		net_nfc_conn_handover_carrier_type_e carrier_type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;

		/* apply priority (order NET_NFC_CONN_HANDOVER_CARRIER_BT ~ NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS) */
		for (priority = NET_NFC_CONN_HANDOVER_CARRIER_BT; *record == NULL && priority < NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN; priority++)
		{
			/* check each carrier record and create matched record */
			for (idx = 0; idx < carrier_count; idx++)
			{
				if ((net_nfc_util_get_alternative_carrier_type(request_msg, idx, &carrier_type) == NET_NFC_OK) && (carrier_type == priority))
				{
					DEBUG_SERVER_MSG("selected carrier type = [%d]", carrier_type);
					net_nfc_util_get_carrier_config_record(request_msg, idx, record);
					result = NET_NFC_OK;
					break;
				}
			}
		}
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_record_count failed");
	}

	LOGD("[%s] END", __func__);

	return result;
}

static net_nfc_error_e _net_nfc_service_handover_create_requester_message_from_rawdata(ndef_message_s **request_msg, data_s *data)
{
	net_nfc_error_e result;

	if ((result = net_nfc_util_create_ndef_message(request_msg)) == NET_NFC_OK)
	{
		if ((result = net_nfc_util_convert_rawdata_to_ndef_message(data, *request_msg)) == NET_NFC_OK)
		{
			if (_net_nfc_service_llcp_check_hr_record_validation(*request_msg) == true)
			{
				result = NET_NFC_OK;
			}
			else
			{
				DEBUG_ERR_MSG("record is not valid or is not available");
				result = NET_NFC_INVALID_PARAM;
			}
		}
		else
		{
			DEBUG_ERR_MSG("_net_nfc_ndef_rawdata_to_ndef failed [%d]", result);
		}
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_util_create_ndef_message failed [%d]", result);
	}

	return result;
}

bool net_nfc_service_llcp_connection_handover_selector(net_nfc_llcp_state_t *state, net_nfc_error_e *result)
{
	bool need_clean_up = false;

	LOGD("[%s] START", __func__);

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

			if (net_nfc_service_llcp_create_server_socket(state, NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED, CH_MAX_BUFFER, 1, CONN_HANDOVER_SAP, CONN_HANDOVER_SAN, result) == true)
			{
				state->step = NET_NFC_LLCP_STEP_02;
			}
			else
			{
				state->step = NET_NFC_STATE_ERROR;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			DEBUG_SERVER_MSG("step 2");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover selector: listen is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			net_nfc_llcp_state_t *new_client = _net_nfc_service_llcp_add_new_state(state->client_fd, state->handle, state->incomming_socket, state->state, NET_NFC_LLCP_STEP_03, NULL);
			if (new_client != NULL)
			{
				memset(conn_handover_sel_data.buffer, 0x00, CH_MAX_BUFFER);
				conn_handover_sel_data.length = CH_MAX_BUFFER;

				if (net_nfc_controller_llcp_recv(new_client->handle, new_client->socket, &conn_handover_sel_data, result, new_client) == false)
				{
					DEBUG_ERR_MSG("net_nfc_controller_llcp_recv failed [%d]", *result);
					state->step = NET_NFC_STATE_ERROR;
				}
			}
			else
			{
				DEBUG_ERR_MSG("_net_nfc_service_llcp_add_new_state returns NULL");
				state->step = NET_NFC_STATE_ERROR;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		{
			DEBUG_SERVER_MSG("step 3");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover selector : receive is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			DEBUG_SERVER_MSG("handover selector : receiving is successful");
			net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

			/* process and send message */
			/* get requester message */
			if ((*result = _net_nfc_service_handover_create_requester_message_from_rawdata(&state->requester, &conn_handover_sel_data)) == NET_NFC_OK)
			{
				unsigned int count = 0;

				if ((*result = net_nfc_util_get_alternative_carrier_record_count(state->requester, &count)) == NET_NFC_OK)
				{
					/* create selector message */
					if ((*result = net_nfc_util_create_handover_select_message(&state->selector)) == NET_NFC_OK)
					{
						if (1/* power state */ || count == 1)
						{
							ndef_record_s *record = NULL;

							/* fill alternative carrier information */
							if ((*result = _net_nfc_service_llcp_get_carrier_record_by_priority_order(state->requester, &record)) == NET_NFC_OK)
							{
								net_nfc_conn_handover_carrier_type_e type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;

								if ((*result = net_nfc_util_get_alternative_carrier_type_from_record(record, &type)) == NET_NFC_OK)
								{
									if ((*result = net_nfc_service_llcp_handover_create_carrier_configs(state->selector, type, false, state, NET_NFC_LLCP_STEP_04)) != NET_NFC_OK)
									{
										state->step = NET_NFC_STATE_ERROR;
										DEBUG_ERR_MSG("net_nfc_service_llcp_handover_create_carrier_configs failed [%d]", *result);
									}
								}
								else
								{
									state->step = NET_NFC_STATE_ERROR;
									DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_type_from_record failed [%d]", *result);
								}
							}
							else
							{
								state->step = NET_NFC_STATE_ERROR;
								DEBUG_ERR_MSG("_net_nfc_service_llcp_get_carrier_record_by_priority_order failed [%d]", *result);
							}
						}
						else /* low power && count > 1 */
						{
							state->low_power = true;

							if ((*result = _net_nfc_service_llcp_create_low_power_selector_message(state->requester, state->selector)) == NET_NFC_OK)
							{
								state->step = NET_NFC_LLCP_STEP_06;
								net_nfc_service_llcp_connection_handover_selector(state, result);
							}
							else
							{
								state->step = NET_NFC_STATE_ERROR;
								DEBUG_ERR_MSG("_net_nfc_service_llcp_create_low_power_selector_message failed [%d]", *result);
							}
						}
					}
					else
					{
						state->step = NET_NFC_STATE_ERROR;
						DEBUG_ERR_MSG("net_nfc_util_create_handover_select_message failed [%d]", *result);
					}
				}
				else
				{
					state->step = NET_NFC_STATE_ERROR;
					DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_record_count failed [%d]", *result);
				}
			}
			else
			{
				state->step = NET_NFC_STATE_ERROR;
				DEBUG_ERR_MSG("_net_nfc_service_handover_create_requester_message_from_rawdata failed [%d]", *result);
			}
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		{
			ndef_record_s *record = NULL;

			DEBUG_SERVER_MSG("step 4");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover selector : recevie is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			/* fill alternative carrier information */
			if ((*result = _net_nfc_service_llcp_get_carrier_record_by_priority_order(state->requester, &record)) == NET_NFC_OK)
			{
				net_nfc_conn_handover_carrier_type_e type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;

				DEBUG_SERVER_MSG("record [%p]", record);

				if ((*result = net_nfc_util_get_alternative_carrier_type_from_record(record, &type)) == NET_NFC_OK)
				{
					net_nfc_carrier_config_s *config = NULL;

					DEBUG_SERVER_MSG("type [%d]", type);

					*result = net_nfc_util_create_carrier_config_from_config_record(&config, record);

					DEBUG_SERVER_MSG("config [%p]", config);

					*result = net_nfc_service_llcp_handover_process_carrier_config(config, false, state, NET_NFC_LLCP_STEP_05);

					if (*result != NET_NFC_OK && *result != NET_NFC_BUSY)
					{
						DEBUG_ERR_MSG("net_nfc_service_llcp_handover_process_carrier_config failed [%d]", *result);
						state->step = NET_NFC_STATE_ERROR;
					}

					DEBUG_SERVER_MSG("after net_nfc_service_llcp_handover_process_carrier_config");
				}
				else
				{
					state->step = NET_NFC_STATE_ERROR;
					DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_type_from_record failed [%d]", *result);
				}
			}
			else
			{
				state->step = NET_NFC_STATE_ERROR;
				DEBUG_ERR_MSG("_net_nfc_service_llcp_get_carrier_record_by_priority_order failed [%d]", *result);
			}
		}
		break;

	case NET_NFC_LLCP_STEP_05 :
		{
			DEBUG_SERVER_MSG("step 5");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover selector : recevie is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			/* send ndef message via llcp */
			if (_net_nfc_service_llcp_send_ndef_message(state, state->selector, result) == true)
			{
				DEBUG_SERVER_MSG("handover selector : sending select msg is success");

				if (state->low_power == true)
				{
					DEBUG_SERVER_MSG("activate_forced == false, next step is NET_NFC_LLCP_STEP_02");
					state->step = NET_NFC_LLCP_STEP_02;
				}
				else
				{
					DEBUG_SERVER_MSG("next step is NET_NFC_LLCP_STEP_06");
					state->step = NET_NFC_LLCP_STEP_06;
				}
			}
			else
			{
				DEBUG_ERR_MSG("handover selector : sending select msg is failed [%d]", *result);
			}

			if (*result == NET_NFC_OK || *result == NET_NFC_BUSY)
			{
			}
			else
			{
				DEBUG_ERR_MSG("_net_nfc_service_llcp_send_selector_ndef_message failed [%d]", *result);
				state->step = NET_NFC_STATE_ERROR;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_06 :
		{
			DEBUG_SERVER_MSG("step 6");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover selector : send ndef failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			net_nfc_util_free_ndef_message(state->requester);
			net_nfc_util_free_ndef_message(state->selector);

			state->step = 0;
		}
		break;

	case NET_NFC_STATE_SOCKET_ERROR :
		{
			DEBUG_SERVER_MSG("conn handover selector : socket error is received %d", state->prev_result);
			need_clean_up = true;
		}
		break;

	default :
		{
			DEBUG_SERVER_MSG("unknown step");
			need_clean_up = true;
		}
		break;
	}

	if (state->step == NET_NFC_STATE_ERROR)
	{
		net_nfc_manager_util_play_sound(NET_NFC_TASK_ERROR);
		state->step = 0;
	}

	if (need_clean_up == true)
	{
		net_nfc_controller_llcp_socket_close(state->socket, result);
		net_nfc_service_llcp_remove_state(state);
		_net_nfc_util_free_mem(state);
	}

	if (*result != NET_NFC_BUSY && *result != NET_NFC_OK)
	{
		return false;
	}

	LOGD("[%s] END", __func__);

	return true;
}

net_nfc_error_e _net_nfc_service_llcp_create_requester_ndef_message(net_nfc_llcp_state_t *state)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	net_nfc_conn_handover_carrier_type_e carrier_type;

	LOGD("[%s] START", __func__);

	if (state->requester == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	carrier_type = state->type;

	if (state->selector != NULL)
	{
		/* selector is low power state... so request one alternative carrier */
		if ((result = net_nfc_util_get_alternative_carrier_type(state->selector, 0, &carrier_type)) == NET_NFC_OK)
		{
			DEBUG_SERVER_MSG("select_msg 0 carrier type [%d]", carrier_type);
		}
	}

	if ((result = net_nfc_service_llcp_handover_create_carrier_configs(state->requester, carrier_type, true, state, NET_NFC_LLCP_STEP_03)) != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_service_llcp_handover_create_carrier_configs failed [%d]", result);
	}

	LOGD("[%s] END", __func__);

	return result;
}

net_nfc_error_e _net_nfc_service_llcp_get_carrier_record(ndef_message_s *select_msg, ndef_record_s **carrier_record)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	unsigned int carrier_count;

	LOGD("[%s] START", __func__);

	if (select_msg == NULL || carrier_record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	/* connect selected carrier...  :) */
	if ((result = net_nfc_util_get_alternative_carrier_record_count(select_msg, &carrier_count)) == NET_NFC_OK)
	{
		int idx;
		net_nfc_conn_handover_carrier_type_e carrier_type;

		for (idx = 0; idx < carrier_count; idx++)
		{
			if ((result = net_nfc_util_get_alternative_carrier_type(select_msg, idx, &carrier_type)) == NET_NFC_OK)
			{
				net_nfc_conn_handover_carrier_state_e cps;

				cps = net_nfc_util_get_cps(carrier_type);

				switch (carrier_type)
				{
				case NET_NFC_CONN_HANDOVER_CARRIER_BT :
					DEBUG_SERVER_MSG("if bt is off, then turn on");
					if (cps != NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE && cps != NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING)
					{
						DEBUG_SERVER_MSG("turn on bt");
						net_nfc_util_enable_bluetooth();
					}

					net_nfc_util_get_carrier_config_record(select_msg, idx, carrier_record);
					break;

				default :
					continue;
				}

				if (*carrier_record != NULL)
				{
					result = NET_NFC_OK;
					break;
				}
			}
			else
			{
				DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_type failed [%d]", result);
			}
		}
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_record_count failed [%d]", result);
	}

	LOGD("[%s] END", __func__);

	return result;
}

static net_nfc_error_e _net_nfc_service_handover_create_selector_message_from_rawdata(ndef_message_s **select_msg, data_s *data)
{
	net_nfc_error_e result;

	if (select_msg == NULL)
		return NET_NFC_NULL_PARAMETER;

	if ((result = net_nfc_util_create_ndef_message(select_msg)) == NET_NFC_OK)
	{
		if ((result = net_nfc_util_convert_rawdata_to_ndef_message(data, *select_msg)) == NET_NFC_OK)
		{
			/* if record is not Hs record, then */
			if (_net_nfc_service_llcp_check_hs_record_validation(*select_msg) == true)
			{
				result = NET_NFC_OK;
			}
			else
			{
				DEBUG_ERR_MSG("record is not valid or is not available");
				result = NET_NFC_INVALID_PARAM;
			}
		}
		else
		{
			DEBUG_ERR_MSG("_net_nfc_ndef_rawdata_to_ndef failed [%d]", result);
		}
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_util_create_ndef_message failed [%d]", result);
	}

	return result;
}

bool net_nfc_service_llcp_connection_handover_requester(net_nfc_llcp_state_t *state, net_nfc_error_e *result)
{
	bool need_clean_up = false;

	LOGD("[%s] START", __func__);

	if (state == NULL || result == NULL)
	{
		DEBUG_SERVER_MSG("state/result is NULL");
		return false;
	}

	*result = NET_NFC_OK;

	switch (state->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		{
			DEBUG_SERVER_MSG("step 1");

			if (net_nfc_controller_llcp_create_socket(&(state->socket), NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED, CH_MAX_BUFFER, 1, result, state) == false)
			{
				DEBUG_SERVER_MSG("creating socket is failed");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			DEBUG_SERVER_MSG("connect to remote server with socket = [0x%x]", state->socket);

			state->step = NET_NFC_LLCP_STEP_02;

			if (net_nfc_controller_llcp_connect_by_url(state->handle, state->socket, (uint8_t *)CONN_HANDOVER_SAN, result, state) == false)
			{
				DEBUG_SERVER_MSG("making connection is failed");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			DEBUG_SERVER_MSG("step 2");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover requester : connect is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_03;

			if ((*result = net_nfc_util_create_handover_request_message(&state->requester)) == NET_NFC_OK)
			{
				net_nfc_conn_handover_carrier_type_e carrier_type;

				if (state->selector != NULL)
				{
					/* selector is low power state... so request one alternative carrier */
					if ((*result = net_nfc_util_get_alternative_carrier_type(state->selector, 0, &carrier_type)) == NET_NFC_OK)
					{
						DEBUG_SERVER_MSG("select_msg 0 carrier type [%d]", carrier_type);
					}
					else
					{
						DEBUG_SERVER_MSG("select_msg 0 carrier type failed [%d]", *result);

						carrier_type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
					}

					net_nfc_util_free_ndef_message(state->selector);
					state->selector = NULL;
				}
				else
				{
					carrier_type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
				}

				if ((*result = net_nfc_service_llcp_handover_create_carrier_configs(state->requester, carrier_type, true, state, NET_NFC_LLCP_STEP_03)) != NET_NFC_OK)
				{
					DEBUG_ERR_MSG("net_nfc_service_llcp_handover_create_carrier_configs failed [%d]", *result);
				}
			}
			else
			{
				DEBUG_ERR_MSG("handover requester : sending select msg is failed [%d]", *result);
				state->step = NET_NFC_STATE_ERROR;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		{
			DEBUG_SERVER_MSG("step 3");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover requester : connect is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_04;

			/* send ndef message via llcp */
			if (_net_nfc_service_llcp_send_ndef_message(state, state->requester, result) == true)
			{
				DEBUG_SERVER_MSG("handover requester : sending request msg is success");
			}
			else
			{
				DEBUG_ERR_MSG("handover requester : sending request msg is failed [%d]", *result);
				state->step = NET_NFC_STATE_ERROR;
			}

			net_nfc_util_free_ndef_message(state->requester);
			state->requester = NULL;
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		{
			DEBUG_SERVER_MSG("step 4");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover requester : connect is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			state->step = NET_NFC_LLCP_STEP_05;

			memset(conn_handover_req_data.buffer, 0x00, CH_MAX_BUFFER);
			conn_handover_req_data.length = CH_MAX_BUFFER;

			if (net_nfc_controller_llcp_recv(state->handle, state->socket, &conn_handover_req_data, result, state) == false)
			{
				state->step = NET_NFC_STATE_ERROR;
				break;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_05 :
		{
			DEBUG_SERVER_MSG("step 5");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover requester : receiving is failed...");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			DEBUG_SERVER_MSG("handover requster : receiving is successful");
			net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

			if ((*result = _net_nfc_service_handover_create_selector_message_from_rawdata(&state->selector, &conn_handover_req_data)) == NET_NFC_OK)
			{
				net_nfc_conn_handover_carrier_state_e power_state = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;

				/* check selector power state */
				if ((*result = net_nfc_util_get_selector_power_status(state->selector, &power_state)) == NET_NFC_OK)
				{
					DEBUG_MSG("power_state == %d", power_state);

					if (power_state == NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE || power_state == NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING)
					{
						ndef_record_s *carrier_record = NULL;

						if ((*result = _net_nfc_service_llcp_get_carrier_record(state->selector, &carrier_record)) == NET_NFC_OK)
						{
							net_nfc_carrier_config_s *handover_config = NULL;

							if ((*result = net_nfc_util_create_carrier_config_from_config_record(&handover_config, carrier_record)) == NET_NFC_OK)
							{
								net_nfc_service_llcp_handover_process_carrier_config(handover_config, true, state, NET_NFC_LLCP_STEP_06);
							}
							else
							{
								DEBUG_ERR_MSG("net_nfc_util_create_carrier_config_from_config_record failed [%d]", *result);
								state->step = NET_NFC_STATE_ERROR;
							}
						}
						else
						{
							DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_record_count failed [%d]", *result);
							state->step = NET_NFC_STATE_ERROR;
						}
					}
					else
					{
						/* go to step 2 */
						state->step = NET_NFC_LLCP_STEP_02;
						net_nfc_service_llcp_connection_handover_requester(state, result);
					}
				}
				else
				{
					DEBUG_ERR_MSG("net_nfc_util_get_selector_power_status failed [%d]", *result);
					state->step = NET_NFC_STATE_ERROR;
				}
			}
			else
			{
				DEBUG_ERR_MSG("_net_nfc_service_handover_create_selector_message_from_rawdata failed [%d]", *result);
				state->step = NET_NFC_STATE_ERROR;
			}
		}
		break;

	case NET_NFC_LLCP_STEP_06 :
		{
			DEBUG_SERVER_MSG("step 6");

			if (state->prev_result != NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("handover requester : processing failed");
				state->step = NET_NFC_STATE_ERROR;
				break;
			}

			net_nfc_util_free_ndef_message(state->requester);
			net_nfc_util_free_ndef_message(state->selector);

			state->step = 0;
		}
		break;

	case NET_NFC_STATE_SOCKET_ERROR :
		{
			DEBUG_SERVER_MSG("exchange server: socket error is received %d", state->prev_result);
			need_clean_up = true;
		}
		break;

	default :
		{
			DEBUG_SERVER_MSG("unknown step");
			need_clean_up = true;
		}
		break;

	}

	if (state->step == NET_NFC_STATE_ERROR)
	{
		net_nfc_manager_util_play_sound(NET_NFC_TASK_ERROR);
		_net_nfc_service_llcp_handover_send_response(state->client_fd, NET_NFC_OPERATION_FAIL, NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN, NULL);
		net_nfc_util_free_ndef_message(state->requester);
		net_nfc_util_free_ndef_message(state->selector);
		state->step = 0;
	}

	if (need_clean_up == true)
	{
		net_nfc_util_free_ndef_message(state->requester);
		net_nfc_util_free_ndef_message(state->selector);
		net_nfc_controller_llcp_socket_close(state->socket, result);
		net_nfc_service_llcp_remove_state(state);
		_net_nfc_util_free_mem(state);
	}

	if (*result != NET_NFC_BUSY && *result != NET_NFC_OK)
	{
		DEBUG_SERVER_MSG("result is = [%d]", *result);
		return false;
	}

	LOGD("[%s] END", __func__);

	return true;
}

static bool _net_nfc_service_llcp_check_hr_record_validation(ndef_message_s *message)
{
	unsigned int count;
	ndef_record_s *rec;

	LOGD("[%s] START", __func__);

	if (message == NULL)
		return false;

	rec = (ndef_record_s *)message->records;

	if (memcmp(rec->type_s.buffer, CONN_HANDOVER_REQ_RECORD_TYPE, rec->type_s.length) != 0)
	{
		DEBUG_SERVER_MSG("This is not connection handover request message");
		return false;
	}

	if (rec->payload_s.buffer[0] != 0x12)
	{
		DEBUG_SERVER_MSG("connection handover version is not matched");
		return false;
	}

	if (net_nfc_util_get_alternative_carrier_record_count(message, &count) != NET_NFC_OK || count == 0)
	{
		DEBUG_SERVER_MSG("there is no carrrier reference");
		return false;
	}

	LOGD("[%s] END", __func__);

	return true;
}

static bool _net_nfc_service_llcp_check_hs_record_validation(ndef_message_s *message)
{
	unsigned int count;
	ndef_record_s *rec;

	LOGD("[%s] START", __func__);

	if (message == NULL)
		return false;

	rec = (ndef_record_s *)message->records;

	if (memcmp(rec->type_s.buffer, CONN_HANDOVER_SEL_RECORD_TYPE, rec->type_s.length) != 0)
	{
		DEBUG_SERVER_MSG("This is not connection handover request message");
		return false;
	}

	if (net_nfc_util_get_alternative_carrier_record_count(message, &count) != NET_NFC_OK || count == 0)
	{
		DEBUG_SERVER_MSG("there is no carrrier reference");
		return false;
	}

	/*  Contant should be replaced to get api */
	if (rec->payload_s.buffer[0] != 0x12)
	{
		DEBUG_SERVER_MSG("connection handover version is not matched");
		return false;
	}

	LOGD("[%s] END", __func__);

	return true;
}

static bool _net_nfc_service_llcp_handover_check_bond_device(bluetooth_device_address_t *address)
{
	bool result = false;
	int i, ret;
	GPtrArray *devinfo = NULL;
	bluetooth_device_info_t *ptr;

	LOGD("[%s] START", __func__);

	/* allocate the g_pointer_array */
	devinfo = g_ptr_array_new();

	ret = bluetooth_get_bonded_device_list(&devinfo);
	if (ret != BLUETOOTH_ERROR_NONE)
	{
		DEBUG_ERR_MSG("bluetooth_get_bonded_device_list failed with [%d]", ret);
	}
	else
	{
		DEBUG_SERVER_MSG("g pointer arrary count : [%d]", devinfo->len);
		for (i = 0; i < devinfo->len; i++)
		{
			ptr = g_ptr_array_index(devinfo, i);
			if (ptr != NULL)
			{
				DEBUG_SERVER_MSG("Name [%s]", ptr->device_name.name);
				DEBUG_SERVER_MSG("Major Class [%d]", ptr->device_class.major_class);
				DEBUG_SERVER_MSG("Minor Class [%d]", ptr->device_class.minor_class);
				DEBUG_SERVER_MSG("Service Class [%d]", ptr->device_class.service_class);
				DEBUG_SERVER_MSG("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
					ptr->device_address.addr[0],
					ptr->device_address.addr[1], ptr->device_address.addr[2],
					ptr->device_address.addr[3],
					ptr->device_address.addr[4], ptr->device_address.addr[5]);

				/* compare selector address */
				if (memcmp(&(ptr->device_address), address, sizeof(ptr->device_address)) == 0)
				{
					DEBUG_SERVER_MSG("Found!!!");
					result = true;
					break;
				}
			}
		}
	}

	/* free g_pointer_array */
	g_ptr_array_free(devinfo, TRUE);

	LOGD("[%s] END", __func__);

	return result;
}

static void _net_nfc_service_llcp_bt_create_config_cb(int event, bluetooth_event_param_t *param, void *user_data)
{
	net_nfc_handover_create_config_context_t *context = (net_nfc_handover_create_config_context_t *)user_data;

	LOGD("[%s] START", __func__);

	if (context == NULL)
	{
		DEBUG_SERVER_MSG("user_data is null");
		LOGD("[%s] END", __func__);
		return;
	}

	switch (event)
	{
	case BLUETOOTH_EVENT_ENABLED :
		DEBUG_SERVER_MSG("BLUETOOTH_EVENT_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			net_nfc_service_llcp_handover_append_bt_carrier_config(context);
		}
		else
		{
			DEBUG_SERVER_MSG("step is incorrect");
		}
		break;

	case BLUETOOTH_EVENT_DISABLED :
		DEBUG_SERVER_MSG("BLUETOOTH_EVENT_DISABLED");
		break;

	default :
		DEBUG_SERVER_MSG("unhandled bt event [%d], [0x%04x]", event, param->result);
		break;
	}

	LOGD("[%s] END", __func__);
}

int net_nfc_service_llcp_handover_return_to_step(net_nfc_handover_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context != NULL)
	{
		net_nfc_llcp_state_t *state = context->llcp_state;
		net_nfc_error_e error = NET_NFC_OK;
		bool requester = context->is_requester;

		DEBUG_MSG("free context [%p]", context);
		_net_nfc_util_free_mem(context);

		if (requester)
		{
			net_nfc_service_llcp_connection_handover_requester(state, &error);
		}
		else
		{
			net_nfc_service_llcp_connection_handover_selector(state, &error);
		}
	}
	else
	{
		DEBUG_ERR_MSG("null param");
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

int net_nfc_service_llcp_handover_go_to_next_config(net_nfc_handover_create_config_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context->result == NET_NFC_OK || context->result == NET_NFC_BUSY)
	{
		if (context->request_type == NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN)
		{
			if (context->current_type < NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN)
			{
				context->current_type++;
			}
		}
		else
		{
			context->current_type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
		}

		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_iterate_carrier_configs, (gpointer)context);
	}
	else
	{
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);

		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_return_to_step, (gpointer)context);
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

int net_nfc_service_llcp_handover_iterate_carrier_configs(net_nfc_handover_create_config_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	switch (context->current_type)
	{
	case NET_NFC_CONN_HANDOVER_CARRIER_BT :
		DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_BT]");
		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_append_bt_carrier_config, (gpointer)context);
		break;

//	case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS :
//		DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS]");
//		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_append_wifi_carrier_config, context);
//		break;
//
//	case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS :
//		DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS]");
//		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_append_wifi_carrier_config, context);
//		break;
//
	case NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN :
		DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN]");
		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_return_to_step, (gpointer)context);
		break;

	default :
		DEBUG_MSG("[unknown : %d]", context->current_type);
		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_go_to_next_config, (gpointer)context);
		break;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

net_nfc_error_e net_nfc_service_llcp_handover_create_carrier_configs(ndef_message_s *msg, net_nfc_conn_handover_carrier_type_e type, bool requester, net_nfc_llcp_state_t *state, int next_step)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_handover_create_config_context_t *context = NULL;

	LOGD("[%s:%d] START", __func__, __LINE__);

	_net_nfc_util_alloc_mem(context, sizeof(net_nfc_handover_create_config_context_t));
	if (context != NULL)
	{
		state->step = next_step;

		context->request_type = type;
		context->current_type = context->request_type;
		if (context->request_type == NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN)
			context->current_type = NET_NFC_CONN_HANDOVER_CARRIER_BT;
		context->is_requester = requester;
		context->llcp_state = state;
		context->step = NET_NFC_LLCP_STEP_01;
		context->ndef_message = msg;

		/* append carrier record */
		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_iterate_carrier_configs, (gpointer)context);
	}
	else
	{
		DEBUG_ERR_MSG("alloc failed");
		result = NET_NFC_ALLOC_FAIL;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return result;
}

int net_nfc_service_llcp_handover_append_bt_carrier_config(net_nfc_handover_create_config_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);

		context->step = NET_NFC_LLCP_STEP_RETURN;
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_MSG("STEP [1]");

		if (bluetooth_register_callback(_net_nfc_service_llcp_bt_create_config_cb, context) >= BLUETOOTH_ERROR_NONE)
		{
			context->step = NET_NFC_LLCP_STEP_02;
			context->result = NET_NFC_OK;

			if (bluetooth_check_adapter() != BLUETOOTH_ADAPTER_ENABLED)
			{
				bluetooth_enable_adapter();
			}
			else
			{
				DEBUG_MSG("bluetooth is enabled already");

				/* do next step */
				g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_append_bt_carrier_config, (gpointer)context);
			}
		}
		else
		{
			DEBUG_ERR_MSG("bluetooth_register_callback failed");

			context->step = NET_NFC_LLCP_STEP_RETURN;
			context->result = NET_NFC_OPERATION_FAIL;
			g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_append_bt_carrier_config, (gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
			net_nfc_carrier_config_s *config = NULL;
			ndef_record_s *record = NULL;
			bluetooth_device_address_t bt_addr = { { 0, } };

			DEBUG_MSG("STEP [2]");

			context->step = NET_NFC_LLCP_STEP_RETURN;

			/* append config to ndef message */
			if ((result = bluetooth_get_local_address(&bt_addr)) == BLUETOOTH_ERROR_NONE)
			{
				if ((result = net_nfc_util_create_carrier_config(&config, NET_NFC_CONN_HANDOVER_CARRIER_BT)) == NET_NFC_OK)
				{
					bt_oob_data_t oob = { { 0 }, };

					if ((result = net_nfc_util_add_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_ADDRESS, sizeof(bt_addr.addr), bt_addr.addr)) != NET_NFC_OK)
					{
						DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
					}

					/* get oob data */
					bluetooth_oob_read_local_data(&oob);

					if (oob.hash_len == 16)
					{
						DEBUG_SERVER_MSG("oob.hash_len [%d]", oob.hash_len);

						if ((result = net_nfc_util_add_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_C, oob.hash_len, oob.hash)) != NET_NFC_OK)
						{
							DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
						}
					}

					if (oob.randomizer_len == 16)
					{
						DEBUG_SERVER_MSG("oob.randomizer_len [%d]", oob.randomizer_len);

						if ((result = net_nfc_util_add_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_R, oob.randomizer_len, oob.randomizer)) != NET_NFC_OK)
						{
							DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
						}
					}

					net_nfc_service_llcp_handover_bt_change_data_order(config);

					if ((result = net_nfc_util_create_ndef_record_with_carrier_config(&record, config)) == NET_NFC_OK)
					{
						if ((result = net_nfc_util_append_carrier_config_record(context->ndef_message, record, 0)) == NET_NFC_OK)
						{
							DEBUG_SERVER_MSG("net_nfc_util_append_carrier_config_record success");

							context->result = result;
						}
						else
						{
							DEBUG_ERR_MSG("net_nfc_util_append_carrier_config_record failed [%d]", result);

							net_nfc_util_free_record(record);
							context->result = result;
						}
					}
					else
					{
						DEBUG_ERR_MSG("net_nfc_util_create_ndef_record_with_carrier_config failed [%d]", result);
						context->result = NET_NFC_OPERATION_FAIL;
					}

					net_nfc_util_free_carrier_config(config);
				}
				else
				{
					DEBUG_ERR_MSG("net_nfc_util_create_carrier_config failed [%d]", result);
					context->result = NET_NFC_OPERATION_FAIL;
				}
			}
			else
			{
				DEBUG_ERR_MSG("bluetooth_get_local_address failed [%d]", result);
				context->result = NET_NFC_OPERATION_FAIL;
			}

			/* complete and return to upper step */
			g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_append_bt_carrier_config, (gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		DEBUG_MSG("STEP return");

		/* unregister current callback */
		bluetooth_unregister_callback();

		/* complete and return to upper step */
		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_go_to_next_config, (gpointer)context);
		break;

	default :
		break;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

int net_nfc_service_llcp_handover_append_wifi_carrier_config(net_nfc_handover_create_config_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_MSG("STEP [1]");

		context->step = NET_NFC_LLCP_STEP_02;
		break;

	case NET_NFC_LLCP_STEP_02 :
		DEBUG_MSG("STEP [2]");

		context->step = NET_NFC_LLCP_STEP_03;
		break;

	case NET_NFC_LLCP_STEP_03 :
		DEBUG_MSG("STEP [3]");

		context->step = NET_NFC_LLCP_STEP_RETURN;
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		DEBUG_MSG("STEP return");

		/* complete and return to upper step */
		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_go_to_next_config, (gpointer)context);
		break;

	default :
		break;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

net_nfc_error_e _net_nfc_service_llcp_create_low_power_selector_message(ndef_message_s *request_msg, ndef_message_s *select_msg)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	unsigned int carrier_count = 0;

	LOGD("[%s] START", __func__);

	if (request_msg == NULL || select_msg == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((result = net_nfc_util_get_alternative_carrier_record_count(request_msg, &carrier_count)) == NET_NFC_OK)
	{
		int idx;
		ndef_record_s *carrier_record = NULL;
		net_nfc_conn_handover_carrier_type_e carrier_type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;

		/* check each carrier record and create matched record */
		for (idx = 0; idx < carrier_count; idx++)
		{
			if ((net_nfc_util_get_alternative_carrier_type(request_msg, idx, &carrier_type) != NET_NFC_OK) ||
				(carrier_type == NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN))
			{
				DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_type failed or unknown");
				continue;
			}

			DEBUG_SERVER_MSG("carrier type = [%d]", carrier_type);

			/* add temporary config record */
			{
				net_nfc_carrier_config_s *config = NULL;

				if ((result = net_nfc_util_create_carrier_config(&config, carrier_type)) == NET_NFC_OK)
				{
					if ((result = net_nfc_util_create_ndef_record_with_carrier_config(&carrier_record, config)) == NET_NFC_OK)
					{
						DEBUG_SERVER_MSG("_net_nfc_service_llcp_create_bt_configuration success");
					}
					else
					{
						DEBUG_ERR_MSG("net_nfc_util_create_ndef_record_with_carrier_config failed [%d]", result);
						net_nfc_util_free_carrier_config(config);
						continue;
					}

					net_nfc_util_free_carrier_config(config);
				}
				else
				{
					DEBUG_ERR_MSG("net_nfc_util_get_local_bt_address return NULL");
					continue;
				}
			}

			/* append carrier configure record to selector message */
			if ((result = net_nfc_util_append_carrier_config_record(select_msg, carrier_record, NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE)) == NET_NFC_OK)
			{
				DEBUG_SERVER_MSG("net_nfc_util_append_carrier_config_record success!!");
			}
			else
			{
				DEBUG_ERR_MSG("net_nfc_util_append_carrier_config_record failed [%d]", result);

				net_nfc_util_free_record(carrier_record);
			}
		}

		result = NET_NFC_OK;
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_util_get_alternative_carrier_record_count failed");
	}

	LOGD("[%s] END", __func__);

	return result;
}

static void _net_nfc_service_llcp_process_bt_config_cb(int event, bluetooth_event_param_t *param, void *user_data)
{
	net_nfc_handover_process_config_context_t *context = (net_nfc_handover_process_config_context_t *)user_data;

	LOGD("[%s] START", __func__);

	if (context == NULL)
	{
		DEBUG_SERVER_MSG("user_data is null");
		LOGD("[%s] END", __func__);
		return;
	}

	switch (event)
	{
	case BLUETOOTH_EVENT_ENABLED :
		DEBUG_SERVER_MSG("BLUETOOTH_EVENT_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			net_nfc_service_llcp_handover_process_bt_config(context);
		}
		else
		{
			DEBUG_SERVER_MSG("step is incorrect");
		}
		break;

	case BLUETOOTH_EVENT_DISABLED :
		DEBUG_SERVER_MSG("BLUETOOTH_EVENT_DISABLED");
		break;

	case BLUETOOTH_EVENT_BONDING_FINISHED :
		DEBUG_SERVER_MSG("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
		if (context->step == NET_NFC_LLCP_STEP_03)
		{
			if (param->result < BLUETOOTH_ERROR_NONE)
			{
				DEBUG_ERR_MSG("bond failed");
				context->result = NET_NFC_OPERATION_FAIL;
			}

			net_nfc_service_llcp_handover_process_bt_config(context);
		}
		else
		{
			DEBUG_SERVER_MSG("step is incorrect");
		}
		break;

	default :
		DEBUG_SERVER_MSG("unhandled bt event [%d], [0x%04x]", event, param->result);
		break;
	}

	LOGD("[%s] END", __func__);
}

net_nfc_error_e net_nfc_service_llcp_handover_process_carrier_config(net_nfc_carrier_config_s *config, bool requester, net_nfc_llcp_state_t *state, int next_step)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_handover_process_config_context_t *context = NULL;

	LOGD("[%s:%d] START", __func__, __LINE__);

	_net_nfc_util_alloc_mem(context, sizeof(net_nfc_handover_process_config_context_t));
	if (context != NULL)
	{
		state->step = next_step;

		context->request_type = config->type;
		context->is_requester = requester;
		context->llcp_state = state;
		context->step = NET_NFC_LLCP_STEP_01;
		context->config = config;

		/* append carrier record */
		switch (config->type)
		{
		case NET_NFC_CONN_HANDOVER_CARRIER_BT :
			DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_BT]");
			net_nfc_service_llcp_handover_bt_change_data_order(context->config);
			g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS :
			DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS]");
			_net_nfc_util_free_mem(context);
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN :
			DEBUG_MSG("[NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN]");
			_net_nfc_util_free_mem(context);
			break;

		default :
			DEBUG_MSG("[unknown]");
			_net_nfc_util_free_mem(context);
			break;
		}
	}
	else
	{
		DEBUG_ERR_MSG("alloc failed");
		result = NET_NFC_ALLOC_FAIL;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return result;
}

int net_nfc_service_llcp_handover_process_bt_config(net_nfc_handover_process_config_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);
		context->step = NET_NFC_LLCP_STEP_RETURN;
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_MSG("STEP [1]");

		if (bluetooth_register_callback(_net_nfc_service_llcp_process_bt_config_cb, context) >= BLUETOOTH_ERROR_NONE)
		{
			/* next step */
			context->step = NET_NFC_LLCP_STEP_02;

			if (bluetooth_check_adapter() != BLUETOOTH_ADAPTER_ENABLED)
			{
				context->result = NET_NFC_OK;
				bluetooth_enable_adapter();
			}
			else
			{
				/* do next step */
				DEBUG_MSG("BT is enabled already, go next step");

				context->result = NET_NFC_OK;
				g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
			}
		}
		else
		{
			DEBUG_ERR_MSG("bluetooth_register_callback failed");
			context->result = NET_NFC_OPERATION_FAIL;
			g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			bluetooth_device_address_t address = { { 0, } };
			data_s temp = { NULL, 0 };

			DEBUG_MSG("STEP [2]");

			net_nfc_util_get_carrier_config_property(context->config, NET_NFC_BT_ATTRIBUTE_ADDRESS, (uint16_t *)&temp.length, &temp.buffer);
			if (temp.length == 6)
			{
				memcpy(address.addr, temp.buffer, MIN(sizeof(address.addr), temp.length));

				if (_net_nfc_service_llcp_handover_check_bond_device(&address) == true)
				{
					DEBUG_SERVER_MSG("already paired with [%02x:%02x:%02x:%02x:%02x:%02x]", address.addr[0], address.addr[1], address.addr[2], address.addr[3], address.addr[4], address.addr[5]);

					if (context->is_requester)
					{
						/* next step */
						context->step = NET_NFC_LLCP_STEP_03;
					}
					else
					{
						/* return */
						context->step = NET_NFC_LLCP_STEP_RETURN;
					}

					context->result = NET_NFC_OK;
					g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
				}
				else
				{
					bt_oob_data_t oob = { { 0 } , };

					if (net_nfc_service_llcp_handover_get_oob_data(context->config, &oob) == NET_NFC_OK)
					{
						/* set oob data */
						bluetooth_oob_add_remote_data(&address, &oob);
					}

					context->result = NET_NFC_OK;

					if (context->is_requester)
					{
						/* pair and send reponse */
						context->step = NET_NFC_LLCP_STEP_03;

						bluetooth_bond_device(&address);
					}
					else
					{
						/* return */
						context->step = NET_NFC_LLCP_STEP_RETURN;
						g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
					}
				}
			}
			else
			{
				DEBUG_ERR_MSG("bluetooth address is invalid. [%d] bytes", temp.length);

				context->step = NET_NFC_LLCP_STEP_RETURN;
				context->result = NET_NFC_OPERATION_FAIL;
				g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
			}
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		{
			data_s data = {NULL, 0};

			DEBUG_MSG("STEP [3]");

			context->step++;

			net_nfc_util_get_carrier_config_property(context->config, NET_NFC_BT_ATTRIBUTE_ADDRESS, (uint16_t *)&data.length, &data.buffer);
			if (data.length == 6)
			{
				/* send handover success message to client */
				_net_nfc_service_llcp_handover_send_response(context->llcp_state->client_fd, NET_NFC_OK, NET_NFC_CONN_HANDOVER_CARRIER_BT, &data);

				context->step = NET_NFC_LLCP_STEP_RETURN;
				context->result = NET_NFC_OK;
			}
			else
			{
				DEBUG_ERR_MSG("bluetooth address is invalid. [%d] bytes", data.length);

				context->step = NET_NFC_LLCP_STEP_RETURN;
				context->result = NET_NFC_OPERATION_FAIL;
			}

			g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_process_bt_config, (gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		DEBUG_MSG("STEP return");

		/* unregister bluetooth callback */
		bluetooth_unregister_callback();

		g_idle_add((GSourceFunc)net_nfc_service_llcp_handover_return_to_step, (gpointer)context);
		break;

	default :
		break;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

net_nfc_error_e net_nfc_service_llcp_handover_get_oob_data(net_nfc_carrier_config_s *config, bt_oob_data_t *oob)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	data_s hash = { NULL, 0 };
	data_s randomizer = { NULL, 0 };

	LOGD("[%s:%d] START", __func__, __LINE__);

	if (config == NULL || oob == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	memset(oob, 0, sizeof(bt_oob_data_t));

	if ((result = net_nfc_util_get_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_C, (uint16_t *)&hash.length, &hash.buffer)) == NET_NFC_OK)
	{
		if ((result = net_nfc_util_get_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_R, (uint16_t *)&randomizer.length, &randomizer.buffer)) == NET_NFC_OK)
		{
			if (hash.length == 16)
			{
				DEBUG_MSG("hash.length == 16");

				oob->hash_len = MIN(sizeof(oob->hash), hash.length);
				memcpy(oob->hash, hash.buffer, oob->hash_len);
			}
			else
			{
				DEBUG_ERR_MSG("hash.length error : [%d] bytes", hash.length);
			}

			if (randomizer.length == 16)
			{
				DEBUG_MSG("randomizer.length == 16");

				oob->randomizer_len = MIN(sizeof(oob->randomizer), randomizer.length);
				memcpy(oob->randomizer, randomizer.buffer, oob->randomizer_len);
			}
			else
			{
				DEBUG_ERR_MSG("randomizer.length error : [%d] bytes", randomizer.length);
			}
		}
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return result;
}

net_nfc_error_e net_nfc_service_llcp_handover_bt_change_data_order(net_nfc_carrier_config_s *config)
{
	uint8_t *buffer = NULL;
	uint16_t len = 0;
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;

	LOGD("[%s:%d] START", __func__, __LINE__);

	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((result = net_nfc_util_get_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_ADDRESS, &len, &buffer)) == NET_NFC_OK)
	{
		if (len == 6)
		{
			NET_NFC_REVERSE_ORDER_6_BYTES(buffer);
		}
		else
		{
			DEBUG_ERR_MSG("NET_NFC_BT_ATTRIBUTE_ADDRESS len error : [%d] bytes", len);
		}
	}

	if ((result = net_nfc_util_get_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_C, &len, &buffer)) == NET_NFC_OK)
	{
		if (len == 16)
		{
			NET_NFC_REVERSE_ORDER_16_BYTES(buffer);
		}
		else
		{
			DEBUG_ERR_MSG("NET_NFC_BT_ATTRIBUTE_OOB_HASH_C len error : [%d] bytes", len);
		}
	}

	if ((result = net_nfc_util_get_carrier_config_property(config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_R, &len, &buffer)) == NET_NFC_OK)
	{
		if (len == 16)
		{
			NET_NFC_REVERSE_ORDER_16_BYTES(buffer);
		}
		else
		{
			DEBUG_ERR_MSG("NET_NFC_BT_ATTRIBUTE_OOB_HASH_R error : [%d] bytes", len);
		}
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return result;
}
