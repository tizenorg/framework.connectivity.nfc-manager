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

#include "net_nfc_typedef.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_service_test_private.h"
#include "net_nfc_server_context_private.h"

void net_nfc_service_test_sim_test(net_nfc_request_msg_t *msg)
{
	net_nfc_request_test_t *detail = (net_nfc_request_test_t *)msg;
	net_nfc_error_e result = NET_NFC_OK;

	if (net_nfc_controller_sim_test(&result) == true)
	{
		DEBUG_SERVER_MSG("net_nfc_controller_sim_test Result [SUCCESS]");
	}
	else
	{
		DEBUG_SERVER_MSG("net_nfc_controller_sim_test Result [ERROR1]");
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_test_t resp = { 0, };

		resp.length = sizeof(net_nfc_response_test_t);
		resp.flags = detail->flags;
		resp.result = result;
		resp.trans_param = detail->trans_param;

		DEBUG_SERVER_MSG("SEND RESPONSE!!");
		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_test_t), NULL);
	}
}

void net_nfc_service_test_get_firmware_version(net_nfc_request_msg_t *msg)
{
	net_nfc_error_e result = NET_NFC_OK;
	data_s *data = NULL;

	if (net_nfc_controller_get_firmware_version(&data, &result) == true)
	{
		DEBUG_SERVER_MSG("net_nfc_controller_update_firmware Result [SUCCESS]");

	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_controller_update_firmware Result [ERROR3]");
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_firmware_version_t resp = { 0, };

		resp.length = sizeof(net_nfc_response_firmware_version_t);
		resp.flags = msg->flags;
		resp.result = result;

		if (data != NULL)
		{
			resp.data.length = data->length;

			net_nfc_send_response_msg(msg->client_fd, msg->request_type,
				(void *)&resp, sizeof(net_nfc_response_firmware_version_t),
				(void *)data->buffer, resp.data.length, NULL);
		}
		else
		{
			net_nfc_send_response_msg(msg->client_fd, msg->request_type,
				(void *)&resp, sizeof(net_nfc_response_firmware_version_t), NULL);
		}
	}

	if (data != NULL)
	{
		net_nfc_util_free_data(data);
		_net_nfc_util_free_mem(data);
	}
}

void net_nfc_service_test_prbs_test(net_nfc_request_msg_t *msg)
{
	net_nfc_request_test_t *detail = (net_nfc_request_test_t *)msg;
	net_nfc_error_e result = NET_NFC_OK;
	uint32_t local_tech = 0;
	uint32_t local_rate = 0;

	local_tech = detail->tech;
	local_rate = detail->rate;

	DEBUG_SERVER_MSG("local_tech [%d]\n", local_tech);
	DEBUG_SERVER_MSG("local_rate [%d]\n", local_rate);

	if (net_nfc_controller_prbs_test(&result, local_tech, local_rate) == true)
	{
		DEBUG_SERVER_MSG("net_nfc_controller_prbs_test Result [SUCCESS]");
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_controller_prbs_test Result [ERROR3]");
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_test_t resp = { 0, };

		resp.length = sizeof(net_nfc_response_test_t);
		resp.flags = detail->flags;
		resp.result = result;
		resp.trans_param = detail->trans_param;

		DEBUG_SERVER_MSG("SEND RESPONSE!!");
		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_test_t), NULL);
	}
}

void net_nfc_service_test_set_eedata(net_nfc_request_msg_t *msg)
{
	net_nfc_request_eedata_register_t *detail = (net_nfc_request_eedata_register_t *)msg;
	net_nfc_error_e result = NET_NFC_OK;
	uint32_t local_mode = 0;
	uint32_t local_reg_id = 0;
	data_s data = { NULL, 0 };

	local_mode = detail->mode;
	local_reg_id = detail->reg_id;

	DEBUG_SERVER_MSG("local_mode [%d]\n", local_mode);
	DEBUG_SERVER_MSG("local_reg_id [%d]\n", local_reg_id);

	if (net_nfc_util_duplicate_data(&data, &detail->data) == true)
	{
		if (net_nfc_controller_eedata_register_set(&result, local_mode,
			local_reg_id, &data) == true)
		{
			DEBUG_SERVER_MSG("net_nfc_controller_eedata_register_set Result [SUCCESS]");
		}
		else
		{
			DEBUG_ERR_MSG("net_nfc_controller_eedata_register_set Result [ERROR3]");
		}
		net_nfc_util_free_data(&data);

		if (net_nfc_server_check_client_is_running(msg->client_fd))
		{
			net_nfc_response_test_t resp = { 0, };

			resp.length = sizeof(net_nfc_response_test_t);
			resp.flags = detail->flags;
			resp.result = result;
			resp.trans_param = detail->trans_param;

			DEBUG_SERVER_MSG("SEND RESPONSE!!");
			net_nfc_send_response_msg(msg->client_fd, msg->request_type,
				(void *)&resp, sizeof(net_nfc_response_test_t), NULL);
		}
	}
}
