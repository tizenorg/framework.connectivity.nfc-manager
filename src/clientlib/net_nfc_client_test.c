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


#include "net_nfc.h"
#include "net_nfc_typedef.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_client_ipc_private.h"


#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API void net_nfc_test_read_test_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	DEBUG_CLIENT_MSG("user_param = [%p] trans_param = [%p] , message[%d]", user_param, trans_data, message);

	switch (message)
	{
	case NET_NFC_MESSAGE_TAG_DISCOVERED :
		{
			if (result == NET_NFC_OK)
			{
				DEBUG_CLIENT_MSG("net_nfc_test_read_cb SUCCESS!!!!! [%d ]", result);
			}
			else
			{
				DEBUG_CLIENT_MSG("net_nfc_test_read_cb FAIL!!!!![%d]", result);
			}
		}
		break;

	default :
		break;
	}
}

NET_NFC_EXPORT_API void net_nfc_test_sim_test_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	DEBUG_CLIENT_MSG("user_param = [%p] trans_param = [%p] data = [%p]", user_param, trans_data, data);

	switch (message)
	{
	case NET_NFC_MESSAGE_SIM_TEST :
		{
			if (result == NET_NFC_OK)
			{
				DEBUG_CLIENT_MSG("net_nfc_test_sim_test_cb SUCCESS!!!!! [%d]", result);
			}
			else
			{
				DEBUG_CLIENT_MSG("net_nfc_test_sim_test_cb FAIL!!!!![%d]", result);
			}
		}
		break;

	default :
		break;
	}
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_sim_test(void)
{
	net_nfc_error_e ret;
	net_nfc_request_test_t request = { 0, };

	request.length = sizeof(net_nfc_request_test_t);
	request.request_type = NET_NFC_MESSAGE_SIM_TEST;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_prbs_test(int tech, int rate)
{
	net_nfc_error_e ret;
	net_nfc_request_test_t request = { 0, };

	request.length = sizeof(net_nfc_request_test_t);
	request.request_type = NET_NFC_MESSAGE_PRBS_TEST;/*TEST MODE*/
	request.rate = rate;
	request.tech = tech;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_firmware_version(void)
{
	net_nfc_error_e ret;
	net_nfc_request_msg_t request = { 0, };

	request.length = sizeof(net_nfc_request_msg_t);
	request.request_type = NET_NFC_MESSAGE_GET_FIRMWARE_VERSION;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_eedata_register(int mode, int reg_id, uint8_t *data, uint32_t len)
{
	net_nfc_request_eedata_register_t *request = NULL;
	net_nfc_error_e result;
	uint32_t length = 0;

	DEBUG_CLIENT_MSG("net_nfc_set_eedata_register");

	length = sizeof(net_nfc_request_eedata_register_t) + len;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	/* fill request message */
	request->length = length;
	request->request_type = NET_NFC_MESSAGE_SET_EEDATA;
	request->mode = mode;
	request->reg_id = reg_id;
	request->data.length = len;
	memcpy(request->data.buffer, data, len);

	result = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return result;
}

