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

#include <string.h>
#include <pthread.h>

#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_client_ipc_private.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_set_card_emulation_mode_sync(
    net_nfc_card_emulation_mode_t se_mode)
{
   net_nfc_error_e ret = NET_NFC_OK;
	net_nfc_request_se_change_card_emulation_t request = { 0, };

	if (se_mode < NET_NFC_SE_TYPE_NONE || se_mode > NET_NFC_SE_TYPE_UICC)
	{
		return NET_NFC_INVALID_PARAM;
	}

	request.length = sizeof(net_nfc_request_se_change_card_emulation_t);
	request.request_type = NET_NFC_MESSAGE_CARD_EMULATION_CHANGE_SE;
	request.se_mode = se_mode;

	ret = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);

	if (ret != NET_NFC_OK)
		DEBUG_ERR_MSG("net_nfc_set_card_emulation_mode_sync failed [%d]", ret);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_secure_element_type_sync(
	net_nfc_se_type_e se_type)
{
	net_nfc_error_e ret = NET_NFC_OK;
	net_nfc_request_set_se_t request = { 0, };

	if (se_type < NET_NFC_SE_TYPE_NONE || se_type > NET_NFC_SE_TYPE_UICC)
	{
		return NET_NFC_INVALID_PARAM;
	}

	request.length = sizeof(net_nfc_request_set_se_t);
	request.request_type = NET_NFC_MESSAGE_SET_SE;
	request.se_type = se_type;

	ret = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);
	if (ret != NET_NFC_OK)
		DEBUG_ERR_MSG("net_nfc_set_secure_element_type_sync failed [%d]", ret);

	return ret;
}


NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_secure_element_type(net_nfc_se_type_e se_type, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_set_se_t request = { 0, };

	if (se_type < NET_NFC_SE_TYPE_NONE || se_type > NET_NFC_SE_TYPE_UICC)
	{
		return NET_NFC_INVALID_PARAM;
	}

	request.length = sizeof(net_nfc_request_set_se_t);
	request.request_type = NET_NFC_MESSAGE_SET_SE;
	request.se_type = se_type;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_secure_element_type(void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_get_se_t request = { 0, };

	request.length = sizeof(net_nfc_request_get_se_t);
	request.request_type = NET_NFC_MESSAGE_GET_SE;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_open_internal_secure_element(net_nfc_se_type_e se_type, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_open_internal_se_t request = { 0, };

	if (se_type < NET_NFC_SE_TYPE_NONE || se_type > NET_NFC_SE_TYPE_UICC)
	{
		return NET_NFC_INVALID_PARAM;
	}

	request.length = sizeof(net_nfc_request_open_internal_se_t);
	request.request_type = NET_NFC_MESSAGE_OPEN_INTERNAL_SE;
	request.se_type = se_type;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_open_internal_secure_element_sync(net_nfc_se_type_e se_type, net_nfc_target_handle_h *handle)
{
	net_nfc_request_open_internal_se_t request = { 0, };
	net_nfc_target_handle_h temp = NULL;
	net_nfc_error_e result;

	if (se_type < NET_NFC_SE_TYPE_NONE || se_type > NET_NFC_SE_TYPE_UICC) {
		return NET_NFC_INVALID_PARAM;
	}

	request.length = sizeof(net_nfc_request_open_internal_se_t);
	request.request_type = NET_NFC_MESSAGE_OPEN_INTERNAL_SE;
	request.se_type = se_type;
	request.user_param = (uint32_t)&temp;

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);
	if (result == NET_NFC_OK) {
		if (temp != NULL) {
			*handle = temp;
		} else {
			DEBUG_ERR_MSG("NULL handle returned data returned");
			result = NET_NFC_OPERATION_FAIL;
		}
	} else{
		DEBUG_ERR_MSG("net_nfc_client_send_request_sync failed [%d]", result);
	}

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_close_internal_secure_element(net_nfc_target_handle_h handle, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_close_internal_se_t request = { 0, };

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	request.length = sizeof(net_nfc_request_close_internal_se_t);
	request.request_type = NET_NFC_MESSAGE_CLOSE_INTERNAL_SE;
	request.handle = (net_nfc_target_handle_s *)handle;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_close_internal_secure_element_sync(net_nfc_target_handle_h handle)
{
	net_nfc_error_e result;
	net_nfc_request_close_internal_se_t request = { 0, };

	if (handle == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	request.length = sizeof(net_nfc_request_close_internal_se_t);
	request.request_type = NET_NFC_MESSAGE_CLOSE_INTERNAL_SE;
	request.handle = (net_nfc_target_handle_s *)handle;

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_send_apdu(net_nfc_target_handle_h handle, data_h apdu, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_send_apdu_t *request = NULL;
	uint32_t length = 0;
	data_s *apdu_data = (data_s *)apdu;

	if (handle == NULL || apdu_data == NULL || apdu_data->buffer == NULL || apdu_data->length == 0)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	length = sizeof(net_nfc_request_send_apdu_t) + apdu_data->length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_SEND_APDU_SE;
	request->handle = (net_nfc_target_handle_s *)handle;
	request->trans_param = trans_param;

	request->data.length = apdu_data->length;
	memcpy(&request->data.buffer, apdu_data->buffer, request->data.length);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_send_apdu_sync(net_nfc_target_handle_h handle, data_h apdu, data_h *response)
{
	net_nfc_request_send_apdu_t *request = NULL;
	data_s *apdu_data = (data_s *)apdu;
	net_nfc_error_e result;
	uint32_t length;
	data_h resp = NULL;

	if (handle == NULL || apdu_data == NULL || apdu_data->buffer == NULL || apdu_data->length == 0)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	length = sizeof(net_nfc_request_send_apdu_t) + apdu_data->length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_SEND_APDU_SE;
	request->handle = (net_nfc_target_handle_s *)handle;
	request->user_param = (uint32_t)&resp;

	request->data.length = apdu_data->length;
	memcpy(&request->data.buffer, apdu_data->buffer, request->data.length);

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)request, NULL);
	if (result == NET_NFC_OK) {
		if (resp != NULL) {
			*response = resp;
		} else {
			DEBUG_ERR_MSG("NULL response returned");
			result = NET_NFC_OPERATION_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("net_nfc_client_send_request_sync failed [%d]", result);
	}

	_net_nfc_util_free_mem(request);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_atr(net_nfc_target_handle_h handle, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_get_atr_t request = { 0, };

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	request.length = sizeof(net_nfc_request_get_atr_t);
	request.request_type = NET_NFC_MESSAGE_GET_ATR_SE;
	request.handle = (net_nfc_target_handle_s *)handle;
	request.user_param = (uint32_t)trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_atr_sync(net_nfc_target_handle_h handle, data_h *atr)
{
	net_nfc_request_get_atr_t request = { 0, };
	data_h response = NULL;
	net_nfc_error_e result;

	if (handle == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	request.length = sizeof(net_nfc_request_get_atr_t);
	request.request_type = NET_NFC_MESSAGE_GET_ATR_SE;
	request.handle = (net_nfc_target_handle_s *)handle;
	request.user_param = (uint32_t)&response;

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);
	if (result == NET_NFC_OK) {
		if (response != NULL) {
			*atr = response;
		} else {
			result = NET_NFC_OPERATION_FAIL;
		}
	}

	return result;
}
