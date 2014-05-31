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

#include <string.h>
#include <pthread.h>

#include "net_nfc_tag.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_client_ipc_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_client_nfc_private.h"
#include "net_nfc_target_info.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_format_ndef(net_nfc_target_handle_h handle, data_h key, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_format_ndef_t *request = NULL;
	uint32_t length = 0;
	data_s *struct_key = (data_s *)key;

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	length = sizeof(net_nfc_request_format_ndef_t);
	if (struct_key != NULL)
	{
		length += struct_key->length;
	}

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_FORMAT_NDEF;
	request->handle = (net_nfc_target_handle_s *)handle;
	request->trans_param = trans_param;

	if (struct_key != NULL && struct_key->length > 0)
	{
		request->key.length = struct_key->length;
		memcpy(&request->key.buffer, struct_key->buffer, request->key.length);
	}

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_tag_filter(net_nfc_event_filter_e config)
{
	client_context_t *client_context = net_nfc_get_client_context();

	pthread_mutex_lock(&(client_context->g_client_lock));
	client_context->filter = config;
	pthread_mutex_unlock(&(client_context->g_client_lock));

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_event_filter_e net_nfc_get_tag_filter()
{

	client_context_t *client_context = net_nfc_get_client_context();

	pthread_mutex_lock(&(client_context->g_client_lock));
	net_nfc_event_filter_e filter = client_context->filter;
	pthread_mutex_unlock(&(client_context->g_client_lock));

	return filter;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_transceive(net_nfc_target_handle_h handle, data_h rawdata, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_transceive_t *request = NULL;
	client_context_t *client_context_tmp = NULL;
	net_nfc_target_info_s *target_info = NULL;
	uint32_t length = 0;
	data_s *data = (data_s *)rawdata;
	uint8_t *send_buffer;

	DEBUG_CLIENT_MSG("send reqeust :: transceive = [%p]", handle);

	if (handle == NULL || rawdata == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (!net_nfc_tag_is_connected())
	{
		return NET_NFC_OPERATION_FAIL;
	}

	client_context_tmp = net_nfc_get_client_context();
	if (client_context_tmp == NULL || client_context_tmp->target_info == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}
	/* fill trans information struct */
	target_info = client_context_tmp->target_info;

	switch (target_info->devType)
	{
	case NET_NFC_MIFARE_MINI_PICC :
	case NET_NFC_MIFARE_1K_PICC :
	case NET_NFC_MIFARE_4K_PICC :
	case NET_NFC_MIFARE_ULTRA_PICC :
		{
			length = sizeof(net_nfc_request_transceive_t) + data->length + 2;

			_net_nfc_util_alloc_mem(request, length);
			if (request == NULL)
			{
				return NET_NFC_ALLOC_FAIL;
			}

			_net_nfc_util_alloc_mem(send_buffer, data->length + 2);
			if (send_buffer == NULL)
			{
				_net_nfc_util_free_mem(request);
				return NET_NFC_ALLOC_FAIL;
			}

			memcpy(send_buffer, data->buffer, data->length);
			net_nfc_util_compute_CRC(CRC_A, send_buffer, data->length + 2);

			memcpy(&request->info.trans_data.buffer, send_buffer, data->length + 2);

			request->info.trans_data.length = data->length + 2;

			_net_nfc_util_free_mem(send_buffer);
		}
		break;

	case NET_NFC_JEWEL_PICC :
		{
			if (data->length > 9)
			{
				return NET_NFC_INVALID_PARAM;
			}

			length = sizeof(net_nfc_request_transceive_t) + 9;

			_net_nfc_util_alloc_mem(request, length);
			if (request == NULL)
			{
				return NET_NFC_ALLOC_FAIL;
			}

			_net_nfc_util_alloc_mem(send_buffer, 9);
			if (send_buffer == NULL)
			{
				_net_nfc_util_free_mem(request);
				return NET_NFC_ALLOC_FAIL;
			}

			memcpy(send_buffer, data->buffer, data->length);
			net_nfc_util_compute_CRC(CRC_B, send_buffer, 9);

			memcpy(&request->info.trans_data.buffer, send_buffer, 9);

			request->info.trans_data.length = 9;

			_net_nfc_util_free_mem(send_buffer);
		}
		break;

	default :
		{
			length = sizeof(net_nfc_request_transceive_t) + data->length;

			_net_nfc_util_alloc_mem(request, length);
			if (request == NULL)
			{
				return NET_NFC_ALLOC_FAIL;
			}

			memcpy(&request->info.trans_data.buffer, data->buffer, data->length);

			request->info.trans_data.length = data->length;
		}
		break;
	}

	/* fill request message */
	request->length = length;
	request->request_type = NET_NFC_MESSAGE_TRANSCEIVE;
	request->handle = (net_nfc_target_handle_s *)handle;
	request->trans_param = trans_param;
	request->info.dev_type = (uint32_t)target_info->devType;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_read_tag(net_nfc_target_handle_h handle, void *trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_read_ndef_t request = { 0, };

	DEBUG_CLIENT_MSG("send reqeust :: read ndef = [%p]", handle);

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (!net_nfc_tag_is_connected())
	{
		return NET_NFC_OPERATION_FAIL;
	}

	request.length = sizeof(net_nfc_request_read_ndef_t);
	request.request_type = NET_NFC_MESSAGE_READ_NDEF;
	request.handle = (net_nfc_target_handle_s *)handle;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_write_ndef(net_nfc_target_handle_h handle, ndef_message_h msg, void *trans_param)
{
	net_nfc_request_write_ndef_t *request = NULL;
	net_nfc_error_e result;
	data_s data;
	uint32_t length = 0, ndef_length = 0;

	DEBUG_CLIENT_MSG("send reqeust :: write ndef = [%p]", handle);

	if (handle == NULL || msg == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (!net_nfc_tag_is_connected())
	{
		return NET_NFC_OPERATION_FAIL;
	}

	ndef_length = net_nfc_util_get_ndef_message_length((ndef_message_s *)msg);
	if (ndef_length == 0)
	{
		return NET_NFC_INVALID_PARAM;
	}

	length = sizeof(net_nfc_request_write_ndef_t) + ndef_length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	/* fill request message */
	request->length = length;
	request->request_type = NET_NFC_MESSAGE_WRITE_NDEF;
	request->handle = (net_nfc_target_handle_s *)handle;
	request->trans_param = trans_param;
	request->data.length = ndef_length;

	data.length = ndef_length;
	data.buffer = request->data.buffer;

	result = net_nfc_util_convert_ndef_message_to_rawdata((ndef_message_s *)msg, &data);
	if (result != NET_NFC_OK)
	{
		DEBUG_CLIENT_MSG("NDEF to rawdata is failed (reason:%d)", result);
		_net_nfc_util_free_mem(request);
		return result;
	}

	result = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_is_tag_connected(void *trans_param)
{
	net_nfc_request_is_tag_connected_t request = { 0, };
	net_nfc_error_e result;

	request.length = sizeof(net_nfc_request_is_tag_connected_t);
	request.request_type = NET_NFC_MESSAGE_IS_TAG_CONNECTED;
	request.trans_param = trans_param;

	result = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_is_tag_connected_sync(int *dev_type)
{
	net_nfc_request_is_tag_connected_t request = { 0, };
	net_nfc_response_is_tag_connected_t context = { 0, };
	net_nfc_error_e result;

	if (dev_type == NULL)
		return NET_NFC_INVALID_PARAM;

	request.length = sizeof(net_nfc_request_is_tag_connected_t);
	request.request_type = NET_NFC_MESSAGE_IS_TAG_CONNECTED;
	request.trans_param = (void *)&context;

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);
	if (result == NET_NFC_OK)
	{
		*dev_type = context.devType;
	}

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_make_read_only_ndef_tag(net_nfc_target_handle_h handle, void *trans_param)
{
	net_nfc_error_e result;
	net_nfc_request_make_read_only_ndef_t request = { 0, };
	client_context_t *tmp_client_context = NULL;
	net_nfc_target_info_s *target_info = NULL;

	DEBUG_CLIENT_MSG("send reqeust :: make read only ndef tag = [%p]", handle);

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (!net_nfc_tag_is_connected())
	{
		return NET_NFC_OPERATION_FAIL;
	}

	tmp_client_context = net_nfc_get_client_context();
	if (tmp_client_context != NULL)
	{
		target_info = tmp_client_context->target_info;

		if (target_info != NULL)
		{
			bool is_supported_tag = false;

			switch (target_info->devType)
			{
			case NET_NFC_ISO14443_A_PICC :
			case NET_NFC_MIFARE_MINI_PICC :
			case NET_NFC_MIFARE_1K_PICC :
			case NET_NFC_MIFARE_4K_PICC :
			case NET_NFC_MIFARE_ULTRA_PICC :
			case NET_NFC_JEWEL_PICC :
				is_supported_tag = true;
				break;
			default :
				is_supported_tag = false;
				break;
			}

			if (!is_supported_tag)
			{
				DEBUG_MSG("not supported tag for read only ndef tag");
				return NET_NFC_NOT_SUPPORTED;
			}
		}
	}

	request.length = sizeof(net_nfc_request_make_read_only_ndef_t);
	request.request_type = NET_NFC_MESSAGE_MAKE_READ_ONLY_NDEF;
	request.handle = (net_nfc_target_handle_s *)handle;
	request.trans_param = trans_param;

	result = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_current_tag_info(void *trans_param)
{
	net_nfc_request_get_current_tag_info_t request = { 0, };
	net_nfc_error_e result = NET_NFC_OK;

	request.length = sizeof(net_nfc_request_get_current_tag_info_t);
	request.request_type = NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO;
	request.trans_param = trans_param;

	result = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_current_tag_info_sync(net_nfc_target_info_h *info)
{
	net_nfc_request_get_current_tag_info_t request = { 0, };
	net_nfc_response_get_current_tag_info_t response = { 0, };
	net_nfc_error_e result = NET_NFC_OK;

	request.length = sizeof(net_nfc_request_get_current_tag_info_t);
	request.request_type = NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO;
	request.trans_param = (void *)&response;

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);
	if (result == NET_NFC_OK)
	{
		/* already allocated memory */
		net_nfc_duplicate_target_info((net_nfc_target_info_h)response.trans_param, info);
	}

	return result;
}

bool net_nfc_util_check_tag_filter(net_nfc_target_type_e type)
{
	net_nfc_event_filter_e current_filter = net_nfc_get_tag_filter();
	net_nfc_event_filter_e converted = NET_NFC_ALL_ENABLE;

	DEBUG_CLIENT_MSG("filter = [%d]", current_filter);

	if (type >= NET_NFC_ISO14443_A_PICC && type <= NET_NFC_MIFARE_DESFIRE_PICC)
	{
		converted = NET_NFC_ISO14443A_ENABLE;
	}
	else if (type >= NET_NFC_ISO14443_B_PICC && type <= NET_NFC_ISO14443_BPRIME_PICC)
	{
		converted = NET_NFC_ISO14443B_ENABLE;
	}
	else if (type == NET_NFC_FELICA_PICC)
	{
		converted = NET_NFC_FELICA_ENABLE;
	}
	else if (type == NET_NFC_JEWEL_PICC)
	{
		converted = NET_NFC_FELICA_ENABLE;
	}
	else if (type == NET_NFC_ISO15693_PICC)
	{
		converted = NET_NFC_ISO15693_ENABLE;
	}

	if ((converted & current_filter) == 0)
	{
		return false;
	}

	return true;
}
