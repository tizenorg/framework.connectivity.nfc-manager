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

#include "net_nfc_exchanger.h"
#include "net_nfc_exchanger_private.h"
#include "net_nfc.h"
#include "net_nfc_typedef.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_client_ipc_private.h"
#include "net_nfc_client_nfc_private.h"

static net_nfc_exchanger_cb exchanger_cb = NULL;

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_exchanger_data(net_nfc_exchanger_data_h *ex_data, data_h payload)
{
	net_nfc_exchanger_data_s* tmp_ex_data = NULL;

	if (ex_data == NULL || payload == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(tmp_ex_data, sizeof(net_nfc_exchanger_data_s));
	if (tmp_ex_data == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	tmp_ex_data->type = NET_NFC_EXCHANGER_RAW;

	_net_nfc_util_alloc_mem(tmp_ex_data->binary_data.buffer, ((data_s *)payload)->length);
	if (tmp_ex_data->binary_data.buffer == NULL)
	{
		_net_nfc_util_free_mem(tmp_ex_data);

		return NET_NFC_ALLOC_FAIL;
	}

	memcpy(tmp_ex_data->binary_data.buffer, ((data_s *)payload)->buffer, ((data_s *)payload)->length);

	tmp_ex_data->binary_data.length = ((data_s *)payload)->length;

	*ex_data = (net_nfc_exchanger_data_h)tmp_ex_data;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_free_exchanger_data(net_nfc_exchanger_data_h ex_data)
{
	if (ex_data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (((net_nfc_exchanger_data_s *)ex_data)->binary_data.buffer != NULL)
	{
		_net_nfc_util_free_mem(((net_nfc_exchanger_data_s *)ex_data)->binary_data.buffer);
	}

	_net_nfc_util_free_mem(ex_data);

	return NET_NFC_OK;
}

net_nfc_exchanger_cb net_nfc_get_exchanger_cb()
{
	return exchanger_cb;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_unset_exchanger_cb()
{
	client_context_t* client_context = net_nfc_get_client_context();

	if (exchanger_cb == NULL)
	{
		return NET_NFC_NOT_REGISTERED;
	}

	if (client_context != NULL)
		pthread_mutex_lock(&(client_context->g_client_lock));
	exchanger_cb = NULL;
	if (client_context != NULL)
		pthread_mutex_unlock(&(client_context->g_client_lock));

	net_nfc_state_deactivate();
	net_nfc_deinitialize();

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_send_exchanger_data(net_nfc_exchanger_data_h ex_handle, net_nfc_target_handle_h target_handle, void* trans_param)
{
	net_nfc_error_e ret;
	net_nfc_request_p2p_send_t *request = NULL;
	uint32_t length = 0;
	net_nfc_exchanger_data_s *ex_data = (net_nfc_exchanger_data_s *)ex_handle;

	DEBUG_CLIENT_MSG("send reqeust :: exchanger data = [%p] target_handle = [%p]", ex_handle, target_handle);

	length = sizeof(net_nfc_request_p2p_send_t) + ex_data->binary_data.length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_P2P_SEND;
	request->handle = (net_nfc_target_handle_s *)target_handle;
	request->data_type = ex_data->type;
	request->data.length = ex_data->binary_data.length;
	request->user_param = (uint32_t)trans_param;

	memcpy(&request->data.buffer, ex_data->binary_data.buffer, request->data.length);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_exchanger_request_connection_handover(net_nfc_target_handle_h target_handle, net_nfc_conn_handover_carrier_type_e type)
{
	net_nfc_error_e ret = NET_NFC_UNKNOWN_ERROR;
	net_nfc_request_connection_handover_t *request = NULL;
	uint32_t length = 0;

	if (target_handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	length = sizeof(net_nfc_request_p2p_send_t);

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_CONNECTION_HANDOVER;
	request->handle = (net_nfc_target_handle_s *)target_handle;
	request->type = type;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_exchanger_get_alternative_carrier_type(net_nfc_connection_handover_info_h info_handle, net_nfc_conn_handover_carrier_type_e *type)
{
	net_nfc_connection_handover_info_s *info = NULL;

	if (info_handle == NULL || type == NULL)
		return NET_NFC_NULL_PARAMETER;

	info = (net_nfc_connection_handover_info_s *)info_handle;

	*type = info->type;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_exchanger_get_alternative_carrier_data(net_nfc_connection_handover_info_h info_handle, data_h *data)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	net_nfc_connection_handover_info_s *info = NULL;

	if (info_handle == NULL || data == NULL)
		return NET_NFC_NULL_PARAMETER;

	info = (net_nfc_connection_handover_info_s *)info_handle;

	result = net_nfc_create_data(data, info->data.buffer, info->data.length);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_exchanger_free_alternative_carrier_data(net_nfc_connection_handover_info_h info_handle)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	net_nfc_connection_handover_info_s *info = NULL;

	if (info_handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	info = (net_nfc_connection_handover_info_s *)info_handle;

	if (info->data.buffer != NULL)
	{
		_net_nfc_util_free_mem(info->data.buffer);
	}

	_net_nfc_util_free_mem(info);

	return result;
}
