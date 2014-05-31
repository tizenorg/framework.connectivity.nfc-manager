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


#include <glib.h>
#include <pthread.h>

#include "net_nfc_llcp.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_client_ipc_private.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

GList * socket_list = NULL;

/*
	Concept of the llcp_lock
	1. this lock protects only between client thread (these are calling llcp apis) and callback thread queue (=dispatcher thread)
	2. dispatcher thread is always serial it does not have to protect itself.
	3. all internal function for example __free_socket_info, __socket_equal_to are used only inside of this file
	(there is no way to access from client api) thread safe.
	4. if the internal function calles from other thread (or changed to public) then you should consider use lock
*/
static pthread_mutex_t llcp_lock = PTHREAD_MUTEX_INITIALIZER;

/* to share client info */
unsigned int socket_handle = 0; /* to generate client socket handle */
static net_nfc_target_handle_s * current_target = NULL;

static net_nfc_llcp_config_info_s local_config = { 128, 1, 10, 0 };
static net_nfc_llcp_config_info_s remote_config = { 128, 1, 10, 0 };

/* =============================================================== */
/* Socket info util */

static void __free_socket_info(net_nfc_llcp_internal_socket_s * data)
{
	net_nfc_llcp_internal_socket_s * socket_info = (net_nfc_llcp_internal_socket_s *)data;

	if (socket_info == NULL)
		return;
	_net_nfc_util_free_mem(socket_info->service_name);
	_net_nfc_util_free_mem(socket_info);
}

static int __socket_equal_to(gconstpointer key1, gconstpointer key2)
{
	net_nfc_llcp_internal_socket_s * arg1 = (net_nfc_llcp_internal_socket_s *)key1;
	net_nfc_llcp_internal_socket_s * arg2 = (net_nfc_llcp_internal_socket_s *)key2;

	if (arg1->client_socket < arg2->client_socket)
	{
		return -1;
	}
	else if (arg1->client_socket > arg2->client_socket)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

net_nfc_llcp_internal_socket_s * _find_internal_socket_info(net_nfc_llcp_socket_t socket)
{
	net_nfc_llcp_internal_socket_s * inter_socket = NULL;
	net_nfc_llcp_internal_socket_s temp = { 0 };
	GList * found = NULL;

	DEBUG_CLIENT_MSG("Socket info search requested with #[ %d ]", socket);

	temp.client_socket = socket;

	if (socket_list != NULL)
	{
		found = g_list_find_custom(socket_list, &temp, __socket_equal_to);
	}

	if (NULL == found)
	{
		DEBUG_CLIENT_MSG("ERROR DATA IS NOT FOUND");
		return NULL;
	}
	else
	{
		DEBUG_CLIENT_MSG("socket_info is found address [%p]", found->data);
		inter_socket = (net_nfc_llcp_internal_socket_s *)found->data;
	}

	return inter_socket;
}

static int __socket_equal_to_by_oal(gconstpointer key1, gconstpointer key2)
{
	net_nfc_llcp_internal_socket_s * arg1 = (net_nfc_llcp_internal_socket_s *)key1;
	net_nfc_llcp_internal_socket_s * arg2 = (net_nfc_llcp_internal_socket_s *)key2;

	if (arg1->oal_socket < arg2->oal_socket)
	{
		return -1;
	}
	else if (arg1->oal_socket > arg2->oal_socket)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static void __socket_foreach(gpointer data, gpointer user_data)
{
	__free_socket_info((net_nfc_llcp_internal_socket_s *)data);
}

void _net_nfc_llcp_close_all_socket()
{
	pthread_mutex_lock(&llcp_lock);

	if (socket_list != NULL)
	{
		g_list_foreach(socket_list, __socket_foreach, NULL);
		g_list_free(socket_list);
	}

	socket_list = NULL;

	pthread_mutex_unlock(&llcp_lock);
}

net_nfc_llcp_internal_socket_s * _find_internal_socket_info_by_oal_socket(net_nfc_llcp_socket_t socket)
{
	net_nfc_llcp_internal_socket_s * inter_socket = NULL;
	net_nfc_llcp_internal_socket_s temp = { 0 };
	GList * found = NULL;

	temp.oal_socket = socket;

	DEBUG_CLIENT_MSG("search by oal socket is called socket[ %d ] ", socket);

	if (socket_list != NULL)
	{
		found = g_list_find_custom(socket_list, &temp, __socket_equal_to_by_oal);
	}

	if (NULL == found)
	{
		DEBUG_CLIENT_MSG("ERROR DATA IS NOT FOUND");
		return NULL;
	}
	else
	{
		inter_socket = (net_nfc_llcp_internal_socket_s *)found->data;
		DEBUG_CLIENT_MSG("oal socket_info is found address [%p]", inter_socket);
	}

	return inter_socket;
}

void _remove_internal_socket(net_nfc_llcp_internal_socket_s * data)
{
	pthread_mutex_lock(&llcp_lock);

	if (data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return;
	}

	if (socket_list != NULL)
	{

		socket_list = g_list_remove(socket_list, data);
	}
	__free_socket_info(data);

	pthread_mutex_unlock(&llcp_lock);
}

void _append_internal_socket(net_nfc_llcp_internal_socket_s * data)
{
	pthread_mutex_lock(&llcp_lock);

	if (data != NULL)
	{
		socket_list = g_list_append(socket_list, data);
	}

	pthread_mutex_unlock(&llcp_lock);
}

/* =============================================================== */
NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_llcp_socket(net_nfc_llcp_socket_t * socket, net_nfc_llcp_socket_option_h options)
{

	net_nfc_llcp_internal_socket_s * socket_data = NULL;
	net_nfc_llcp_socket_option_s * strct_options = (net_nfc_llcp_socket_option_s *)options;
	net_nfc_llcp_socket_option_s default_option = {
		128, 1, NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED
	};

	DEBUG_CLIENT_MSG("function %s is called", __func__);

	if (socket == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (options == NULL)
	{
		strct_options = &default_option;
	}

	_net_nfc_util_alloc_mem(socket_data, sizeof(net_nfc_llcp_internal_socket_s));

	socket_data->client_socket = socket_handle++;
	socket_data->miu = strct_options->miu;
	socket_data->rw = strct_options->rw;
	socket_data->type = strct_options->type;
	socket_data->device_id = current_target;
	socket_data->close_requested = false;

	_append_internal_socket(socket_data);

	*socket = socket_data->client_socket;

	return NET_NFC_OK;

}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_socket_callback(net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_cb cb, void * user_param)
{
	net_nfc_llcp_internal_socket_s * socket_data = NULL;

	if (cb == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	pthread_mutex_lock(&llcp_lock);

	socket_data = _find_internal_socket_info(socket);

	if (socket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	socket_data->cb = cb;
	socket_data->register_param = user_param;

	pthread_mutex_unlock(&llcp_lock);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_unset_llcp_socket_callback(net_nfc_llcp_socket_t socket)
{
	pthread_mutex_lock(&llcp_lock);
	net_nfc_llcp_internal_socket_s * socket_data = _find_internal_socket_info(socket);

	if (socket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	if (socket_data->cb == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_NOT_REGISTERED;
	}

	socket_data->cb = NULL;
	pthread_mutex_unlock(&llcp_lock);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_listen_llcp(net_nfc_llcp_socket_t socket, const char *service_name, sap_t sap, void *trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_listen_socket_t *request = NULL;
	net_nfc_error_e ret;
	int srv_name_count = 0;
	uint32_t length = 0;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	if (service_name == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	pthread_mutex_lock(&llcp_lock);
	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	srv_name_count = strlen((char *)service_name) + 1;

	_net_nfc_util_alloc_mem(psocket_data->service_name, srv_name_count);
	if (psocket_data->service_name == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_ALLOC_FAIL;
	}
	strncpy((char *)psocket_data->service_name, (char *)service_name, srv_name_count);
	psocket_data->sap = sap;

	/* fill request message */
	length = sizeof(net_nfc_request_listen_socket_t) + srv_name_count;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		_net_nfc_util_free_mem(psocket_data->service_name);
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_LLCP_LISTEN;
	request->handle = current_target;
	request->miu = psocket_data->miu;
	request->oal_socket = psocket_data->oal_socket;
	request->rw = psocket_data->rw;
	request->sap = psocket_data->sap;
	request->type = psocket_data->type;
	request->client_socket = psocket_data->client_socket;
	request->trans_param = trans_param;

	request->service_name.length = srv_name_count;
	memcpy(&request->service_name.buffer, psocket_data->service_name, request->service_name.length);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_disconnect_llcp(net_nfc_llcp_socket_t socket, void * trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data;
	net_nfc_request_disconnect_socket_t request = { 0, };
	net_nfc_error_e ret;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);
	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	request.length = sizeof(net_nfc_request_disconnect_socket_t);
	request.request_type = NET_NFC_MESSAGE_LLCP_DISCONNECT;
	request.handle = current_target;
	request.oal_socket = psocket_data->oal_socket;
	request.client_socket = psocket_data->client_socket;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_close_llcp_socket(net_nfc_llcp_socket_t socket, void * trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_close_socket_t request = { 0, };
	net_nfc_error_e ret;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);
	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	if (psocket_data->close_requested)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_OK;
	}
	psocket_data->close_requested = true;

	request.length = sizeof(net_nfc_request_close_socket_t);
	request.request_type = NET_NFC_MESSAGE_SERVICE_LLCP_CLOSE;
	request.handle = current_target;
	request.oal_socket = psocket_data->oal_socket;
	request.client_socket = psocket_data->client_socket;
	request.trans_param = trans_param;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	_remove_internal_socket(psocket_data);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_send_llcp(net_nfc_llcp_socket_t socket, data_h data, void * trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data;
	net_nfc_request_send_socket_t *request = NULL;
	data_s *data_private = (data_s *)data;
	net_nfc_error_e ret;
	uint32_t length = 0;

	if (data_private == NULL || data_private->buffer == NULL || data_private->length == 0)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);
	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	/* fill request message */
	length = sizeof(net_nfc_request_send_socket_t) + data_private->length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_LLCP_SEND;
	request->handle = current_target;
	request->oal_socket = psocket_data->oal_socket;
	request->client_socket = psocket_data->client_socket;
	request->trans_param = trans_param;

	request->data.length = data_private->length;
	memcpy(&request->data.buffer, data_private->buffer, request->data.length);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_receive_llcp(net_nfc_llcp_socket_t socket, size_t req_length, void * trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_receive_socket_t request = { 0, };
	net_nfc_error_e ret;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);

	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	request.length = sizeof(net_nfc_request_receive_socket_t);
	request.request_type = NET_NFC_MESSAGE_LLCP_RECEIVE;
	request.handle = current_target;
	request.oal_socket = psocket_data->oal_socket;
	request.client_socket = psocket_data->client_socket;
	request.trans_param = trans_param;
	request.req_length = req_length;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_send_to_llcp(net_nfc_llcp_socket_t socket, sap_t dsap, data_h data, void *trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_send_to_socket_t *request = NULL;
	data_s * data_private = (data_s *)data;
	net_nfc_error_e ret;
	uint32_t length = 0;

	if (data_private == NULL || data_private->buffer == NULL || data_private->length == 0)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);
	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	/* fill request message */
	length = sizeof(net_nfc_request_send_to_socket_t) + data_private->length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_LLCP_SEND_TO;
	request->handle = current_target;
	request->oal_socket = psocket_data->oal_socket;
	request->client_socket = psocket_data->client_socket;
	request->trans_param = trans_param;

	request->data.length = data_private->length;
	memcpy(&request->data.buffer, data_private->buffer, request->data.length);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_receive_from_llcp(net_nfc_llcp_socket_t socket, sap_t ssap, size_t req_length, void * trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_receive_from_socket_t request = { 0, };
	net_nfc_error_e ret;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);

	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	request.length = sizeof(net_nfc_request_receive_from_socket_t);
	request.request_type = NET_NFC_MESSAGE_LLCP_RECEIVE_FROM;
	request.handle = current_target;
	request.oal_socket = psocket_data->oal_socket;
	request.client_socket = psocket_data->client_socket;
	request.trans_param = trans_param;
	request.req_length = req_length;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_connect_llcp_with_sap(net_nfc_llcp_socket_t socket, sap_t sap, void * trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_connect_sap_socket_t request = { 0, };
	net_nfc_error_e ret;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);

	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	request.length = sizeof(net_nfc_request_connect_sap_socket_t);
	request.request_type = NET_NFC_MESSAGE_LLCP_CONNECT_SAP;
	request.handle = current_target;
	request.oal_socket = psocket_data->oal_socket;
	request.sap = sap;
	request.client_socket = psocket_data->client_socket;
	request.trans_param = trans_param;
	request.miu = psocket_data->miu;
	request.rw = psocket_data->rw;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_connect_llcp(net_nfc_llcp_socket_t socket, const char *service_name, void *trans_param)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;
	net_nfc_request_connect_socket_t *request = NULL;
	net_nfc_error_e ret;
	uint32_t length = 0, svc_name_length = 0;

	DEBUG_CLIENT_MSG("function %s is called. socket#[ %d ]", __func__, socket);

	pthread_mutex_lock(&llcp_lock);

	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_LLCP_INVALID_SOCKET;
	}

	svc_name_length = strlen(service_name) + 1;

	/* fill request message */
	length = sizeof(net_nfc_request_connect_socket_t) + svc_name_length;

	_net_nfc_util_alloc_mem(request, length);
	if (request == NULL)
	{
		pthread_mutex_unlock(&llcp_lock);
		return NET_NFC_ALLOC_FAIL;
	}

	request->length = length;
	request->request_type = NET_NFC_MESSAGE_LLCP_CONNECT;
	request->handle = current_target;
	request->oal_socket = psocket_data->oal_socket;
	request->client_socket = psocket_data->client_socket;
	request->trans_param = trans_param;
	request->miu = psocket_data->miu;
	request->rw = psocket_data->rw;

	request->service_name.length = svc_name_length;
	memcpy(&request->service_name.buffer, service_name, request->service_name.length);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)request, NULL);

	_net_nfc_util_free_mem(request);

	pthread_mutex_unlock(&llcp_lock);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_local_configure(net_nfc_llcp_config_info_h * config)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*config = (net_nfc_llcp_config_info_h)&local_config;

	return NET_NFC_OK;
}

void _net_nfc_set_llcp_remote_configure(net_nfc_llcp_config_info_s * remote_data)
{
	if (remote_data == NULL)
	{
		DEBUG_CLIENT_MSG("recieved data is NULL");
		return;
	}
	remote_config.lto = remote_data->lto;
	remote_config.wks = remote_data->wks;
	remote_config.miu = remote_data->miu;
	remote_config.option = remote_data->option;

}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_remote_configure(net_nfc_target_handle_h handle, net_nfc_llcp_config_info_h * config)
{
	if (config == NULL || handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (current_target == NULL || (net_nfc_target_handle_s*)handle != current_target)
	{
		return NET_NFC_INVALID_HANDLE;
	}

	*config = (net_nfc_llcp_config_info_h)&remote_config;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_local_configure(net_nfc_llcp_config_info_h config, void * trans_param)
{
	net_nfc_request_config_llcp_t request = { 0, };
	net_nfc_error_e ret;

	DEBUG_CLIENT_MSG("function %s is called", __func__);

	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	request.length = sizeof(net_nfc_request_config_llcp_t);
	request.request_type = NET_NFC_MESSAGE_LLCP_CONFIG;
	memset(&request, 0x0, sizeof(net_nfc_request_config_llcp_t));
	memcpy(&local_config, config, sizeof(net_nfc_llcp_config_info_s));
	request.trans_param = trans_param;
	memcpy(&(request.config), config, sizeof(net_nfc_llcp_config_info_s));

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_local_socket_option(net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_h * info)
{
	net_nfc_llcp_internal_socket_s *psocket_data = NULL;

	DEBUG_CLIENT_MSG("function %s is called", __func__);

	psocket_data = _find_internal_socket_info(socket);
	if (psocket_data == NULL)
		return NET_NFC_LLCP_INVALID_SOCKET;

	*info = (net_nfc_llcp_socket_option_h)psocket_data;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_remote_socket_option(net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_h * info)
{
	info = NULL;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_llcp_socket_option(net_nfc_llcp_socket_option_h * option, uint16_t miu, uint8_t rw, net_nfc_socket_type_e type)
{
	if (option == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (miu < 128 || miu > 1152 ||
		rw < 1 || rw > 15 ||
		type < NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED || type > NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONLESS)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	net_nfc_llcp_socket_option_s * struct_option = NULL;

	_net_nfc_util_alloc_mem(struct_option, sizeof(net_nfc_llcp_socket_option_s));
	if (struct_option != NULL)
	{
		struct_option->miu = miu;
		struct_option->rw = rw;
		struct_option->type = type;

		*option = (net_nfc_llcp_socket_option_h)struct_option;

		return NET_NFC_OK;
	}
	else
	{
		return NET_NFC_ALLOC_FAIL;
	}
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_llcp_socket_option_default(net_nfc_llcp_socket_option_h * option)
{
	return net_nfc_create_llcp_socket_option(option, 128, 1, NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_socket_option_miu(net_nfc_llcp_socket_option_h option, uint16_t * miu)
{
	if (option == NULL || miu == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_llcp_socket_option_s * struct_option = (net_nfc_llcp_socket_option_s *)option;

	*miu = struct_option->miu;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_socket_option_miu(net_nfc_llcp_socket_option_h option, uint16_t miu)
{
	if (option == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_llcp_socket_option_s * struct_option = (net_nfc_llcp_socket_option_s *)option;

	struct_option->miu = miu;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_socket_option_rw(net_nfc_llcp_socket_option_h option, uint8_t * rw)
{
	if (option == NULL || rw == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_llcp_socket_option_s * struct_option = (net_nfc_llcp_socket_option_s *)option;

	*rw = struct_option->rw;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_socket_option_rw(net_nfc_llcp_socket_option_h option, uint8_t rw)
{
	if (option == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_llcp_socket_option_s * struct_option = (net_nfc_llcp_socket_option_s *)option;

	struct_option->rw = rw;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_socket_option_type(net_nfc_llcp_socket_option_h option, net_nfc_socket_type_e * type)
{
	if (option == NULL || type == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_llcp_socket_option_s * struct_option = (net_nfc_llcp_socket_option_s *)option;

	*type = struct_option->type;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_socket_option_type(net_nfc_llcp_socket_option_h option, net_nfc_socket_type_e type)
{
	if (option == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_llcp_socket_option_s * struct_option = (net_nfc_llcp_socket_option_s *)option;

	struct_option->type = type;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_free_llcp_socket_option(net_nfc_llcp_socket_option_h option)
{
	if (option == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_free_mem(option);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_llcp_configure(net_nfc_llcp_config_info_h * config, uint16_t miu, uint16_t wks, uint8_t lto, uint8_t option)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s ** config_private = (net_nfc_llcp_config_info_s **)config;

	_net_nfc_util_alloc_mem(*config_private, sizeof (net_nfc_llcp_config_info_s));
	if (*config_private == NULL)
		return NET_NFC_ALLOC_FAIL;

	(*config_private)->miu = miu;
	(*config_private)->wks = wks;
	(*config_private)->lto = lto;
	(*config_private)->option = option;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_llcp_configure_default(net_nfc_llcp_config_info_h * config)
{
	return net_nfc_create_llcp_configure(config, 128, 1, 10, 0);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_configure_miu(net_nfc_llcp_config_info_h config, uint16_t * miu)
{
	if (config == NULL || miu == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	*miu = config_private->miu;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_configure_wks(net_nfc_llcp_config_info_h config, uint16_t * wks)
{
	if (config == NULL || wks == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	*wks = config_private->wks;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_configure_lto(net_nfc_llcp_config_info_h config, uint8_t * lto)
{
	if (config == NULL || lto == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	*lto = config_private->lto;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_llcp_configure_option(net_nfc_llcp_config_info_h config, uint8_t * option)
{
	if (config == NULL || option == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	*option = config_private->option;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_configure_miu(net_nfc_llcp_config_info_h config, uint16_t miu)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (miu < 128 || miu > 1152)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	config_private->miu = miu;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_configure_wks(net_nfc_llcp_config_info_h config, uint16_t wks)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	config_private->wks = wks;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_configure_lto(net_nfc_llcp_config_info_h config, uint8_t lto)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	config_private->lto = lto;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_llcp_configure_option(net_nfc_llcp_config_info_h config, uint8_t option)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_llcp_config_info_s * config_private = (net_nfc_llcp_config_info_s *)config;
	config_private->option = option;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_free_llcp_configure(net_nfc_llcp_config_info_h config)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_free_mem(config);
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_current_target_handle(void *trans_param)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_request_get_current_target_handle_t request = { 0, };

	request.length = sizeof(net_nfc_request_get_current_target_handle_t);
	request.request_type = NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE;
	request.trans_param = trans_param;

	result = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_current_target_handle_sync(net_nfc_target_handle_h *handle)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_request_get_current_target_handle_t request = { 0, };
	net_nfc_response_get_current_target_handle_t response = { 0, };

	request.length = sizeof(net_nfc_request_get_current_target_handle_t);
	request.request_type = NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE;
	request.trans_param = (void *)&response;

	result = net_nfc_client_send_request_sync((net_nfc_request_msg_t *)&request, NULL);
	if (result == NET_NFC_OK)
	{
		*handle = (net_nfc_target_handle_h)response.handle;
		result = response.result;
	}

	return result;
}

void _net_nfc_set_llcp_current_target_id(net_nfc_target_handle_s * handle)
{
	current_target = handle;
}
