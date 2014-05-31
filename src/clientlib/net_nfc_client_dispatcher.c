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

#include <stdio.h>
#include <glib.h>

#ifdef USE_ECORE_MAIN_LOOP
#include "Ecore.h"
#endif

#include "net_nfc_typedef_private.h"
#include "net_nfc_typedef.h"
#include "net_nfc_data.h"
#include "net_nfc_exchanger_private.h"
#include "net_nfc_tag.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_client_dispatcher_private.h"
#include "net_nfc_client_nfc_private.h"


extern unsigned int socket_handle;

net_nfc_llcp_internal_socket_s *_find_internal_socket_info(net_nfc_llcp_socket_t socket);
net_nfc_llcp_internal_socket_s *_find_internal_socket_info_by_oal_socket(net_nfc_llcp_socket_t socket);
void _append_internal_socket(net_nfc_llcp_internal_socket_s *data);
void _remove_internal_socket(net_nfc_llcp_internal_socket_s *data);
void _net_nfc_llcp_close_all_socket();
void _net_nfc_set_llcp_remote_configure(net_nfc_llcp_config_info_s *remote_data);

typedef struct _client_dispatcher_param_t
{
	net_nfc_response_cb client_cb;
	net_nfc_response_msg_t *msg;
} client_dispatcher_param_t;

/* static function */

static net_nfc_error_e net_nfc_get_tag_info_list(data_s *values, int number_of_keys, net_nfc_tag_info_s **list);
static bool net_nfc_client_dispatch_response(client_dispatcher_param_t *param);

/////////////////////

void _net_nfc_set_llcp_current_target_id(net_nfc_target_handle_s *handle);

#ifdef SAVE_TARGET_INFO_IN_CC
static void __net_nfc_clear_tag_info_cache (client_context_t *context)
{
	if (context->target_info != NULL)
	{
		net_nfc_target_info_s *info = context->target_info;
		net_nfc_tag_info_s *list = info->tag_info_list;

		if (list != NULL)
		{

			int i = 0;
			net_nfc_tag_info_s *temp = list;

			while (i < info->number_of_keys)
			{
				if (list->key != NULL)
					free(list->key);

				if (list->value != NULL)
					net_nfc_free_data(list->value);

				list++;
				i++;
			}

			/* destroy list */
			free(temp);
		}

		if (info->keylist != NULL)
		{
			_net_nfc_util_free_mem(info->keylist);
		}

		_net_nfc_util_free_mem(context->target_info);
		context->target_info = NULL;
	}
}
#endif

#ifdef USE_GLIB_MAIN_LOOP
void net_nfc_client_call_dispatcher_in_g_main_loop(net_nfc_response_cb client_cb, net_nfc_response_msg_t *msg)
{
	client_dispatcher_param_t *param = NULL;

	DEBUG_CLIENT_MSG("put message to g main loop");

	_net_nfc_util_alloc_mem(param, sizeof(client_dispatcher_param_t));
	if (param != NULL)
	{
		param->client_cb = client_cb;
		param->msg = msg;

		if (g_idle_add_full(G_PRIORITY_HIGH_IDLE, (GSourceFunc)net_nfc_client_dispatch_response, param, NULL))
		{
			g_main_context_wakeup(g_main_context_default());
		}
	}
}
#elif USE_ECORE_MAIN_LOOP
void net_nfc_client_call_dispatcher_in_ecore_main_loop(net_nfc_response_cb client_cb, net_nfc_response_msg_t *msg)
{
	client_dispatcher_param_t *param = NULL;

	DEBUG_CLIENT_MSG("put message to ecore main loop");

	_net_nfc_util_alloc_mem(param, sizeof(client_dispatcher_param_t));
	if (param != NULL)
	{
		param->client_cb = client_cb;
		param->msg = msg;

		if (ecore_idler_add((Ecore_Task_Cb)net_nfc_client_dispatch_response, param) != NULL)
		{
			g_main_context_wakeup(g_main_context_default());
		}
	}
}
#else
void net_nfc_client_call_dispatcher_in_current_context(net_nfc_response_cb client_cb, net_nfc_response_msg_t *msg)
{
	client_dispatcher_param_t *param = NULL;

	DEBUG_CLIENT_MSG("invoke callback in current thread");

	_net_nfc_util_alloc_mem(param, sizeof(client_dispatcher_param_t));
	if (param != NULL)
	{
		param->client_cb = client_cb;
		param->msg = msg;

		net_nfc_client_dispatch_response(param);
	}
}
#endif

static bool net_nfc_client_dispatch_response(client_dispatcher_param_t *param)
{
	if (param == NULL)
		return false;

	net_nfc_response_cb client_cb = param->client_cb;
	net_nfc_response_msg_t *msg = param->msg;

	_net_nfc_util_free_mem(param);

	DEBUG_CLIENT_MSG("we have got message from nfc-daemon type = [%d]", msg->response_type);

	client_context_t *client_context = net_nfc_get_client_context();

	switch (msg->response_type)
	{
	case NET_NFC_MESSAGE_GET_SE :
		{
			if (client_cb != NULL)
			{
				client_cb(msg->response_type, ((net_nfc_response_get_se_t *)msg->detail_message)->result, &(((net_nfc_response_get_se_t *)msg->detail_message)->se_type), client_context->register_user_param, ((net_nfc_response_get_se_t *)msg->detail_message)->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_SET_SE :
		{
			if (client_cb != NULL)
			{
				client_cb(msg->response_type, ((net_nfc_response_set_se_t *)msg->detail_message)->result, &(((net_nfc_response_get_se_t *)msg->detail_message)->se_type), client_context->register_user_param, ((net_nfc_response_set_se_t *)msg->detail_message)->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_SE_TYPE_CHANGED :
		{
			if (client_cb != NULL)
			{
				client_cb(msg->response_type, NET_NFC_OK, NULL, NULL, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED :
		{
			if (client_cb != NULL)
			{
				client_cb(msg->response_type, NET_NFC_OK, NULL, NULL, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_OPEN_INTERNAL_SE :
		{
			DEBUG_CLIENT_MSG("handle = [0x%p]", ((net_nfc_response_open_internal_se_t *)(msg->detail_message))->handle);

			if (client_cb != NULL)
			{
				client_cb(msg->response_type, ((net_nfc_response_open_internal_se_t *)(msg->detail_message))->result, (void *)((net_nfc_response_open_internal_se_t *)(msg->detail_message))->handle, client_context->register_user_param, ((net_nfc_response_open_internal_se_t *)(msg->detail_message))->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_CLOSE_INTERNAL_SE :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_close_internal_se_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_close_internal_se_t *)msg->detail_message)->trans_param);
		}
		break;

	case NET_NFC_MESSAGE_SEND_APDU_SE :
		{
			data_s *apdu = &(((net_nfc_response_send_apdu_t *)msg->detail_message)->data);

			if (apdu->length > 0)
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_send_apdu_t *)msg->detail_message)->result, apdu, client_context->register_user_param, ((net_nfc_response_send_apdu_t *)(msg->detail_message))->trans_param);
			}
			else
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_send_apdu_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_send_apdu_t *)(msg->detail_message))->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_GET_ATR_SE :
		{
			data_s *atr = &(((net_nfc_response_get_atr_t *)msg->detail_message)->data);

			if (atr->length > 0)
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_get_atr_t *)msg->detail_message)->result, atr, client_context->register_user_param, (void *)((net_nfc_response_get_atr_t *)(msg->detail_message))->user_param);
			}
			else
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_get_atr_t *)msg->detail_message)->result, NULL, client_context->register_user_param, (void *)((net_nfc_response_get_atr_t *)(msg->detail_message))->user_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_NOTIFY :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_notify_t *)msg->detail_message)->result, NULL, client_context->register_user_param, NULL);
		}
		break;

	case NET_NFC_MESSAGE_TRANSCEIVE :
		{
			data_s *data = &(((net_nfc_response_transceive_t *)msg->detail_message)->data);

			if (data->length > 0)
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_transceive_t *)msg->detail_message)->result, (void *)data, client_context->register_user_param, ((net_nfc_response_transceive_t *)(msg->detail_message))->trans_param);
			}
			else
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_transceive_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_transceive_t *)(msg->detail_message))->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_MAKE_READ_ONLY_NDEF :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_make_read_only_ndef_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_make_read_only_ndef_t *)(msg->detail_message))->trans_param);
		}
		break;

	case NET_NFC_MESSAGE_IS_TAG_CONNECTED :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_is_tag_connected_t *)msg->detail_message)->result, (void *)&(((net_nfc_response_is_tag_connected_t *)msg->detail_message)->devType), client_context->register_user_param, ((net_nfc_response_is_tag_connected_t *)(msg->detail_message))->trans_param);
		}
		break;

	case NET_NFC_MESSAGE_READ_NDEF :
		{
			data_s *data = &(((net_nfc_response_read_ndef_t *)msg->detail_message)->data);
			ndef_message_s *ndef = NULL;

			if (net_nfc_util_create_ndef_message(&ndef) != NET_NFC_OK)
			{
				DEBUG_ERR_MSG("memory alloc fail..");
				break;
			}

			if (data->length > 0 && net_nfc_util_convert_rawdata_to_ndef_message(data, ndef) == NET_NFC_OK)
			{
				if(client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_read_ndef_t *)msg->detail_message)->result, ndef, client_context->register_user_param, ((net_nfc_response_transceive_t *)(msg->detail_message))->trans_param);
			}
			else
			{
				if(client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_read_ndef_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_transceive_t *)(msg->detail_message))->trans_param);
			}
			net_nfc_util_free_ndef_message(ndef);
		}
		break;

	case NET_NFC_GET_SERVER_STATE :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_get_server_state_t *)msg->detail_message)->result, NULL, client_context->register_user_param, (void *)((net_nfc_response_get_server_state_t *)msg->detail_message)->state);
		}
		break;

	case NET_NFC_MESSAGE_SIM_TEST :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_get_server_state_t *)msg->detail_message)->result, NULL, client_context->register_user_param, (void *)((net_nfc_response_get_server_state_t *)msg->detail_message)->state);
		}
		break;

	case NET_NFC_MESSAGE_PRBS_TEST :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_get_server_state_t *)msg->detail_message)->result, NULL, client_context->register_user_param, (void *)((net_nfc_response_get_server_state_t *)msg->detail_message)->state);
		}
		break;

	case NET_NFC_MESSAGE_SET_EEDATA :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_get_server_state_t *)msg->detail_message)->result, NULL, client_context->register_user_param, (void *)((net_nfc_response_get_server_state_t *)msg->detail_message)->state);
		}
		break;

	case NET_NFC_MESSAGE_GET_FIRMWARE_VERSION :
		{
			data_s *version = &(((net_nfc_response_firmware_version_t *)msg->detail_message)->data);

			if (version->length > 0)
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_send_apdu_t *)msg->detail_message)->result, version, client_context->register_user_param, ((net_nfc_response_send_apdu_t *)(msg->detail_message))->trans_param);
			}
			else
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, ((net_nfc_response_send_apdu_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_send_apdu_t *)(msg->detail_message))->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_WRITE_NDEF :
		{
			if (client_cb != NULL)
				client_cb(msg->response_type, ((net_nfc_response_write_ndef_t *)msg->detail_message)->result, NULL, client_context->register_user_param, ((net_nfc_response_transceive_t *)(msg->detail_message))->trans_param);
		}
		break;

	case NET_NFC_MESSAGE_TAG_DISCOVERED :
		{
			net_nfc_response_tag_discovered_t *detected = (net_nfc_response_tag_discovered_t *)msg->detail_message;

			if (net_nfc_util_check_tag_filter(detected->devType) == false)
			{
				DEBUG_CLIENT_MSG("The detected target is filtered out");
			}

#ifdef SAVE_TARGET_INFO_IN_CC
			__net_nfc_clear_tag_info_cache(client_context);

			net_nfc_tag_info_s *list = NULL;
			net_nfc_get_tag_info_list(&(detected->target_info_values), detected->number_of_keys, &list);

			net_nfc_target_info_s *info = NULL;
			_net_nfc_util_alloc_mem(info, sizeof(net_nfc_target_info_s));
			if (info == NULL)
			{
				DEBUG_CLIENT_MSG("mem alloc is failed");
				_net_nfc_util_free_mem(list);
				break;
			}

			info->ndefCardState = detected->ndefCardState;
			info->actualDataSize = detected->actualDataSize;
			info->maxDataSize = detected->maxDataSize;
			info->devType = detected->devType;
			info->handle = detected->handle;
			info->is_ndef_supported = detected->is_ndef_supported;
			info->number_of_keys = detected->number_of_keys;
			info->tag_info_list = list;
			info->raw_data = detected->raw_data;

			client_context->target_info = info;

			if (client_cb != NULL)
				client_cb(msg->response_type, NET_NFC_OK, info, client_context->register_user_param, NULL);
#else
			net_nfc_tag_info_s *list = NULL;
			net_nfc_get_tag_info_list(&(detected->target_info_values), detected->number_of_keys, &list);

			net_nfc_target_info_s info;
			memset(&info, 0x00, sizeof(net_nfc_target_info_s));

			info.ndefCardState = detected->ndefCardState;
			info.actualDataSize = detected->actualDataSize;
			info.maxDataSize = detected->maxDataSize;
			info.devType = detected->devType;
			info.handle = detected->handle;
			info.is_ndef_supported = detected->is_ndef_supported;
			info.number_of_keys = detected->number_of_keys;
			info.tag_info_list = list;
			info.raw_data = detected.raw_data;

			if (client_cb != NULL)
				client_cb(msg->response_type, NET_NFC_OK, &info, client_context->register_user_param, NULL);

			net_nfc_util_release_tag_info(&info);
#endif
		}
		break;

	case NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO :
		{
			net_nfc_response_get_current_tag_info_t *detected = (net_nfc_response_get_current_tag_info_t *)msg->detail_message;

			if (detected->result != NET_NFC_NOT_CONNECTED)
			{
				if (net_nfc_util_check_tag_filter(detected->devType) == false)
				{
					DEBUG_CLIENT_MSG("The detected target is filtered out");
				}

#ifdef SAVE_TARGET_INFO_IN_CC
				__net_nfc_clear_tag_info_cache(client_context);

				net_nfc_tag_info_s *list = NULL;
				net_nfc_get_tag_info_list(&(detected->target_info_values), detected->number_of_keys, &list);

				net_nfc_target_info_s *info = NULL;
				_net_nfc_util_alloc_mem(info, sizeof(net_nfc_target_info_s));
				if (info == NULL)
				{
					DEBUG_CLIENT_MSG("mem alloc is failed");
					_net_nfc_util_free_mem(list);
					break;
				}

				info->ndefCardState = detected->ndefCardState;
				info->actualDataSize = detected->actualDataSize;
				info->maxDataSize = detected->maxDataSize;
				info->devType = detected->devType;
				info->handle = detected->handle;
				info->is_ndef_supported = detected->is_ndef_supported;
				info->number_of_keys = detected->number_of_keys;
				info->tag_info_list = list;
				info->raw_data = detected->raw_data;

				client_context->target_info = info;

				if (client_cb != NULL)
					client_cb(msg->response_type, NET_NFC_OK, info, client_context->register_user_param, detected->trans_param);
#else
				net_nfc_tag_info_s *list = NULL;
				net_nfc_get_tag_info_list(&(detected->target_info_values), detected->number_of_keys, &list);

				net_nfc_target_info_s info;
				memset(&info, 0x00, sizeof(net_nfc_target_info_s));

				info.ndefCardState = detected->ndefCardState;
				info.actualDataSize = detected->actualDataSize;
				info.maxDataSize = detected->maxDataSize;
				info.devType = detected->devType;
				info.handle = detected->handle;
				info.is_ndef_supported = detected->is_ndef_supported;
				info.number_of_keys = detected->number_of_keys;
				info.tag_info_list = list;
				info.raw_data = detected.raw_data;

				if (client_cb != NULL)
					client_cb(msg->response_type, NET_NFC_OK, &info, client_context->register_user_param, detected->trans_param);

				net_nfc_util_release_tag_info(&info);
#endif
			}
			else
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, detected->result, NULL, client_context->register_user_param, detected->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE :
		{
			net_nfc_response_get_current_target_handle_t *detected = (net_nfc_response_get_current_target_handle_t *)msg->detail_message;

			if (detected->result == NET_NFC_OK)
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, detected->result, (void *)detected->handle, client_context->register_user_param, detected->trans_param);
			}
			else
			{
				if (client_cb != NULL)
					client_cb(msg->response_type, detected->result, NULL, client_context->register_user_param, detected->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_TAG_DETACHED :
		{
			net_nfc_response_target_detached_t *detached = (net_nfc_response_target_detached_t *)msg->detail_message;

			if (net_nfc_util_check_tag_filter(detached->devType) == false)
			{
				DEBUG_CLIENT_MSG("The detected target is filtered out");
			}

			if (client_cb != NULL)
				client_cb(msg->response_type, NET_NFC_OK, (net_nfc_target_handle_h)detached->handle, client_context->register_user_param, NULL);

#ifdef SAVE_TARGET_INFO_IN_CC
			__net_nfc_clear_tag_info_cache(client_context);
#endif
		}
		break;

	case NET_NFC_MESSAGE_FORMAT_NDEF :
		{
			net_nfc_response_format_ndef_t *detail_msg = (net_nfc_response_format_ndef_t *)msg->detail_message;

			if (client_cb != NULL)
				client_cb(msg->response_type, detail_msg->result, NULL, client_context->register_user_param, detail_msg->trans_param);
		}
		break;

	case NET_NFC_MESSAGE_SE_START_TRANSACTION :
	case NET_NFC_MESSAGE_SE_END_TRANSACTION :
	case NET_NFC_MESSAGE_SE_TYPE_TRANSACTION :
	case NET_NFC_MESSAGE_SE_CONNECTIVITY :
	case NET_NFC_MESSAGE_SE_FIELD_ON :
	case NET_NFC_MESSAGE_SE_FIELD_OFF :
		{
			net_nfc_response_se_event_t *se_event = (net_nfc_response_se_event_t *)msg->detail_message;
			net_nfc_se_event_info_s info = { { 0, }, };

			info.aid = se_event->aid;
			info.param = se_event->param;
			info.se_type = se_event->se_type;
			info.fg_dispatch = se_event->fg_dispatch;
			info.focus_app_pid = se_event->focus_app_pid;

			if (client_cb != NULL)
				client_cb(msg->response_type, NET_NFC_OK, (void *)&info, client_context->register_user_param, NULL);
		}
		break;

	case NET_NFC_MESSAGE_LLCP_LISTEN :
		{
			net_nfc_response_listen_socket_t *detail_msg = (net_nfc_response_listen_socket_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;

			psocket_info = _find_internal_socket_info(detail_msg->client_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			psocket_info->oal_socket = detail_msg->oal_socket;
			DEBUG_CLIENT_MSG ("oal socket %d", detail_msg->oal_socket);
			if (psocket_info->cb != NULL)
			{
				psocket_info->cb(msg->response_type, detail_msg->result, NULL, psocket_info->register_param, detail_msg->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_CONNECT :
		{
			net_nfc_response_connect_socket_t *detail_msg = (net_nfc_response_connect_socket_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;

			psocket_info = _find_internal_socket_info(detail_msg->client_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			psocket_info->oal_socket = detail_msg->oal_socket;
			if (psocket_info->cb != NULL)
			{
				psocket_info->cb(msg->response_type, detail_msg->result, NULL, psocket_info->register_param, detail_msg->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_CONNECT_SAP :
		{
			net_nfc_response_connect_sap_socket_t *detail_msg = (net_nfc_response_connect_sap_socket_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;

			psocket_info = _find_internal_socket_info(detail_msg->client_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			psocket_info->oal_socket = detail_msg->oal_socket;
			if (psocket_info->cb != NULL)
			{
				psocket_info->cb(msg->response_type, detail_msg->result, NULL, psocket_info->register_param, detail_msg->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_SEND :
		{
			net_nfc_response_send_socket_t *detail_msg = (net_nfc_response_send_socket_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;

			psocket_info = _find_internal_socket_info(detail_msg->client_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			if (psocket_info->cb != NULL)
			{
				psocket_info->cb(msg->response_type, detail_msg->result, NULL, psocket_info->register_param, detail_msg->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_RECEIVE :
		{
			net_nfc_response_receive_socket_t *detail_msg = (net_nfc_response_receive_socket_t *)msg->detail_message;

			if (client_cb != NULL)
				client_cb(msg->response_type, detail_msg->result, &(detail_msg->data), client_context->register_user_param, NULL);
		}
		break;

	case NET_NFC_MESSAGE_P2P_RECEIVE :
		{
			net_nfc_response_p2p_receive_t *detail_msg = (net_nfc_response_p2p_receive_t *)msg->detail_message;

			if (client_cb != NULL)
				client_cb(msg->response_type, detail_msg->result, &(detail_msg->data), client_context->register_user_param, NULL);
		}
		break;

	case NET_NFC_MESSAGE_P2P_SEND :
		{
			net_nfc_response_p2p_send_t *detail_msg = (net_nfc_response_p2p_send_t *)msg->detail_message;

			if (client_cb != NULL)
				client_cb(msg->response_type, detail_msg->result, NULL, client_context->register_user_param, NULL);
		}
		break;

	case NET_NFC_MESSAGE_LLCP_DISCONNECT :
		{
			net_nfc_response_disconnect_socket_t *detail_msg = (net_nfc_response_disconnect_socket_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;

			psocket_info = _find_internal_socket_info(detail_msg->client_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			if (psocket_info->cb != NULL)
			{
				psocket_info->cb(msg->response_type, detail_msg->result, NULL, psocket_info->register_param, detail_msg->trans_param);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_CONFIG :
		{
			net_nfc_response_config_llcp_t *detail_msg = (net_nfc_response_config_llcp_t *)msg->detail_message;

			if (client_cb != NULL)
				client_cb(msg->response_type, detail_msg->result, NULL, client_context->register_user_param, NULL);
		}
		break;

	case NET_NFC_MESSAGE_LLCP_ERROR :
		{
			net_nfc_response_llcp_socket_error_t *detail_msg = (net_nfc_response_llcp_socket_error_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;

			psocket_info = _find_internal_socket_info(detail_msg->client_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			if (psocket_info->cb != NULL)
			{
				psocket_info->cb(msg->response_type, detail_msg->error, NULL, psocket_info->register_param, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_ACCEPTED :
		{
			net_nfc_response_incomming_llcp_t *detail_msg = (net_nfc_response_incomming_llcp_t *)msg->detail_message;
			net_nfc_llcp_internal_socket_s *psocket_info = NULL;
			psocket_info = _find_internal_socket_info_by_oal_socket(detail_msg->oal_socket);
			if (psocket_info == NULL)
			{
				DEBUG_ERR_MSG("Wrong client socket is returned from server..");
				break;
			}
			if (psocket_info->cb != NULL)
			{
				net_nfc_llcp_internal_socket_s *socket_data = NULL;
				_net_nfc_util_alloc_mem(socket_data, sizeof(net_nfc_llcp_internal_socket_s));
				socket_data->client_socket = socket_handle++;
				socket_data->miu = detail_msg->option.miu;
				socket_data->rw = detail_msg->option.rw;
				socket_data->type = detail_msg->option.type;
				socket_data->device_id = detail_msg->handle;
				socket_data->close_requested = false;
				socket_data->oal_socket = detail_msg->incomming_socket;
				_append_internal_socket(socket_data);
				psocket_info->cb(msg->response_type, detail_msg->result, (void *)&(socket_data->client_socket), psocket_info->register_param, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_LLCP_DISCOVERED :
		{
			net_nfc_response_llcp_discovered_t *detail_msg = (net_nfc_response_llcp_discovered_t *)msg->detail_message;

			_net_nfc_set_llcp_current_target_id(detail_msg->handle);
			_net_nfc_set_llcp_remote_configure(&(detail_msg->llcp_config_info));

			__net_nfc_clear_tag_info_cache(client_context);

			net_nfc_tag_info_s *list = NULL;
			net_nfc_get_tag_info_list(&(detail_msg->target_info_values), detail_msg->number_of_keys, &list);

			net_nfc_target_info_s *info = NULL;
			if ((info = calloc(1, sizeof(net_nfc_target_info_s))) == NULL)
			{
				DEBUG_CLIENT_MSG("mem alloc is failed");
				_net_nfc_util_free_mem(list);
				break;
			}

			info->actualDataSize = 0;
			info->maxDataSize = 0;
			info->devType = detail_msg->devType;
			info->handle = detail_msg->handle;
			info->is_ndef_supported = false;
			info->number_of_keys = detail_msg->number_of_keys;
			info->tag_info_list = list;

			client_context->target_info = info;

			if (client_cb != NULL)
			{
				client_cb(msg->response_type, NET_NFC_OK, (void *)info, client_context->register_user_param, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_P2P_DETACHED :
		{
			net_nfc_response_llcp_detached_t *detail_msg = (net_nfc_response_llcp_detached_t *)msg->detail_message;

			_net_nfc_set_llcp_current_target_id(NULL);

			if (client_cb != NULL)
			{
				client_cb(msg->response_type, detail_msg->result, NULL, client_context->register_user_param, NULL);
			}
			_net_nfc_llcp_close_all_socket();

		}
		break;

	case NET_NFC_MESSAGE_P2P_DISCOVERED :
		{
			net_nfc_response_p2p_discovered_t *detail_msg = (net_nfc_response_p2p_discovered_t *)msg->detail_message;

			if (client_cb != NULL)
			{
				client_cb(msg->response_type, detail_msg->result, (void *)detail_msg->handle, client_context->register_user_param, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_CONNECTION_HANDOVER :
		{
			net_nfc_response_connection_handover_t *detail_msg = (net_nfc_response_connection_handover_t *)msg->detail_message;

			if (detail_msg == NULL)
			{
				DEBUG_ERR_MSG("NET_NFC_MESSAGE_CONNECTION_HANDOVER detail_msg == NULL");
				break;
			}

			if (client_cb != NULL)
			{
				net_nfc_connection_handover_info_s info = { 0, };

				info.type = detail_msg->type;
				info.data.length = detail_msg->data.length;
				if (info.data.length > 0)
				{
					_net_nfc_util_alloc_mem(info.data.buffer, info.data.length);
					if (info.data.buffer == NULL)
					{
						DEBUG_ERR_MSG("mem alloc is failed");
						break;
					}
					memcpy(info.data.buffer, detail_msg->data.buffer, info.data.length);
				}

				client_cb(msg->response_type, detail_msg->event, (void *)&info, client_context->register_user_param, NULL);

				if (info.data.length > 0)
				{
					_net_nfc_util_free_mem(info.data.buffer);
				}
			}
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_INIT :
		{
			net_nfc_response_test_t *detail_msg = (net_nfc_response_test_t *)msg->detail_message;

			DEBUG_CLIENT_MSG("NET_NFC_MESSAGE_SERVICE_INIT [%p]", detail_msg->trans_param);

			if (client_cb != NULL)
			{
				client_cb(NET_NFC_MESSAGE_INIT, detail_msg->result, NULL, client_context->register_user_param, NULL);
			}
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_DEINIT :
		{
			net_nfc_response_test_t *detail_msg = (net_nfc_response_test_t *)msg->detail_message;

			DEBUG_CLIENT_MSG("NET_NFC_MESSAGE_SERVICE_DEINIT [%p]", detail_msg->trans_param);

			if (client_cb != NULL)
			{
				client_cb(NET_NFC_MESSAGE_DEINIT, detail_msg->result, NULL, client_context->register_user_param, NULL);
			}
		}
		break;

	default :
		break;
	}

	/* client  callback must copy data to client area */
	net_nfc_util_mem_free_detail_msg(NET_NFC_UTIL_MSG_TYPE_RESPONSE, msg->response_type, msg->detail_message);
	_net_nfc_util_free_mem(msg);

	return false;
}

net_nfc_error_e net_nfc_client_dispatch_sync_response(net_nfc_response_msg_t *msg)
{
	net_nfc_error_e result = NET_NFC_OK;
	client_context_t *client_context = NULL;

	DEBUG_CLIENT_MSG("synchronous callback, message = [%d]", msg->response_type);

	client_context = net_nfc_get_client_context();

	switch (msg->response_type)
	{
	case NET_NFC_MESSAGE_GET_SE :
		break;

	case NET_NFC_MESSAGE_SET_SE :
		break;

	case NET_NFC_MESSAGE_SE_TYPE_CHANGED :
		break;

	case NET_NFC_MESSAGE_CARD_EMULATION_CHANGE_SE :
		{
			net_nfc_response_se_change_card_emulation_t *response
				= (net_nfc_response_se_change_card_emulation_t *)msg->detail_message;

			/* return */
			result = response->result;
		}
		break;

	case NET_NFC_MESSAGE_OPEN_INTERNAL_SE :
		{
			net_nfc_response_open_internal_se_t *response = (net_nfc_response_open_internal_se_t *)msg->detail_message;
			net_nfc_target_handle_h *handle = (net_nfc_target_handle_h *)response->user_param;

			/* return */
			result = response->result;

			if (handle != NULL) {
				*handle = (net_nfc_target_handle_h)response->handle;
			}
		}
		break;

	case NET_NFC_MESSAGE_CLOSE_INTERNAL_SE :
		{
			net_nfc_response_close_internal_se_t *response = (net_nfc_response_close_internal_se_t *)msg->detail_message;

			/* return */
			result = response->result;
		}
		break;

	case NET_NFC_MESSAGE_SEND_APDU_SE :
		{
			net_nfc_response_send_apdu_t *response = (net_nfc_response_send_apdu_t *)msg->detail_message;
			data_h *data = (data_h *)response->user_param;

			/* return */
			result = response->result;

			if (data != NULL && response->data.buffer != NULL &&
				response->data.length > 0) {
				net_nfc_create_data(data, response->data.buffer,
					response->data.length);
			}
		}
		break;

	case NET_NFC_MESSAGE_GET_ATR_SE :
		{
			net_nfc_response_get_atr_t *response = (net_nfc_response_get_atr_t *)msg->detail_message;
			data_h *data = (data_h *)response->user_param;

			/* return */
			result = response->result;

			if (data != NULL && response->data.buffer != NULL &&
				response->data.length > 0) {
				net_nfc_create_data(data, response->data.buffer,
					response->data.length);
			}
		}
		break;

	case NET_NFC_MESSAGE_NOTIFY :
		break;

	case NET_NFC_MESSAGE_TRANSCEIVE :
		break;

	case NET_NFC_MESSAGE_MAKE_READ_ONLY_NDEF :
		break;

	case NET_NFC_MESSAGE_IS_TAG_CONNECTED :
		{
			net_nfc_response_is_tag_connected_t *response = (net_nfc_response_is_tag_connected_t *)msg->detail_message;
			net_nfc_response_is_tag_connected_t *context = (net_nfc_response_is_tag_connected_t *)response->trans_param;

			/* return */
			result = response->result;

			if (context != NULL)
			{
				context->result = response->result;
				context->devType = response->devType;
			}
		}
		break;

	case NET_NFC_MESSAGE_READ_NDEF :
		break;

	case NET_NFC_GET_SERVER_STATE :
		break;

	case NET_NFC_MESSAGE_SIM_TEST :
		break;

	case NET_NFC_MESSAGE_PRBS_TEST :
		break;

	case NET_NFC_MESSAGE_SET_EEDATA :
		break;

	case NET_NFC_MESSAGE_GET_FIRMWARE_VERSION :
		break;

	case NET_NFC_MESSAGE_WRITE_NDEF :
		break;

	case NET_NFC_MESSAGE_TAG_DISCOVERED :
		break;

	case NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO :
		{
			net_nfc_response_get_current_tag_info_t *response = (net_nfc_response_get_current_tag_info_t *)msg->detail_message;
			net_nfc_response_get_current_tag_info_t *context = (net_nfc_response_get_current_tag_info_t *)response->trans_param;

			/* return */
			result = response->result;

			if (context != NULL)
			{
				context->result = response->result;

				if (response->result != NET_NFC_NOT_CONNECTED)
				{
					if (net_nfc_util_check_tag_filter(response->devType) == true)
					{
						net_nfc_target_info_s *info = NULL;

						_net_nfc_util_alloc_mem(info, sizeof(net_nfc_target_info_s));

						info->ndefCardState = response->ndefCardState;
						info->actualDataSize = response->actualDataSize;
						info->maxDataSize = response->maxDataSize;
						info->devType = response->devType;
						info->handle = response->handle;
						info->is_ndef_supported = response->is_ndef_supported;
						info->number_of_keys = response->number_of_keys;
						net_nfc_get_tag_info_list(&(response->target_info_values), response->number_of_keys, &info->tag_info_list);
						if (response->raw_data.length > 0)
						{
							net_nfc_util_alloc_data(&info->raw_data, response->raw_data.length);
							memcpy(info->raw_data.buffer, response->raw_data.buffer, info->raw_data.length);
						}

						context->trans_param = info;
						// TODO: check usage of trans_param
						client_context->target_info = info;
					}
					else
					{
						/* filtered tag */
					}
				}
			}
		}
		break;

	case NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE :
		{
			net_nfc_response_get_current_target_handle_t *response = (net_nfc_response_get_current_target_handle_t *)msg->detail_message;
			net_nfc_response_get_current_target_handle_t *context = (net_nfc_response_get_current_target_handle_t *)response->trans_param;

			/* return */
			result = response->result;

			if (context != NULL)
			{
				context->handle = response->handle;
				context->result = response->result;
			}
		}
		break;

	case NET_NFC_MESSAGE_TAG_DETACHED :
		break;

	case NET_NFC_MESSAGE_FORMAT_NDEF :
		break;

	case NET_NFC_MESSAGE_SE_START_TRANSACTION :
	case NET_NFC_MESSAGE_SE_END_TRANSACTION :
	case NET_NFC_MESSAGE_SE_TYPE_TRANSACTION :
	case NET_NFC_MESSAGE_SE_CONNECTIVITY :
	case NET_NFC_MESSAGE_SE_FIELD_ON :
	case NET_NFC_MESSAGE_SE_FIELD_OFF :
		break;

	case NET_NFC_MESSAGE_LLCP_LISTEN :
		break;

	case NET_NFC_MESSAGE_LLCP_CONNECT :
		break;

	case NET_NFC_MESSAGE_LLCP_CONNECT_SAP :
		break;

	case NET_NFC_MESSAGE_LLCP_SEND :
		break;

	case NET_NFC_MESSAGE_LLCP_RECEIVE :
		break;

	case NET_NFC_MESSAGE_P2P_RECEIVE :
		break;

	case NET_NFC_MESSAGE_P2P_SEND :
		break;

	case NET_NFC_MESSAGE_LLCP_DISCONNECT :
		break;

	case NET_NFC_MESSAGE_LLCP_CONFIG :
		break;

	case NET_NFC_MESSAGE_LLCP_ERROR :
		break;

	case NET_NFC_MESSAGE_LLCP_ACCEPTED :
		break;

	case NET_NFC_MESSAGE_LLCP_DISCOVERED :
		break;

	case NET_NFC_MESSAGE_P2P_DETACHED :
		break;

	case NET_NFC_MESSAGE_P2P_DISCOVERED :
		break;

	case NET_NFC_MESSAGE_CONNECTION_HANDOVER :
		break;

	case NET_NFC_MESSAGE_SERVICE_INIT :
		break;

	case NET_NFC_MESSAGE_SERVICE_DEINIT :
		break;

	default :
		break;
	}

	/* client callback must copy data to client area */
	net_nfc_util_mem_free_detail_msg(NET_NFC_UTIL_MSG_TYPE_RESPONSE, msg->response_type, msg->detail_message);
	_net_nfc_util_free_mem(msg);

	return result;
}

static net_nfc_error_e net_nfc_get_tag_info_list(data_s *values, int number_of_keys, net_nfc_tag_info_s **list)
{
	net_nfc_tag_info_s *temp_list = NULL;

	if (list == NULL)
		return NET_NFC_NULL_PARAMETER;

	/* TODO */
	_net_nfc_util_alloc_mem(temp_list, number_of_keys * sizeof(net_nfc_tag_info_s));
	if (temp_list == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	*list = temp_list;

	/* get 1 byte :: length
	 * get key name
	 * get 1 byte :: value length
	 * make data_h
	 */
	uint8_t *pBuffer = values->buffer;

	if (pBuffer == NULL)
		return NET_NFC_NULL_PARAMETER;

	int index = 0;

	while (index < number_of_keys)
	{
		int key_length = *pBuffer;
		char *key = NULL;

		_net_nfc_util_alloc_mem(key, key_length + 1);
		if (key == NULL)
			return NET_NFC_ALLOC_FAIL;
		pBuffer = pBuffer + 1;

		/* copy key name */
		memcpy(key, pBuffer, key_length);
		pBuffer = pBuffer + key_length;

		DEBUG_CLIENT_MSG("key = [%s]", key);

		/* get values length */
		uint32_t value_length = *pBuffer;
		pBuffer = pBuffer + 1;

		data_h value = NULL;

		if (value_length > 0)
		{
			net_nfc_create_data(&value, pBuffer, value_length);
			pBuffer = pBuffer + value_length;
		}

		temp_list->key = key;
		temp_list->value = value;

		temp_list++;

		index++;
	}
	return NET_NFC_OK;
}
