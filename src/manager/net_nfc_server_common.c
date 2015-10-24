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

#include <vconf.h>

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_manager.h"
#include "net_nfc_manager_util_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_llcp.h"
#include "net_nfc_server_se.h"
#include "net_nfc_server_hce.h"


typedef struct _ControllerFuncData ControllerFuncData;

struct _ControllerFuncData
{
	net_nfc_server_controller_func func;
	gpointer data;
	gboolean blocking;
};

static gpointer controller_thread_func(gpointer user_data);

static void controller_async_queue_free_func(gpointer user_data);

static void controller_thread_deinit_thread_func(gpointer user_data);

static void controller_target_detected_cb(void *info,
				void *user_context);

static void controller_se_transaction_cb(void *info,
				void *user_context);

static void controller_llcp_event_cb(void *info,
				void *user_context);

static void controller_hce_apdu_cb(void *info,
				void *user_context);

static void controller_init_thread_func(gpointer user_data);

#ifndef ESE_ALWAYS_ON
static void controller_deinit_thread_func(gpointer user_data);
#endif

static void restart_polling_loop_thread_func(gpointer user_data);
static void force_polling_loop_thread_func(gpointer user_data);

static GAsyncQueue *controller_async_queue = NULL;

static GThread *controller_thread = NULL;

static gboolean controller_is_running = FALSE;
static gboolean controller_dispath_running = FALSE;

static guint32 server_state = NET_NFC_SERVER_IDLE;

static gint controller_block;

static gboolean check_nfc_disable = FALSE;



static void controller_async_queue_free_func(gpointer user_data)
{
	ControllerFuncData *func_data = (ControllerFuncData *)user_data;

	if (func_data != NULL) {
		if (func_data->blocking == true) {
			controller_block--;
		}

		g_free(user_data);
	}
}

static gpointer controller_thread_func(gpointer user_data)
{
	if (controller_async_queue == NULL)
	{
		g_thread_exit(NULL);

		return NULL;
	}

	controller_is_running = TRUE;
	while (controller_is_running)
	{
		ControllerFuncData *func_data;

		func_data = g_async_queue_pop(controller_async_queue);
		if (func_data->func)
			func_data->func(func_data->data);

		controller_async_queue_free_func(func_data);
	}

	g_thread_exit(NULL);

	return NULL;
}

static void controller_thread_deinit_thread_func(gpointer user_data)
{
	controller_is_running = FALSE;
}

static net_nfc_current_target_info_s *_create_target_info(
	net_nfc_request_target_detected_t *msg)
{
	net_nfc_current_target_info_s *info;

	info = g_malloc0(sizeof(net_nfc_current_target_info_s) +
		msg->target_info_values.length);

	if(info == NULL)
		return NULL;

	info->handle = msg->handle;
	info->devType = msg->devType;

	if (info->devType != NET_NFC_NFCIP1_INITIATOR &&
		info->devType != NET_NFC_NFCIP1_TARGET)
	{
		info->number_of_keys = msg->number_of_keys;
		info->target_info_values.length =
			msg->target_info_values.length;

		memcpy(&info->target_info_values,
			&msg->target_info_values,
			info->target_info_values.length + sizeof(int));
	}

	return info;
}


/* FIXME: it works as broadcast only now */
static void controller_target_detected_cb(void *info,
				void *user_context)
{
	net_nfc_request_target_detected_t *req =
		(net_nfc_request_target_detected_t *)info;

	g_assert(info != NULL);

	INFO_MSG("check devType = [%d]", req->devType );

	if (req->request_type == NET_NFC_MESSAGE_SERVICE_RESTART_POLLING_LOOP)
	{
		net_nfc_server_restart_polling_loop();
	}
	else
	{
		bool ret = true;
		net_nfc_current_target_info_s *target_info;

		/* FIXME */
		target_info = _create_target_info(req);
		if (target_info != NULL) {
			if (req->devType != NET_NFC_UNKNOWN_TARGET) {
				if (req->devType == NET_NFC_NFCIP1_TARGET ||
					req->devType == NET_NFC_NFCIP1_INITIATOR) {
					/* llcp target detected */
					ret = net_nfc_server_llcp_target_detected(target_info);
				} else {
					/* tag target detected */
					ret = net_nfc_server_tag_target_detected(target_info);
				}
			}

			/* If target detected, sound should be played. */
			//net_nfc_manager_util_play_sound(NET_NFC_TASK_START);
		} else {
			DEBUG_ERR_MSG("_create_target_info failed");
		}

		if(ret == false)
			_net_nfc_util_free_mem(target_info);
	}

	/* FIXME : should be removed when plugins would be fixed*/
	_net_nfc_util_free_mem(info);
}

/* FIXME : net_nfc_dispatcher_queue_push() need to be removed */
static void controller_se_transaction_cb(void *info,
				void *user_context)
{
	net_nfc_request_se_event_t *req = (net_nfc_request_se_event_t *)info;

	g_assert(info != NULL);

	req->user_param = (uint32_t)user_context;


	INFO_MSG("SE Transaction = [%d]", req->request_type );

	switch(req->request_type)
	{
	case NET_NFC_MESSAGE_SERVICE_SLAVE_ESE_DETECTED :
		net_nfc_server_se_detected(req);
		break;

	case NET_NFC_MESSAGE_SE_START_TRANSACTION :
		net_nfc_server_se_transaction_received(req);
		break;

	case NET_NFC_MESSAGE_SE_FIELD_ON :
		net_nfc_server_se_rf_field_on(req);
		break;

	default :
		break;
	}
}

/* FIXME : net_nfc_dispatcher_queue_push() need to be removed */
static void _controller_llcp_event_cb(gpointer user_data)
{
	net_nfc_request_llcp_msg_t *req_msg =
		(net_nfc_request_llcp_msg_t *)user_data;

	if (req_msg == NULL)
	{
		DEBUG_ERR_MSG("can not get llcp_event info");

		return;
	}

	switch (req_msg->request_type)
	{
	case NET_NFC_MESSAGE_SERVICE_LLCP_DEACTIVATED :
		net_nfc_server_llcp_deactivated(NULL);
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_LISTEN :
		{
			net_nfc_request_listen_socket_t *msg =
				(net_nfc_request_listen_socket_t *)user_data;

			net_nfc_controller_llcp_incoming_cb(msg->client_socket,
				msg->result, NULL, (void *)req_msg->user_param);
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ERROR :
	case NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ACCEPTED_ERROR :
		net_nfc_controller_llcp_socket_error_cb(
			req_msg->llcp_socket,
			req_msg->result,
			NULL,
			(void *)req_msg->user_param);
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_SEND :
	case NET_NFC_MESSAGE_SERVICE_LLCP_SEND_TO :
		net_nfc_controller_llcp_sent_cb(
			req_msg->llcp_socket,
			req_msg->result,
			NULL,
			(void *)req_msg->user_param);
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE :
		{
			net_nfc_request_receive_socket_t *msg =
				(net_nfc_request_receive_socket_t *)user_data;
			data_s data = { msg->data.buffer, msg->data.length };

			net_nfc_controller_llcp_received_cb(msg->client_socket,
				msg->result,
				&data,
				(void *)req_msg->user_param);
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE_FROM :
		{
			net_nfc_request_receive_from_socket_t *msg =
				(net_nfc_request_receive_from_socket_t *)user_data;
			data_s data = { msg->data.buffer, msg->data.length };

			/* FIXME : pass sap */
			net_nfc_controller_llcp_received_cb(msg->client_socket,
				msg->result,
				&data,
				(void *)req_msg->user_param);
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT :
	case NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT_SAP :
		net_nfc_controller_llcp_connected_cb(
			req_msg->llcp_socket,
			req_msg->result,
			NULL,
			(void *)req_msg->user_param);
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_DISCONNECT :
		net_nfc_controller_llcp_disconnected_cb(
			req_msg->llcp_socket,
			req_msg->result,
			NULL,
			(void *)req_msg->user_param);
		break;

	default:
		break;
	}

	/* FIXME : should be removed when plugins would be fixed*/
	_net_nfc_util_free_mem(req_msg);
}

/* FIXME : net_nfc_dispatcher_queue_push() need to be removed */
static void controller_llcp_event_cb(void *info, void *user_context)
{
	net_nfc_request_llcp_msg_t *req_msg = info;

	if(user_context != NULL)
		req_msg->user_param = user_context;

	if (net_nfc_server_controller_async_queue_push_force(
		_controller_llcp_event_cb, req_msg) == FALSE)
	{
		DEBUG_ERR_MSG("Failed to push onto the queue");
	}
}


static void controller_hce_apdu_cb(void *info,
				void *user_context)
{
	net_nfc_request_hce_apdu_t *req = (net_nfc_request_hce_apdu_t *)info;

	g_assert(info != NULL);

	net_nfc_server_hce_apdu_received(req);
}


static void controller_init_thread_func(gpointer user_data)
{
	net_nfc_error_e result;

	if (net_nfc_controller_init(&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_init failed, [%d]", result);

		/* ADD TEMPORARY ABORT FOR DEBUG */
		abort();
//		net_nfc_manager_quit();
		return;
	}

	INFO_MSG("net_nfc_controller_init success, [%d]", result);

	if (net_nfc_controller_register_listener(controller_target_detected_cb,
						controller_se_transaction_cb,
						controller_llcp_event_cb,
						controller_hce_apdu_cb,
						&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_contorller_register_listener failed [%d]",
				result);

		/* ADD TEMPORARY ABORT FOR DEBUG */
		abort();
	}

	INFO_MSG("net_nfc_contorller_register_listener success");

	result = net_nfc_server_llcp_set_config(NULL);
	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_server_llcp_set config failed, [%d]",
			result);

		/* ADD TEMPORARY ABORT FOR DEBUG */
		abort();
	}

	INFO_MSG("net_nfc_server_llcp_set_config success");
}

#ifndef ESE_ALWAYS_ON
static void controller_deinit_thread_func(gpointer user_data)
{
	net_nfc_server_free_target_info();

	if (net_nfc_controller_deinit() == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_deinit failed");

		/* ADD TEMPORARY ABORT FOR DEBUG */
		abort();
		return;
	}

	INFO_MSG("net_nfc_controller_deinit success");

	net_nfc_manager_quit();
}
#endif

static void restart_polling_loop_thread_func(gpointer user_data)
{
	gint state = 0;
	gint lock_state = 0;
	gint lock_screen_set = 0;
	gint pm_state = 0;

	net_nfc_error_e result;

	if (vconf_get_bool(VCONFKEY_NFC_STATE, &state) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_NFC_STATE");

	if (state == 0)
		return;

	if (vconf_get_int(VCONFKEY_IDLE_LOCK_STATE, &lock_state) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_IDLE_LOCK_STATE");

	if (vconf_get_int(VCONFKEY_SETAPPL_SCREEN_LOCK_TYPE_INT, &lock_screen_set) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_SETAPPL_SCREEN_LOCK_TYPE_INT");

	if (vconf_get_int(VCONFKEY_PM_STATE, &pm_state) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_PM_STATE");

	DEBUG_SERVER_MSG("lock_screen_set:%d ,pm_state:%d,lock_state:%d",
		lock_screen_set , pm_state , lock_state);

	if (lock_screen_set == SETTING_SCREEN_LOCK_TYPE_NONE)
	{
		if (pm_state == VCONFKEY_PM_STATE_NORMAL)
		{
			if (net_nfc_controller_configure_discovery(
							NET_NFC_DISCOVERY_MODE_CONFIG,
							NET_NFC_ALL_ENABLE,
							&result) == true)
			{
				check_nfc_disable = FALSE;
				DEBUG_SERVER_MSG("polling enable");
			}

			return;
		}

		if (pm_state == VCONFKEY_PM_STATE_LCDOFF)
		{
			if (check_nfc_disable == FALSE)
			{
				if (net_nfc_controller_configure_discovery(
								NET_NFC_DISCOVERY_MODE_CONFIG,
								NET_NFC_ALL_DISABLE,
								&result) == true)
				{
					check_nfc_disable = TRUE;
					DEBUG_SERVER_MSG("polling disabled");
				}
			}
			return;
		}
	}
	else
	{      //Idle  is lock setting screen.

		if (lock_state == VCONFKEY_IDLE_LOCK || pm_state == VCONFKEY_PM_STATE_LCDOFF)
		{
			if (check_nfc_disable == FALSE)
			{
				if (net_nfc_controller_configure_discovery(
								NET_NFC_DISCOVERY_MODE_CONFIG,
								NET_NFC_ALL_DISABLE,
								&result) == true)
				{
					check_nfc_disable = TRUE;
					DEBUG_SERVER_MSG("polling disabled");
				}
			}

			return;
		}

		if (lock_state == VCONFKEY_IDLE_UNLOCK)
		{
			if (net_nfc_controller_configure_discovery(
							NET_NFC_DISCOVERY_MODE_CONFIG,
							NET_NFC_ALL_ENABLE,
							&result) == true)
			{
				check_nfc_disable = FALSE;
				DEBUG_SERVER_MSG("polling enable");
			}

			return;
		}

	}
}

static void force_polling_loop_thread_func(gpointer user_data)
{
	net_nfc_error_e result;

	/* keep_SE_select_value */
	result = net_nfc_server_se_apply_se_current_policy();

	if (net_nfc_controller_configure_discovery(
				NET_NFC_DISCOVERY_MODE_START,
				NET_NFC_ALL_ENABLE,
				&result) == true)
	{
		/* vconf on */
		if (vconf_set_bool(VCONFKEY_NFC_STATE, TRUE) != 0)
		{
			DEBUG_ERR_MSG("vconf_set_bool is failed");

			result = NET_NFC_OPERATION_FAIL;
		}
		check_nfc_disable = FALSE;
		DEBUG_SERVER_MSG("force polling is success & set nfc state true");
	}
	return;
}

gboolean net_nfc_server_controller_thread_init(void)
{
	GError *error = NULL;

	controller_async_queue = g_async_queue_new_full(
					controller_async_queue_free_func);

	controller_thread = g_thread_try_new("controller_thread",
					controller_thread_func,
					NULL,
					&error);

	if (controller_thread == NULL)
	{
		DEBUG_ERR_MSG("can not create controller thread: %s",
				error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

void net_nfc_server_controller_thread_deinit(void)
{
	if (net_nfc_server_controller_async_queue_push_force(
					controller_thread_deinit_thread_func,
					NULL)==FALSE)
	{
		DEBUG_ERR_MSG("Failed to push onto the queue");
	}

	g_thread_join(controller_thread);
	controller_thread = NULL;

	g_async_queue_unref(controller_async_queue);
	controller_async_queue = NULL;
}

void net_nfc_server_controller_init(void)
{
	if (net_nfc_server_controller_async_queue_push_force(
		controller_init_thread_func, NULL) == FALSE)
	{
		DEBUG_ERR_MSG("Failed to push onto the queue");
	}
}

inline static gboolean _timeout_cb(gpointer data)
{
	g_assert(data != NULL);

	g_async_queue_push(controller_async_queue, data);

	return false;
}

inline static void _push_to_queue(guint msec, bool blocking,
	net_nfc_server_controller_func func,
	gpointer user_data)
{
	ControllerFuncData *func_data;

	func_data = g_new0(ControllerFuncData, 1);
	func_data->func = func;
	func_data->data = user_data;
	func_data->blocking = blocking;

	if (__builtin_expect(msec == 0, true)) {
		g_async_queue_push(controller_async_queue, func_data);
	} else {
		g_timeout_add(msec, _timeout_cb, func_data);
	}
}

#ifndef ESE_ALWAYS_ON
void net_nfc_server_controller_deinit(void)
{
	if (controller_async_queue == NULL)
	{
		DEBUG_ERR_MSG("controller_async_queue is not initialized");

		return;
	}

	/* block all other message because daemon will be shutting down */
	controller_block = 9999;

	_push_to_queue(0, false, controller_deinit_thread_func, NULL);
}
#endif

gboolean net_nfc_server_controller_is_blocked()
{
	return (controller_block > 0);
}

gboolean net_nfc_server_controller_async_queue_delayed_push_force(
	guint msec, net_nfc_server_controller_func func, gpointer user_data)
{
	if (controller_async_queue == NULL)
	{
		DEBUG_ERR_MSG("controller_async_queue is not initialized");

		return FALSE;
	}

	_push_to_queue(msec, false, func, user_data);

	return TRUE;
}

gboolean net_nfc_server_controller_async_queue_push_force(
	net_nfc_server_controller_func func, gpointer user_data)
{
	return net_nfc_server_controller_async_queue_delayed_push_force(0,
		func, user_data);
}

gboolean net_nfc_server_controller_async_queue_push(
					net_nfc_server_controller_func func,
					gpointer user_data)
{
	if (net_nfc_server_controller_is_blocked() == true) {
		return FALSE;
	}

	return net_nfc_server_controller_async_queue_push_force(func,
		user_data);
}

gboolean net_nfc_server_controller_async_queue_push_and_block(
	net_nfc_server_controller_func func, gpointer user_data)
{
	if (controller_async_queue == NULL)
	{
		DEBUG_ERR_MSG("controller_async_queue is not initialized");

		return FALSE;
	}

	if (net_nfc_server_controller_is_blocked() == true) {
		return FALSE;
	}

	/* block pushing message until complete previous blocking message */
	controller_block++;

	_push_to_queue(0, true, func, user_data);

	return TRUE;
}

void net_nfc_server_controller_run_dispatch_loop()
{
	if (controller_async_queue == NULL)
	{
		return;
	}

	WARN_MSG("START DISPATCH LOOP");

	controller_dispath_running = TRUE;
	while (controller_is_running && controller_dispath_running)
	{
		ControllerFuncData *func_data;

		func_data = g_async_queue_try_pop(controller_async_queue);
		if (func_data != NULL) {
			WARN_MSG("DISPATCHED!!!");
			if (func_data->func)
				func_data->func(func_data->data);

			controller_async_queue_free_func(func_data);
		} else {
			g_usleep(10);
		}
	}

	WARN_MSG("STOP DISPATCH LOOP");
}

void net_nfc_server_controller_quit_dispatch_loop()
{
	controller_dispath_running = FALSE;
}

void net_nfc_server_restart_polling_loop(void)
{
	if (net_nfc_server_controller_async_queue_push_force(
					restart_polling_loop_thread_func,
					NULL) == FALSE)
	{
		DEBUG_ERR_MSG("Failed to push onto the queue");
	}
}

void net_nfc_server_force_polling_loop(void)
{
	if (net_nfc_server_controller_async_queue_push_force(
					force_polling_loop_thread_func,
					NULL) == FALSE)
	{
		DEBUG_ERR_MSG("Failed to push onto the queue");
	}
}

void net_nfc_server_set_state(guint32 state)
{
	if (state == NET_NFC_SERVER_IDLE)
		server_state &= NET_NFC_SERVER_IDLE;
	else
		server_state |= state;
}

void net_nfc_server_unset_state(guint32 state)
{
	server_state &= ~state;
}

guint32 net_nfc_server_get_state(void)
{
	return server_state;
}
