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

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_manager_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_process_snep.h"
#include "net_nfc_server_p2p.h"


typedef struct _P2pSendData P2pSendData;

struct _P2pSendData
{
	NetNfcGDbusP2p *p2p;
	GDBusMethodInvocation *invocation;
	gint32 type;
	guint32 p2p_handle;
	data_s data;
};

static void p2p_send_data_thread_func(gpointer user_data);

static gboolean p2p_handle_send(NetNfcGDbusP2p *p2p,
				GDBusMethodInvocation *invocation,
				gint32 arg_type,
				GVariant *arg_data,
				guint32 handle,
				GVariant *smack_privilege,
				gpointer user_data);

static NetNfcGDbusP2p *p2p_skeleton = NULL;

static void p2p_send_data_thread_func(gpointer user_data)
{
	P2pSendData *p2p_data = (P2pSendData *)user_data;
	net_nfc_error_e result;
	net_nfc_target_handle_s *handle;

	g_assert(p2p_data != NULL);
	g_assert(p2p_data->p2p != NULL);
	g_assert(p2p_data->invocation != NULL);

	handle = GUINT_TO_POINTER(p2p_data->p2p_handle);

	result = net_nfc_server_snep_default_client_start(
		handle,
		SNEP_REQ_PUT,
		&p2p_data->data,
		-1,
		p2p_data);
	if (result != NET_NFC_OK)
	{
		net_nfc_gdbus_p2p_complete_send(p2p_data->p2p,
			p2p_data->invocation,
			(gint)result);

		net_nfc_util_clear_data(&p2p_data->data);

		g_object_unref(p2p_data->invocation);
		g_object_unref(p2p_data->p2p);

		g_free(p2p_data);
	}
}

static gboolean p2p_handle_send(NetNfcGDbusP2p *p2p,
				GDBusMethodInvocation *invocation,
				gint32 arg_type,
				GVariant *arg_data,
				guint32 handle,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	P2pSendData *data = NULL;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::p2p",
		"w") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_new0(P2pSendData, 1);
	if(data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->p2p = g_object_ref(p2p);
	data->invocation = g_object_ref(invocation);
	data->type = arg_type;
	data->p2p_handle = handle;
	net_nfc_util_gdbus_variant_to_data_s(arg_data, &data->data);

	if (net_nfc_server_controller_async_queue_push(
		p2p_send_data_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		net_nfc_util_clear_data(&data->data);

		g_object_unref(data->invocation);
		g_object_unref(data->p2p);

		g_free(data);
	}

	net_nfc_gdbus_p2p_complete_send(p2p, invocation, result);

	return TRUE;
}


gboolean net_nfc_server_p2p_init(GDBusConnection *connection)
{
	gboolean result;
	GError *error = NULL;

	if (p2p_skeleton)
		net_nfc_server_p2p_deinit();

	p2p_skeleton = net_nfc_gdbus_p2p_skeleton_new();

	g_signal_connect(p2p_skeleton,
			"handle-send",
			G_CALLBACK(p2p_handle_send),
			NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(p2p_skeleton),
		connection,
		"/org/tizen/NetNfcService/P2p",
		&error);
	if (result == FALSE)
	{
		g_error_free(error);

		net_nfc_server_p2p_deinit();
	}

	return result;
}

void net_nfc_server_p2p_deinit(void)
{
	if (p2p_skeleton)
	{
		g_object_unref(p2p_skeleton);
		p2p_skeleton = NULL;
	}
}

void net_nfc_server_p2p_detached(gpointer user_data)
{
	INFO_MSG("====== p2p target detached ======");

	/* release target information */
	net_nfc_server_free_target_info();

	if (p2p_skeleton != NULL)
	{
		net_nfc_gdbus_p2p_emit_detached(p2p_skeleton);
	}
}

void net_nfc_server_p2p_discovered(net_nfc_target_handle_h handle)
{
	INFO_MSG("====== p2p target discovered ======");

	if (p2p_skeleton == NULL)
	{
		DEBUG_ERR_MSG("p2p_skeleton is not initialized");

		return;
	}

	net_nfc_gdbus_p2p_emit_discovered(p2p_skeleton,
					GPOINTER_TO_UINT(handle));

	net_nfc_manager_util_play_sound(NET_NFC_TASK_START);
}

void net_nfc_server_p2p_received(data_h user_data)
{
	GVariant *arg_data;

	if (p2p_skeleton == NULL)
	{
		DEBUG_ERR_MSG("p2p_skeleton is not initialized");

		return;
	}

	arg_data = net_nfc_util_gdbus_data_to_variant((data_s *)user_data);

	net_nfc_gdbus_p2p_emit_received(p2p_skeleton, arg_data);

	net_nfc_manager_util_play_sound(NET_NFC_TASK_END);
}

void net_nfc_server_p2p_data_sent(net_nfc_error_e result,
				gpointer user_data)
{
	P2pSendData *data = (P2pSendData *)user_data;

	g_assert(data != NULL);
	g_assert(data->p2p != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_gdbus_p2p_complete_send(data->p2p,
		data->invocation,
		(gint)result);

	net_nfc_manager_util_play_sound(NET_NFC_TASK_END);

	net_nfc_util_clear_data(&data->data);

	g_object_unref(data->invocation);
	g_object_unref(data->p2p);

	g_free(data);
}
