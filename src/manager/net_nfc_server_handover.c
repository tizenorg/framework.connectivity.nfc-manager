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
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_handover.h"
#include "net_nfc_server_process_handover.h"

static NetNfcGDbusHandover *handover_skeleton = NULL;

static void handover_request_thread_func(gpointer user_data);

static gboolean handover_handle_request(NetNfcGDbusHandover *hdover,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				gint32 arg_type,
				GVariant *smack_privilege,
				gpointer user_data);

static void handover_request_thread_func(gpointer user_data)
{
	HandoverRequestData *handover_data = (HandoverRequestData *)user_data;
	net_nfc_error_e result;

	g_assert(handover_data != NULL);
	g_assert(handover_data->handoverobj != NULL);
	g_assert(handover_data->invocation != NULL);

	result = net_nfc_server_handover_default_client_start(
		GUINT_TO_POINTER(handover_data->handle),
		(void *)handover_data);
	if (result != NET_NFC_OK)
	{
		net_nfc_gdbus_handover_complete_request(
			handover_data->handoverobj,
			handover_data->invocation,
			result,
			NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN,
			net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

		g_object_unref(handover_data->invocation);
		g_object_unref(handover_data->handoverobj);

		g_free(handover_data);
	}
}

static gboolean handover_handle_request(NetNfcGDbusHandover *hdover,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				gint32 arg_type,
				GVariant *smack_privilege,
				gpointer user_data)
{
	HandoverRequestData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(HandoverRequestData,1);
	if(data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->handoverobj = g_object_ref(hdover);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->type = arg_type;

	if (net_nfc_server_controller_async_queue_push(
		handover_request_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->handoverobj);

		g_free(data);
	}

	net_nfc_gdbus_handover_complete_request(
		hdover,
		invocation,
		result,
		NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN,
		net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

net_nfc_error_e net_nfc_server_handover_emit_started_signal(
	net_nfc_target_handle_s *handle, data_s *message)
{
	if (handover_skeleton == NULL) {
		return NET_NFC_INVALID_STATE;
	}

	net_nfc_gdbus_handover_emit_started(handover_skeleton,
		net_nfc_util_gdbus_data_to_variant(message));

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_server_handover_emit_finished_signal(
	net_nfc_error_e result,
	net_nfc_conn_handover_carrier_type_e type,
	data_s *address, data_s *message)
{
	if (handover_skeleton == NULL) {
		return NET_NFC_INVALID_STATE;
	}

	net_nfc_gdbus_handover_emit_finished(handover_skeleton,
		result,
		type,
		net_nfc_util_gdbus_data_to_variant(address),
		net_nfc_util_gdbus_data_to_variant(message));

	return NET_NFC_OK;
}

gboolean net_nfc_server_handover_init(GDBusConnection *connection)
{
	GError *error = NULL;

	if (handover_skeleton)
		g_object_unref(handover_skeleton);

	handover_skeleton = net_nfc_gdbus_handover_skeleton_new();

	g_signal_connect(handover_skeleton,
			"handle-request",
			G_CALLBACK(handover_handle_request),
			NULL);

	if (g_dbus_interface_skeleton_export(
				G_DBUS_INTERFACE_SKELETON(handover_skeleton),
				connection,
				"/org/tizen/NetNfcService/Handover",
				&error) == FALSE)
	{
		g_error_free(error);

		g_object_unref(handover_skeleton);
		handover_skeleton = NULL;

		return FALSE;
	}

	return TRUE;
}

void net_nfc_server_handover_deinit(void)
{
	if (handover_skeleton)
	{
		g_object_unref(handover_skeleton);
		handover_skeleton = NULL;
	}
}
