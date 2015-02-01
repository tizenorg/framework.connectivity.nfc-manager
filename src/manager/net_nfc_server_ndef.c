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

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_gdbus.h"

#include "net_nfc_server_common.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_ndef.h"

typedef struct _ReadData ReadData;

struct _ReadData
{
	NetNfcGDbusNdef *ndef;
	GDBusMethodInvocation *invocation;
	guint32 handle;
};

typedef struct _WriteData WriteData;

struct _WriteData
{
	NetNfcGDbusNdef *ndef;
	GDBusMethodInvocation *invocation;
	guint32 handle;
	data_s data;
};

typedef struct _MakeReadOnlyData MakeReadOnlyData;

struct _MakeReadOnlyData
{
	NetNfcGDbusNdef *ndef;
	GDBusMethodInvocation *invocation;
	guint32 handle;
};

typedef struct _FormatData FormatData;

struct _FormatData
{
	NetNfcGDbusNdef *ndef;
	GDBusMethodInvocation *invocation;
	guint32 handle;
	data_s key;
};


static NetNfcGDbusNdef *ndef_skeleton = NULL;

static void ndef_read_thread_func(gpointer user_data);

static void ndef_write_thread_func(gpointer user_data);

static void ndef_make_read_only_thread_func(gpointer user_data);

static void ndef_format_thread_func(gpointer user_data);

/* methods */
static gboolean ndef_handle_read(NetNfcGDbusNdef *ndef,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean ndef_handle_write(NetNfcGDbusNdef *ndef,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				GVariant *arg_data,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean ndef_handle_make_read_only(NetNfcGDbusNdef *ndef,
					GDBusMethodInvocation *invocation,
					guint32 arg_handle,
					GVariant *smack_privilege,
					gpointer user_data);

static gboolean ndef_handle_format(NetNfcGDbusNdef *ndef,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				GVariant *arg_key,
				GVariant *smack_privilege,
				gpointer user_data);


static void ndef_read_thread_func(gpointer user_data)
{
	ReadData *data = user_data;

	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;
	data_s *read_data = NULL;
	GVariant *data_variant;

	g_assert(data != NULL);
	g_assert(data->ndef != NULL);
	g_assert(data->invocation != NULL);

	handle = GUINT_TO_POINTER(data->handle);

	if (net_nfc_server_target_connected(handle) == true) {
		net_nfc_controller_read_ndef(handle, &read_data, &result);
	} else {
		result = NET_NFC_TARGET_IS_MOVED_AWAY;
	}

	data_variant = net_nfc_util_gdbus_data_to_variant(read_data);

	net_nfc_gdbus_ndef_complete_read(data->ndef,
					data->invocation,
					(gint)result,
					data_variant);

	if (read_data) {
		net_nfc_util_free_data(read_data);
	}

	g_object_unref(data->invocation);
	g_object_unref(data->ndef);

	g_free(data);
}

static void ndef_write_thread_func(gpointer user_data)
{
	WriteData *data = user_data;

	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->ndef != NULL);
	g_assert(data->invocation != NULL);

	handle = GUINT_TO_POINTER(data->handle);

	if (net_nfc_server_target_connected(handle) == true) {
		net_nfc_controller_write_ndef(handle, &data->data, &result);
	} else {
		result = NET_NFC_TARGET_IS_MOVED_AWAY;
	}

	net_nfc_gdbus_ndef_complete_write(data->ndef,
		data->invocation,
		(gint)result);

	net_nfc_util_clear_data(&data->data);

	g_object_unref(data->invocation);
	g_object_unref(data->ndef);

	g_free(data);
}

static void ndef_make_read_only_thread_func(gpointer user_data)
{
	MakeReadOnlyData *data = user_data;

	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->ndef != NULL);
	g_assert(data->invocation != NULL);

	handle = GUINT_TO_POINTER(data->handle);

	if (net_nfc_server_target_connected(handle) == true) {
		net_nfc_controller_make_read_only_ndef(handle, &result);
	} else {
		result = NET_NFC_TARGET_IS_MOVED_AWAY;
	}

	net_nfc_gdbus_ndef_complete_make_read_only(data->ndef,
		data->invocation,
		(gint)result);

	g_object_unref(data->invocation);
	g_object_unref(data->ndef);

	g_free(data);
}

static void ndef_format_thread_func(gpointer user_data)
{
	FormatData *data = user_data;

	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->ndef != NULL);
	g_assert(data->invocation != NULL);

	handle = GUINT_TO_POINTER(data->handle);

	if (net_nfc_server_target_connected(handle) == true) {
		net_nfc_controller_format_ndef(handle, &data->key, &result);
	} else {
		result = NET_NFC_TARGET_IS_MOVED_AWAY;
	}

	net_nfc_gdbus_ndef_complete_format(data->ndef,
		data->invocation,
		(gint)result);

	net_nfc_util_clear_data(&data->key);

	g_object_unref(data->invocation);
	g_object_unref(data->ndef);

	g_free(data);
}

static gboolean ndef_handle_read(NetNfcGDbusNdef *ndef,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				GVariant *smack_privilege,
				gpointer user_data)
{
	ReadData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::tag",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_new0(ReadData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->ndef = g_object_ref(ndef);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;

	if (net_nfc_server_controller_async_queue_push(
		ndef_read_thread_func, data) == FALSE)
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
		g_object_unref(data->ndef);

		g_free(data);
	}

	net_nfc_gdbus_ndef_complete_read(ndef, invocation, result,
		net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static gboolean ndef_handle_write(NetNfcGDbusNdef *ndef,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				GVariant *arg_data,
				GVariant *smack_privilege,
				gpointer user_data)
{
	WriteData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::tag",
		"w") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_new0(WriteData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->ndef = g_object_ref(ndef);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;

	net_nfc_util_gdbus_variant_to_data_s(arg_data, &data->data);

	if (net_nfc_server_controller_async_queue_push(
		ndef_write_thread_func, data) == FALSE)
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
		g_object_unref(data->ndef);

		g_free(data);
	}

	net_nfc_gdbus_ndef_complete_write(ndef, invocation, result);

	return TRUE;
}

static gboolean ndef_handle_make_read_only(NetNfcGDbusNdef *ndef,
					GDBusMethodInvocation *invocation,
					guint32 arg_handle,
					GVariant *smack_privilege,
					gpointer user_data)
{
	MakeReadOnlyData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::tag",
		"w") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_new0(MakeReadOnlyData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->ndef = g_object_ref(ndef);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;

	if (net_nfc_server_controller_async_queue_push(
		ndef_make_read_only_thread_func, data) == FALSE)
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
		g_object_unref(data->ndef);

		g_free(data);
	}

	net_nfc_gdbus_ndef_complete_make_read_only(ndef, invocation, result);

	return TRUE;
}

static gboolean ndef_handle_format(NetNfcGDbusNdef *ndef,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				GVariant *arg_key,
				GVariant *smack_privilege,
				gpointer user_data)
{
	FormatData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::tag",
		"w") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_new0(FormatData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->ndef = g_object_ref(ndef);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	net_nfc_util_gdbus_variant_to_data_s(arg_key, &data->key);

	if (net_nfc_server_controller_async_queue_push(
		ndef_format_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		net_nfc_util_clear_data(&data->key);

		g_object_unref(data->invocation);
		g_object_unref(data->ndef);

		g_free(data);
	}

	net_nfc_gdbus_ndef_complete_format(ndef, invocation, result);

	return TRUE;
}

gboolean net_nfc_server_ndef_init(GDBusConnection *connection)
{
	gboolean result;
	GError *error = NULL;

	if (ndef_skeleton)
		net_nfc_server_ndef_deinit();

	ndef_skeleton = net_nfc_gdbus_ndef_skeleton_new();

	g_signal_connect(ndef_skeleton,
			"handle-read",
			G_CALLBACK(ndef_handle_read),
			NULL);

	g_signal_connect(ndef_skeleton,
			"handle-write",
			G_CALLBACK(ndef_handle_write),
			NULL);

	g_signal_connect(ndef_skeleton,
			"handle-make-read-only",
			G_CALLBACK(ndef_handle_make_read_only),
			NULL);

	g_signal_connect(ndef_skeleton,
			"handle-format",
			G_CALLBACK(ndef_handle_format),
			NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(ndef_skeleton),
		connection,
		"/org/tizen/NetNfcService/Ndef",
		&error);
	if (result == FALSE)
	{
		g_error_free(error);

		net_nfc_server_ndef_deinit();
	}

	return TRUE;
}

void net_nfc_server_ndef_deinit(void)
{
	if (ndef_skeleton)
	{
		g_object_unref(ndef_skeleton);
		ndef_skeleton = NULL;
	}
}
