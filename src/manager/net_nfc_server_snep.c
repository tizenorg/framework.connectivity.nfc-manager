/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glib.h>

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_llcp.h"
#include "net_nfc_server_snep.h"
#include "net_nfc_server_process_snep.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_server_context_internal.h"

/* declaration */
static gboolean _handle_start_server(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	guint arg_sap,
	const gchar *arg_san,
	guint arg_user_data,
	GVariant *arg_privilege);

static gboolean _handle_start_client(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	guint arg_sap,
	const gchar *arg_san,
	guint arg_user_data,
	GVariant *arg_privilege);

static gboolean _handle_client_send_request(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_snep_handle,
	guint arg_type,
	GVariant *arg_ndef_msg,
	GVariant *arg_privilege);

static gboolean _handle_stop_snep(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	guint arg_snep_handle,
	GVariant *arg_privilege);

static void snep_server_start_thread_func(gpointer user_data);

static void snep_client_start_thread_func(gpointer user_data);

static void snep_client_send_request_thread_func(gpointer user_data);

static void snep_stop_service_thread_func(gpointer user_data);

/* definition */
static NetNfcGDbusSnep *snep_skeleton =  NULL;

static void _emit_snep_event_signal(GVariant *parameter,
	net_nfc_snep_handle_h handle,
	net_nfc_error_e result,
	uint32_t type,
	data_s *data)
{
	GDBusConnection *connection;
	char *client_id;
	void *user_data;
	GVariant *arg_data;
	GError *error = NULL;

	g_variant_get(parameter, "(usu)",
		(guint *)&connection,
		&client_id,
		(guint *)&user_data);

	arg_data = net_nfc_util_gdbus_data_to_variant(data);

	if (g_dbus_connection_emit_signal(
		connection,
		client_id,
		"/org/tizen/NetNfcService/Snep",
		"org.tizen.NetNfcService.Snep",
		"SnepEvent",
		g_variant_new("(uui@a(y)u)",
			GPOINTER_TO_UINT(handle),
			type,
			(gint)result,
			arg_data,
			GPOINTER_TO_UINT(user_data)),
		&error) == false) {
		if (error != NULL && error->message != NULL) {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed : %s", error->message);
		} else {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed");
		}
	}

	g_free(client_id);
}

static net_nfc_error_e _snep_server_cb(net_nfc_snep_handle_h handle,
	net_nfc_error_e result,
	uint32_t type,
	data_s *data,
	void *user_param)
{
	GVariant *parameter = (GVariant *)user_param;

	data_s *temp = data;

	DEBUG_SERVER_MSG("type [%d], result [%d], data [%p], user_param [%p]",
			type, result, data, user_param);

	switch (type)
	{
	case SNEP_REQ_GET :
		{
			uint32_t max_len = 0;

			net_nfc_server_snep_parse_get_request(data, &max_len,
				temp);
		}
		break;

	case SNEP_REQ_PUT :
			break;

	default :
		DEBUG_ERR_MSG("error [%d]", result);
		break;
	}

	if (result < NET_NFC_OK) {
		type = NET_NFC_LLCP_STOP;
	}

	_emit_snep_event_signal(parameter, handle,
		result, type, data);

	if (type == NET_NFC_LLCP_STOP) {

		GDBusConnection *connection;
		char *client_id;
		void *user_data;

		g_variant_get(parameter, "(usu)",
			(guint *)&connection,
			&client_id,
			(guint *)&user_data);

		g_object_unref(connection);
		g_variant_unref(parameter);
	}

	return result;
}

static void snep_server_start_thread_func(gpointer user_data)
{
	NetNfcGDbusSnep *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s *arg_handle;
	guint arg_sap;
	gchar *arg_san;
	void *arg_user_data;
	net_nfc_error_e result;

	GVariant *parameter;
	GDBusConnection *connection;

	if (user_data == NULL)
	{
		DEBUG_ERR_MSG("cannot get SNEP client data");

		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uuuusu)",
		(guint *)&object,
		(guint *)&invocation,
		(guint *)&arg_handle,
		&arg_sap,
		&arg_san,
		(guint *)&arg_user_data);

	g_assert(object != NULL);
	g_assert(invocation != NULL);

	connection = g_dbus_method_invocation_get_connection(invocation);

	parameter = g_variant_new("(usu)",
		GPOINTER_TO_UINT(g_object_ref(connection)),
		g_dbus_method_invocation_get_sender(invocation),
		GPOINTER_TO_UINT(arg_user_data));
	if (parameter != NULL) {
		result = net_nfc_server_snep_server(arg_handle,
			arg_san,
			arg_sap,
			_snep_server_cb,
			parameter);
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_server_snep_server failed, [%d]",
					result);
			g_object_unref(connection);

			g_variant_unref(parameter);
		}
	} else {
		DEBUG_ERR_MSG("g_variant_new failed");

		g_object_unref(connection);

		result = NET_NFC_ALLOC_FAIL;
	}

	net_nfc_gdbus_snep_complete_server_start(object, invocation, result);

	g_free(arg_san);

	g_variant_unref(user_data);
}

static gboolean _handle_start_server(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	guint arg_sap,
	const gchar *arg_san,
	guint arg_user_data,
	GVariant *arg_privilege)
{
	GVariant *parameter = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		arg_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	parameter = g_variant_new("(uuuusu)",
		GPOINTER_TO_UINT(g_object_ref(object)),
		GPOINTER_TO_UINT(g_object_ref(invocation)),
		arg_handle,
		arg_sap,
		arg_san,
		arg_user_data);
	if (parameter == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	if (net_nfc_server_controller_async_queue_push(
		snep_server_start_thread_func, parameter) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (parameter != NULL) {
		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);
	}

	net_nfc_gdbus_snep_complete_server_start(object, invocation, result);

	return TRUE;
}

static net_nfc_error_e _snep_start_client_cb(
	net_nfc_snep_handle_h handle,
	net_nfc_error_e result,
	uint32_t type,
	data_s *data,
	void *user_param)
{
	GVariant *parameter = (GVariant *)user_param;

	DEBUG_SERVER_MSG("type [%d], result [%d], data [%p], user_param [%p]",
			type, result, data, user_param);

	_emit_snep_event_signal(parameter, handle, result, type, data);

	if (type == NET_NFC_LLCP_STOP) {
		g_variant_unref(parameter);
	}

	return result;
}

static void snep_client_start_thread_func(gpointer user_data)
{
	NetNfcGDbusSnep *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s *arg_handle;
	guint arg_sap;
	gchar *arg_san;
	void *arg_user_data;
	net_nfc_error_e result;

	GVariant *parameter;
	GDBusConnection *connection;

	if (user_data == NULL)
	{
		DEBUG_ERR_MSG("cannot get SNEP client data");

		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uuuusu)",
		(guint *)&object,
		(guint *)&invocation,
		(guint *)&arg_handle,
		&arg_sap,
		&arg_san,
		(guint *)&arg_user_data);

	g_assert(object != NULL);
	g_assert(invocation != NULL);

	connection = g_dbus_method_invocation_get_connection(invocation);

	parameter = g_variant_new("(usu)",
		GPOINTER_TO_UINT(g_object_ref(connection)),
		g_dbus_method_invocation_get_sender(invocation),
		GPOINTER_TO_UINT(arg_user_data));
	if (parameter != NULL) {
		result = net_nfc_server_snep_client(arg_handle,
			arg_san,
			arg_sap,
			_snep_start_client_cb,
			parameter);
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_server_snep_client failed, [%d]",
					result);
			g_object_unref(connection);

			g_variant_unref(parameter);
		}
	} else {
		DEBUG_ERR_MSG("g_variant_new failed");

		g_object_unref(connection);

		result = NET_NFC_ALLOC_FAIL;
	}

	net_nfc_gdbus_snep_complete_client_start(object, invocation, result);

	g_free(arg_san);

	g_variant_unref(user_data);
}

static gboolean _handle_start_client(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	guint arg_sap,
	const gchar *arg_san,
	guint arg_user_data,
	GVariant *arg_privilege)
{
	GVariant *parameter = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		arg_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	parameter = g_variant_new("(uuuusu)",
		GPOINTER_TO_UINT(g_object_ref(object)),
		GPOINTER_TO_UINT(g_object_ref(invocation)),
		arg_handle,
		arg_sap,
		arg_san,
		arg_user_data);
	if (parameter == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	if (net_nfc_server_controller_async_queue_push(
		snep_client_start_thread_func, parameter) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (parameter != NULL) {
		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);
	}

	net_nfc_gdbus_snep_complete_client_start(object, invocation, result);

	return TRUE;
}

static net_nfc_error_e _snep_client_request_cb(
	net_nfc_snep_handle_h handle,
	net_nfc_error_e result,
	net_nfc_snep_type_t type,
	data_s *data,
	void *user_param)
{
	GVariant *parameter = (GVariant *)user_param;

	DEBUG_SERVER_MSG("type [%d], result [%d], data [%p], user_param [%p]",
		type, result, data, user_param);

	if (parameter != NULL) {
		NetNfcGDbusSnep *object;
		GDBusMethodInvocation *invocation;
		net_nfc_snep_handle_h arg_snep_handle;
		net_nfc_snep_type_t arg_type;
		GVariant *arg_ndef_msg;
		GVariant *arg_data = NULL;

		g_variant_get(parameter,
			"(uuuu@a(y))",
			(guint *)&object,
			(guint *)&invocation,
			(guint *)&arg_snep_handle,
			(guint *)&arg_type,
			&arg_ndef_msg);

		if (data != NULL && data->buffer != NULL && data->length > 0) {
			arg_data = net_nfc_util_gdbus_data_to_variant(data);
		} else {
			arg_data = net_nfc_util_gdbus_buffer_to_variant(NULL, 0);
		}

		net_nfc_gdbus_snep_complete_client_request(object,
			invocation,
			result,
			type,
			arg_data);

		g_variant_unref(arg_ndef_msg);

		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NULL_PARAMETER;
	}

	return result;
}

static void snep_client_send_request_thread_func(gpointer user_data)
{
	NetNfcGDbusSnep *object;
	GDBusMethodInvocation *invocation;
	net_nfc_snep_handle_h arg_snep_handle;
	net_nfc_snep_type_t arg_type;
	GVariant *arg_ndef_msg;
	data_s data = { NULL, };
	net_nfc_error_e result;

	if (user_data == NULL)
	{
		DEBUG_ERR_MSG("cannot get SNEP client data");

		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uuuu@a(y))",
		(guint *)&object,
		(guint *)&invocation,
		(guint *)&arg_snep_handle,
		(guint *)&arg_type,
		&arg_ndef_msg);

	g_assert(object != NULL);
	g_assert(invocation != NULL);

	net_nfc_util_gdbus_variant_to_data_s(arg_ndef_msg, &data);

	result = net_nfc_server_snep_client_request(arg_snep_handle,
		arg_type,
		&data,
		_snep_client_request_cb,
		user_data);
	if (result != NET_NFC_OK)
	{
		GVariant *resp;

		DEBUG_ERR_MSG("net_nfc_server_snep_client_request  "
			"failed, [%d]",result);

		resp = net_nfc_util_gdbus_buffer_to_variant(NULL, 0);

		net_nfc_gdbus_snep_complete_client_request(object,
			invocation, result, NET_NFC_LLCP_STOP, resp);

		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(user_data);
	}

	net_nfc_util_clear_data(&data);

	g_variant_unref(arg_ndef_msg);
}

static gboolean _handle_client_send_request(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_snep_handle,
	guint arg_type,
	GVariant *arg_ndef_msg,
	GVariant *arg_privilege)
{
	GVariant *parameter = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		arg_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	parameter = g_variant_new("(uuuu@a(y))",
		GPOINTER_TO_UINT(g_object_ref(object)),
		GPOINTER_TO_UINT(g_object_ref(invocation)),
		arg_snep_handle,
		arg_type,
		arg_ndef_msg);

	if (parameter == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	if (net_nfc_server_controller_async_queue_push(
		snep_client_send_request_thread_func, parameter) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (parameter != NULL) {
		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);
	}

	net_nfc_gdbus_snep_complete_client_request(object,
		invocation,
		result,
		NET_NFC_LLCP_STOP,
		net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static void snep_stop_service_thread_func(gpointer user_data)
{
	NetNfcGDbusSnep *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s *handle;
	net_nfc_snep_handle_h snep_handle;

	if (user_data == NULL)
	{
		DEBUG_ERR_MSG("cannot get SNEP client data");

		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uuuu)",
		(guint *)&object,
		(guint *)&invocation,
		(guint *)&handle,
		(guint *)&snep_handle);

	g_assert(object != NULL);
	g_assert(invocation != NULL);

	/* TODO :
	g_dbus_method_invocation_return_dbus_error(
		invocation,
		"org.tizen.NetNfcService.Snep.DataError",
		"Cannot stop SNEP service");
	*/

	net_nfc_gdbus_snep_complete_stop_snep(object,
		invocation,
		NET_NFC_OK);

	g_object_unref(invocation);
	g_object_unref(object);

	g_variant_unref(user_data);
}

static gboolean _handle_stop_snep(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	guint arg_snep_handle,
	GVariant *arg_privilege)
{
	GVariant *parameter = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		arg_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	parameter = g_variant_new("(uuuu)",
		GPOINTER_TO_UINT(g_object_ref(object)),
		GPOINTER_TO_UINT(g_object_ref(invocation)),
		arg_handle,
		arg_snep_handle);
	if (parameter == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	if (net_nfc_server_controller_async_queue_push(
		snep_stop_service_thread_func, parameter) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (parameter != NULL) {
		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);
	}

	net_nfc_gdbus_snep_complete_stop_snep(object,
		invocation,
		result);

	return TRUE;
}

static void _snep_activate_cb(int event, net_nfc_target_handle_s *handle,
	uint32_t sap, const char *san, void *user_param)
{
	GVariant *parameter = (GVariant *)user_param;
	net_nfc_error_e result = NET_NFC_OK;

	DEBUG_SERVER_MSG("event [%d], handle [%p], sap [%d], san [%s]",
		event, handle, sap, san);

	if (event == NET_NFC_LLCP_START) {
		GDBusConnection *connection;
		GVariant *param = NULL;
		char *client_id;
		void *user_data;

		/* start server */
		g_variant_get(parameter, "(usu)",
			(guint *)&connection,
			&client_id,
			(guint *)&user_data);

		param = g_variant_new("(usu)",
			GPOINTER_TO_UINT(g_object_ref(connection)),
			client_id,
			GPOINTER_TO_UINT(user_data));

		g_free(client_id);

		result = net_nfc_server_snep_server(handle, (char *)san, sap,
			_snep_server_cb, param);
		if (result == NET_NFC_OK) {
			_emit_snep_event_signal(parameter, handle,
				result, event, NULL);
		} else {
			DEBUG_ERR_MSG("net_nfc_server_snep_server failed, [%d]",
				result);

			g_variant_unref(param);
		}
	} else {
		_emit_snep_event_signal(parameter, handle,
			result, NET_NFC_LLCP_UNREGISTERED, NULL);

		/* unregister server */
		g_variant_unref(parameter);
	}
}

static void snep_register_server_thread_func(gpointer user_data)
{
	NetNfcGDbusSnep *object;
	GDBusMethodInvocation *invocation;
	guint arg_sap;
	gchar *arg_san;
	guint arg_user_data;

	net_nfc_error_e result;
	GVariant *parameter = NULL;
	GDBusConnection *connection;

	g_assert(user_data != NULL);

	g_variant_get((GVariant *)user_data,
		"(uuusu)",
		(guint *)&object,
		(guint *)&invocation,
		&arg_sap,
		&arg_san,
		&arg_user_data);

	g_assert(object != NULL);
	g_assert(invocation != NULL);

	connection = g_dbus_method_invocation_get_connection(invocation);

	parameter = g_variant_new("(usu)",
		GPOINTER_TO_UINT(g_object_ref(connection)),
		g_dbus_method_invocation_get_sender(invocation),
		arg_user_data);
	if (parameter != NULL) {
		/* register default snep server */
		result = net_nfc_server_llcp_register_service(
			g_dbus_method_invocation_get_sender(invocation),
			arg_sap,
			arg_san,
			_snep_activate_cb,
			parameter);
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_service_llcp_register_service failed, [%d]", result);
			g_object_unref(connection);
			g_variant_unref(parameter);
		}
	} else {
		result = NET_NFC_ALLOC_FAIL;
		g_object_unref(connection);
	}

	net_nfc_gdbus_snep_complete_server_register(object,
		invocation,
		result);

	g_free(arg_san);

	g_object_unref(invocation);
	g_object_unref(object);

	g_variant_unref(user_data);
}

static gboolean _handle_register_server(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_sap,
	const gchar *arg_san,
	guint arg_user_data,
	GVariant *arg_privilege)
{
	GVariant *parameter = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		arg_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	parameter = g_variant_new("(uuusu)",
		GPOINTER_TO_UINT(g_object_ref(object)),
		GPOINTER_TO_UINT(g_object_ref(invocation)),
		arg_sap,
		arg_san,
		arg_user_data);
	if (parameter == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	if (net_nfc_server_controller_async_queue_push(
		snep_register_server_thread_func, parameter) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (parameter != NULL) {
		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);
	}

	net_nfc_gdbus_snep_complete_server_register(object,
		invocation,
		result);

	return TRUE;
}

static void snep_unregister_server_thread_func(gpointer user_data)
{
	NetNfcGDbusSnep *object;
	GDBusMethodInvocation *invocation;
	guint arg_sap;
	gchar *arg_san;

	net_nfc_error_e result;

	g_assert(user_data != NULL);

	g_variant_get((GVariant *)user_data,
		"(uuus)",
		(guint *)&object,
		(guint *)&invocation,
		&arg_sap,
		&arg_san);

	g_assert(object != NULL);
	g_assert(invocation != NULL);

	result = net_nfc_server_llcp_unregister_service(
		g_dbus_method_invocation_get_sender(invocation),
		arg_sap,
		arg_san);

	net_nfc_gdbus_snep_complete_server_unregister(object,
		invocation,
		result);

	g_free(arg_san);

	g_object_unref(invocation);
	g_object_unref(object);

	g_variant_unref(user_data);
}

static gboolean _handle_unregister_server(
	NetNfcGDbusSnep *object,
	GDBusMethodInvocation *invocation,
	guint arg_sap,
	const gchar *arg_san,
	GVariant *arg_privilege)
{
	GVariant *parameter = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		arg_privilege,
		"nfc-manager::p2p",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	parameter = g_variant_new("(uuus)",
		GPOINTER_TO_UINT(g_object_ref(object)),
		GPOINTER_TO_UINT(g_object_ref(invocation)),
		arg_sap,
		arg_san);
	if (parameter == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	if (net_nfc_server_controller_async_queue_push(
		snep_unregister_server_thread_func, parameter) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (parameter != NULL) {
		g_object_unref(invocation);
		g_object_unref(object);

		g_variant_unref(parameter);
	}

	net_nfc_gdbus_snep_complete_server_unregister(object,
		invocation,
		result);

	return TRUE;
}

gboolean net_nfc_server_snep_init(GDBusConnection *connection)
{
	GError *error = NULL;
	gboolean result;

	if (snep_skeleton)
		g_object_unref(snep_skeleton);

	snep_skeleton = net_nfc_gdbus_snep_skeleton_new();

	g_signal_connect(snep_skeleton,
		"handle-server-register",
		G_CALLBACK(_handle_register_server),
		NULL);

	g_signal_connect(snep_skeleton,
		"handle-server-unregister",
		G_CALLBACK(_handle_unregister_server),
		NULL);

	g_signal_connect(snep_skeleton,
		"handle-server-start",
		G_CALLBACK(_handle_start_server),
		NULL);

	g_signal_connect(snep_skeleton,
		"handle-client-start",
		G_CALLBACK(_handle_start_client),
		NULL);

	g_signal_connect(snep_skeleton,
		"handle-client-request",
		G_CALLBACK(_handle_client_send_request),
		NULL);

	g_signal_connect(snep_skeleton,
		"handle-stop-snep",
		G_CALLBACK(_handle_stop_snep),
		NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(snep_skeleton),
		connection,
		"/org/tizen/NetNfcService/Snep",
		&error);
	if (result == FALSE)
	{
		g_error_free(error);

		net_nfc_server_snep_deinit();
	}

	return result;
}

void net_nfc_server_snep_deinit(void)
{
	if (snep_skeleton)
	{
		g_object_unref(snep_skeleton);
		snep_skeleton = NULL;
	}
}
