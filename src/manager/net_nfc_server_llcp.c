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

#include <dd-display.h>/*for pm lock*/
//#include <logd/logd.h>   /* battery_adv */

#include "net_nfc_debug_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"

#include "net_nfc_gdbus.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_llcp.h"
#include "net_nfc_server_p2p.h"
#include "net_nfc_server_process_snep.h"
#include "net_nfc_server_process_npp.h"
#include "net_nfc_server_process_handover.h"

/* default llcp configurations */
#define NET_NFC_LLCP_MIU	128
#define NET_NFC_LLCP_WKS	1
#define NET_NFC_LLCP_LTO	10
#define NET_NFC_LLCP_OPT	0

static NetNfcGDbusLlcp *llcp_skeleton = NULL;

static net_nfc_llcp_config_info_s llcp_config =
{
	NET_NFC_LLCP_MIU,
	NET_NFC_LLCP_WKS,
	NET_NFC_LLCP_LTO,
	NET_NFC_LLCP_OPT,
};


typedef struct _llcp_client_data
{
	GDBusConnection *connection;
	char *id;
	net_nfc_target_handle_h handle;
	net_nfc_llcp_socket_t socket;
	void *user_data;
}
llcp_client_data;


typedef struct _LlcpData LlcpData;

struct _LlcpData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;
};

typedef struct _LlcpConfigData LlcpConfigData;

struct _LlcpConfigData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint16 miu;
	guint16 wks;
	guint8 lto;
	guint8 option;
};

typedef struct _LlcpListenData LlcpListenData;

struct _LlcpListenData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
	guint16 miu;
	guint8 rw;
	guint type;
	guint sap;
	gchar *service_name;
};

typedef struct _LlcpAcceptData LlcpAcceptData;

struct _LlcpAcceptData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint handle;
	guint client_socket;
};

typedef struct _LlcpConnectData LlcpConnectData;

struct _LlcpConnectData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
	guint16 miu;
	guint8 rw;
	guint type;
	gchar *service_name;
};

typedef struct _LlcpConnectSapData LlcpConnectSapData;

struct _LlcpConnectSapData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
	guint16 miu;
	guint8 rw;
	guint type;
	guint sap;
};

typedef struct _LlcpSendData LlcpSendData;

struct _LlcpSendData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;

	data_s data;
};

typedef struct _LlcpSendToData LlcpSendToData;

struct _LlcpSendToData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
	guint8 sap;

	data_s data;
};

typedef struct _LlcpReceiveData LlcpReceiveData;

struct _LlcpReceiveData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
	guint32 req_length;
};

typedef struct _LlcpCloseData LlcpCloseData;

struct _LlcpCloseData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
};

typedef struct _LlcpDisconnectData LlcpDisconnectData;

struct _LlcpDisconnectData
{
	NetNfcGDbusLlcp *llcp;
	GDBusMethodInvocation *invocation;

	guint32 handle;
	guint32 client_socket;
};

typedef struct _LlcpSimpleData LlcpSimpleData;

struct _LlcpSimpleData
{
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t socket;
	guint32 miu;
	net_nfc_server_llcp_callback callback;
	net_nfc_server_llcp_callback error_callback;
	gpointer user_data;
};

static void llcp_socket_error_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_incoming_cb(net_nfc_llcp_socket_t socket,
			net_nfc_error_e result,
			data_s *data,
			void *extra,
			void *user_param);

static void llcp_connect_by_url_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_connect_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_send_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_send_to_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_receive_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_receive_from_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

static void llcp_disconnect_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param);

/* client method */
static void llcp_handle_config_thread_func(gpointer user_data);

static void llcp_handle_listen_thread_func(gpointer user_data);

static void llcp_handle_accept_thread_func(gpointer user_data);

static void llcp_handle_reject_thread_func(gpointer user_data);

static void llcp_handle_connect_thread_func(gpointer user_data);

static void llcp_handle_connect_sap_thread_func(gpointer user_data);

static void llcp_handle_send_thread_func(gpointer user_data);

static void llcp_handle_send_to_thread_func(gpointer user_data);

static void llcp_handle_receive_thread_func(gpointer user_data);

static void llcp_handle_receive_from_thread_func(gpointer user_data);

static void llcp_handle_close_thread_func(gpointer user_data);

static void llcp_handle_disconnect_thread_func(gpointer user_data);

/* methods */
static gboolean llcp_handle_config(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				GVariant *arg_config,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_listen(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint16 arg_miu,
				guint8 arg_rw,
				gint32 arg_type,
				guint8 arg_sap,
				const gchar *arg_service_name,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_connect(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint16 arg_miu,
				guint8 arg_rw,
				gint32 arg_type,
				const gchar *arg_service_name,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_connect_sap(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint16 arg_miu,
				guint8 arg_rw,
				gint32 arg_type,
				guint8 arg_sap,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_send(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *arg_data,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_send_to(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint8 arg_sap,
				GVariant *arg_data,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_receive(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint32 arg_req_length,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_receive_from(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint32 arg_req_length,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_close(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean llcp_handle_disconnect(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *smack_privilege,
				gpointer user_data);


/* simple */
static void llcp_simple_socket_error_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param);

static void llcp_simple_listen_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param);

static void llcp_simple_connect_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param);

static void llcp_simple_send_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param);

static void llcp_simple_receive_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param);


static void llcp_socket_error_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	llcp_client_data *client_data = (llcp_client_data *)user_param;
	GError *error = NULL;

	if (g_dbus_connection_emit_signal(
		client_data->connection,
		client_data->id,
		"/org/tizen/NetNfcService/Llcp",
		"org.tizen.NetNfcService.Llcp",
		"Error",
		g_variant_new("(uui)",
			GPOINTER_TO_UINT(client_data->handle),
			socket,
			result),
		&error) == false) {
		if (error != NULL && error->message != NULL) {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed : %s", error->message);
		} else {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed");
		}
	}
}

static void llcp_incoming_cb(net_nfc_llcp_socket_t socket,
			net_nfc_error_e result,
			data_s *data,
			void *extra,
			void *user_param)
{
	llcp_client_data *client_data = (llcp_client_data *)user_param;
	GError *error = NULL;

	if (g_dbus_connection_emit_signal(
		client_data->connection,
		client_data->id,
		"/org/tizen/NetNfcService/Llcp",
		"org.tizen.NetNfcService.Llcp",
		"Incoming",
		g_variant_new("(uuu)",
			GPOINTER_TO_UINT(client_data->handle),
			client_data->socket,
			socket),
		&error) == false) {
		if (error != NULL && error->message != NULL) {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed : %s", error->message);
		} else {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed");
		}
	}
}

static void llcp_connect_by_url_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	LlcpConnectData *llcp_data = (LlcpConnectData *)user_param;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	net_nfc_gdbus_llcp_complete_connect(llcp_data->llcp,
		llcp_data->invocation,
		result,
		socket);

	g_free(llcp_data->service_name);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}

static void llcp_connect_cb(net_nfc_llcp_socket_t socket,
			net_nfc_error_e result,
			data_s *data,
			void *extra,
			void *user_param)
{
	LlcpConnectSapData *llcp_data = (LlcpConnectSapData *)user_param;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	net_nfc_gdbus_llcp_complete_connect_sap(
		llcp_data->llcp,
		llcp_data->invocation,
		result,
		socket);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}

static void llcp_send_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param)
{
	LlcpSendData *llcp_data = (LlcpSendData *)user_param;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	net_nfc_gdbus_llcp_complete_send(
		llcp_data->llcp,
		llcp_data->invocation,
		result,
		socket);

	net_nfc_util_clear_data(&llcp_data->data);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}

static void llcp_send_to_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result,
	data_s *data,
	void *extra,
	void *user_param)
{
	LlcpSendToData *llcp_data = (LlcpSendToData *)user_param;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	net_nfc_gdbus_llcp_complete_send_to(
		llcp_data->llcp,
		llcp_data->invocation,
		result,
		socket);

	net_nfc_util_clear_data(&llcp_data->data);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}

static void llcp_receive_cb(net_nfc_llcp_socket_t socket,
			net_nfc_error_e result,
			data_s *data,
			void *extra,
			void *user_param)
{
	LlcpReceiveData *llcp_data = (LlcpReceiveData *)user_param;
	GVariant *variant;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	variant = net_nfc_util_gdbus_data_to_variant(data);
	net_nfc_gdbus_llcp_complete_receive(
		llcp_data->llcp,
		llcp_data->invocation,
		result,
		variant);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}

static void llcp_receive_from_cb(net_nfc_llcp_socket_t socket,
			net_nfc_error_e result,
			data_s *data,
			void *extra,
			void *user_param)
{
	LlcpReceiveData *llcp_data = (LlcpReceiveData *)user_param;
	GVariant *variant;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	variant = net_nfc_util_gdbus_data_to_variant(data);
	net_nfc_gdbus_llcp_complete_receive_from(
		llcp_data->llcp,
		llcp_data->invocation,
		result,
		(guint8)(int)extra,
		variant);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}


static void llcp_disconnect_cb(net_nfc_llcp_socket_t socket,
			net_nfc_error_e result,
			data_s *data,
			void *extra,
			void *user_param)
{
	LlcpDisconnectData *llcp_data = (LlcpDisconnectData *)user_param;

	g_assert(llcp_data != NULL);
	g_assert(llcp_data->llcp != NULL);
	g_assert(llcp_data->invocation != NULL);

	net_nfc_gdbus_llcp_complete_disconnect(
		llcp_data->llcp,
		llcp_data->invocation,
		result,
		socket);

	g_object_unref(llcp_data->invocation);
	g_object_unref(llcp_data->llcp);

	g_free(llcp_data);
}


static void llcp_handle_config_thread_func(gpointer user_data)
{
	LlcpConfigData *data = (LlcpConfigData *)user_data;
	net_nfc_error_e result;
	net_nfc_llcp_config_info_s config;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	config.miu = data->miu;
	config.wks = data->wks;
	config.lto = data->lto;
	config.option = data->option;

	result = net_nfc_server_llcp_set_config(&config);

	net_nfc_gdbus_llcp_complete_config(data->llcp,
					data->invocation,
					result);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);
}

static void llcp_handle_listen_thread_func(gpointer user_data)
{
	LlcpListenData *data = (LlcpListenData *)user_data;
	llcp_client_data *client_data;

	net_nfc_llcp_socket_t socket = -1;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	client_data = g_try_new0(llcp_client_data, 1);
	if (client_data == NULL) {
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	client_data->connection = g_dbus_method_invocation_get_connection(
		data->invocation);
	client_data->id = g_strdup(
		g_dbus_method_invocation_get_sender(data->invocation));
	client_data->handle = (net_nfc_target_handle_h)data->handle;

	if (net_nfc_controller_llcp_create_socket(&socket,
		data->type,
		data->miu,
		data->rw,
		&result,
		llcp_socket_error_cb,
		client_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_create_socket failed [%d]", result);

		goto ERROR;
	}

	client_data->socket = socket;

	if (net_nfc_controller_llcp_bind(socket,
		data->sap,
		&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_bind failed [%d]", result);

		goto ERROR;
	}

	if (net_nfc_controller_llcp_listen(GUINT_TO_POINTER(data->handle),
		(uint8_t *)data->service_name,
		socket,
		&result,
		llcp_incoming_cb,
		client_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_listen failed [%d]", result);

		goto ERROR;
	}

	net_nfc_gdbus_llcp_complete_listen(data->llcp, data->invocation,
		result,
		GPOINTER_TO_UINT(socket));

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);

	return;

ERROR :
	net_nfc_gdbus_llcp_complete_listen(data->llcp, data->invocation,
		result,
		-1);

	if (socket != -1)
		net_nfc_controller_llcp_socket_close(socket, &result);

	g_free(client_data);

	g_free(data->service_name);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);
}

static void llcp_handle_accept_thread_func(gpointer user_data)
{
	LlcpAcceptData *data = (LlcpAcceptData *)user_data;
	llcp_client_data *client_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	client_data = g_try_new0(llcp_client_data, 1);
	if (client_data == NULL) {
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	client_data->connection = g_dbus_method_invocation_get_connection(
		data->invocation);
	client_data->id = g_strdup(
		g_dbus_method_invocation_get_sender(data->invocation));
	client_data->handle = (net_nfc_target_handle_h)data->handle;
	client_data->socket = data->client_socket;

	if (net_nfc_controller_llcp_accept(data->client_socket, &result,
		llcp_socket_error_cb,
		client_data) == false) {
		DEBUG_ERR_MSG("net_nfc_controller_llcp_accept failed [%d]", result);

		goto ERROR;
	}

	net_nfc_gdbus_llcp_complete_accept(data->llcp, data->invocation,
		result);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);

	return;

ERROR :
	net_nfc_gdbus_llcp_complete_accept(data->llcp, data->invocation,
		result);

	g_free(client_data);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);
}

static void llcp_handle_reject_thread_func(gpointer user_data)
{
	LlcpAcceptData *data = (LlcpAcceptData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	if (net_nfc_controller_llcp_reject(GUINT_TO_POINTER(data->handle),
		data->client_socket,
		&result) == false) {
		DEBUG_ERR_MSG("net_nfc_controller_llcp_reject failed [%d]", result);
	}

	net_nfc_gdbus_llcp_complete_reject(data->llcp, data->invocation,
		result);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);
}


static void llcp_handle_connect_thread_func(gpointer user_data)
{
	LlcpConnectData *data = (LlcpConnectData *)user_data;
	llcp_client_data *client_data;
	net_nfc_llcp_socket_t socket = -1;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	client_data = g_try_new0(llcp_client_data, 1);
	if (client_data == NULL) {
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	client_data->connection = g_dbus_method_invocation_get_connection(
		data->invocation);
	client_data->id = g_strdup(
		g_dbus_method_invocation_get_sender(data->invocation));
	client_data->handle = (net_nfc_target_handle_h)data->handle;

	if (net_nfc_controller_llcp_create_socket(&socket,
		data->type,
		data->miu,
		data->rw,
		&result,
		llcp_socket_error_cb,
		client_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_create_socket failed [%d]", result);

		goto ERROR;
	}

	client_data->socket = socket;

	if (net_nfc_controller_llcp_connect_by_url(
		GUINT_TO_POINTER(data->handle),
		socket,
		(uint8_t *)data->service_name,
		&result,
		llcp_connect_by_url_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_listen failed [%d]", result);

		goto ERROR;
	}

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);

	return;

ERROR :
	net_nfc_gdbus_llcp_complete_connect(data->llcp, data->invocation,
		result,
		-1);

	if (socket != -1)
		net_nfc_controller_llcp_socket_close(socket, &result);

	g_free(client_data);

	g_free(data->service_name);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);
}

static void llcp_handle_connect_sap_thread_func(gpointer user_data)
{
	LlcpConnectSapData *data = (LlcpConnectSapData *)user_data;
	llcp_client_data *client_data;

	net_nfc_llcp_socket_t socket = -1;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	client_data = g_try_new0(llcp_client_data, 1);
	if (client_data == NULL) {
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	client_data->connection = g_dbus_method_invocation_get_connection(
		data->invocation);
	client_data->id = g_strdup(
		g_dbus_method_invocation_get_sender(data->invocation));
	client_data->handle = (net_nfc_target_handle_h)data->handle;

	if (net_nfc_controller_llcp_create_socket(&socket,
		data->type,
		data->miu,
		data->rw,
		&result,
		llcp_socket_error_cb,
		client_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_create_socket failed [%d]", result);

		goto ERROR;
	}

	client_data->socket = socket;

	if (net_nfc_controller_llcp_connect(GUINT_TO_POINTER(data->handle),
		socket,
		data->sap,
		&result,
		llcp_connect_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_listen failed [%d]", result);

		goto ERROR;
	}

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);

	return;

ERROR :
	net_nfc_gdbus_llcp_complete_connect_sap(data->llcp, data->invocation,
		result,
		-1);

	if (socket != -1)
		net_nfc_controller_llcp_socket_close(socket, &result);

	g_free(client_data);

	g_object_unref(data->invocation);
	g_object_unref(data->llcp);

	g_free(data);
}

static void llcp_handle_send_thread_func(gpointer user_data)
{
	LlcpSendData *data = (LlcpSendData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	if (net_nfc_controller_llcp_send(GUINT_TO_POINTER(data->handle),
		data->client_socket,
		&data->data,
		&result,
		llcp_send_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_send failed [%d]", result);

		net_nfc_gdbus_llcp_complete_send(data->llcp,
			data->invocation,
			result,
			data->client_socket);

		net_nfc_util_clear_data(&data->data);

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}
}

static void llcp_handle_send_to_thread_func(gpointer user_data)
{
	LlcpSendToData *data = (LlcpSendToData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	if (net_nfc_controller_llcp_send_to(GUINT_TO_POINTER(data->handle),
		data->client_socket,
		&data->data,
		data->sap,
		&result,
		llcp_send_to_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_send_to failed [%d]", result);

		net_nfc_gdbus_llcp_complete_send_to(data->llcp,
			data->invocation,
			result,
			data->client_socket);

		net_nfc_util_clear_data(&data->data);

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}
}

static void llcp_handle_receive_thread_func(gpointer user_data)
{
	LlcpReceiveData *data = (LlcpReceiveData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	if (net_nfc_controller_llcp_recv(GUINT_TO_POINTER(data->handle),
		data->client_socket,
		data->req_length,
		&result,
		llcp_receive_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_recv failed [%d]", result);

		net_nfc_gdbus_llcp_complete_receive(data->llcp,
			data->invocation,
			result,
			net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}
}

static void llcp_handle_receive_from_thread_func(gpointer user_data)
{
	LlcpReceiveData *data = (LlcpReceiveData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	if (net_nfc_controller_llcp_recv_from(GUINT_TO_POINTER(data->handle),
		data->client_socket,
		data->req_length,
		&result,
		llcp_receive_from_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_recv_from failed [%d]", result);

		net_nfc_gdbus_llcp_complete_receive_from(data->llcp,
			data->invocation,
			result,
			-1,
			net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}
}

static void llcp_handle_close_thread_func(gpointer user_data)
{
	LlcpCloseData *data = (LlcpCloseData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_llcp_socket_close(data->client_socket, &result);

	net_nfc_gdbus_llcp_complete_close(data->llcp,
		data->invocation,
		result,
		data->client_socket);
}

static void llcp_handle_disconnect_thread_func(gpointer user_data)
{
	LlcpDisconnectData *data = (LlcpDisconnectData *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->llcp != NULL);
	g_assert(data->invocation != NULL);

	if (GUINT_TO_POINTER(data->handle) == 0)
	{
		int ret_val;

		net_nfc_server_free_target_info();
		ret_val = display_unlock_state(LCD_NORMAL, PM_RESET_TIMER);
		DEBUG_SERVER_MSG("net_nfc_controller_disconnect display_unlock_state"
						"[%d]!!", ret_val);
	}

	if (net_nfc_controller_llcp_disconnect(GUINT_TO_POINTER(data->handle),
		data->client_socket,
		&result,
		llcp_disconnect_cb,
		data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_disconnect failed [%d]", result);

		net_nfc_gdbus_llcp_complete_disconnect(data->llcp,
			data->invocation,
			result,
			data->client_socket);

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}
}


static gboolean llcp_handle_config(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				GVariant *arg_config,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpConfigData *data = NULL;

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

	data = g_try_new0(LlcpConfigData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);

	g_variant_get(arg_config,
		"(qqyy)",
		&data->miu,
		&data->wks,
		&data->lto,
		&data->option);

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_config_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_config(llcp,
					invocation,
					result);

	return TRUE;
}

static gboolean llcp_handle_listen(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint16 arg_miu,
				guint8 arg_rw,
				gint32 arg_type,
				guint8 arg_sap,
				const gchar *arg_service_name,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpListenData *data = NULL;

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

	data = g_try_new0(LlcpListenData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;
	data->miu = arg_miu;
	data->rw = arg_rw;
	data->type = arg_type;
	data->sap = arg_sap;
	data->service_name = g_strdup(arg_service_name);

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_listen_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->service_name);

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_listen(llcp, invocation, result, -1);

	return TRUE;
}

static gboolean llcp_handle_accept(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpAcceptData *data = NULL;

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

	data = g_try_new0(LlcpAcceptData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_accept_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_accept(llcp, invocation, result);

	return TRUE;
}

static gboolean llcp_handle_reject(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpAcceptData *data = NULL;

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

	data = g_try_new0(LlcpAcceptData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_reject_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_reject(llcp, invocation, result);

	return TRUE;
}

static gboolean llcp_handle_connect(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint16 arg_miu,
				guint8 arg_rw,
				gint32 arg_type,
				const gchar *arg_service_name,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpConnectData *data = NULL;

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

	data = g_try_new0(LlcpConnectData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;
	data->miu = arg_miu;
	data->rw = arg_rw;
	data->type = arg_type;
	data->service_name = g_strdup(arg_service_name);

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_connect_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->service_name);

		g_object_unref(data->invocation);
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_connect(llcp, invocation, result, -1);

	return TRUE;
}

static gboolean llcp_handle_connect_sap(NetNfcGDbusLlcp *llcp,
					GDBusMethodInvocation *invocation,
					guint32 arg_handle,
					guint32 arg_client_socket,
					guint16 arg_miu,
					guint8 arg_rw,
					gint32 arg_type,
					guint8 arg_sap,
					GVariant *smack_privilege,
					gpointer user_data)
{
	gint result;
	LlcpConnectSapData *data = NULL;

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

	data = g_try_new0(LlcpConnectSapData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;
	data->miu = arg_miu;
	data->rw = arg_rw;
	data->type = arg_type;
	data->sap = arg_sap;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_connect_sap_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_connect_sap(llcp,invocation, result, -1);

	return TRUE;
}

static gboolean llcp_handle_send(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *arg_data,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpSendData *data = NULL;

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

	data = g_try_new0(LlcpSendData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;

	net_nfc_util_gdbus_variant_to_data_s(arg_data, &data->data);

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_send_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_send(llcp, invocation,
		result, arg_client_socket);

	return TRUE;
}

static gboolean llcp_handle_send_to(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint8 arg_sap,
				GVariant *arg_data,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpSendToData *data = NULL;

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

	data = g_try_new0(LlcpSendToData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;
	data->sap = arg_sap;

	net_nfc_util_gdbus_variant_to_data_s(arg_data, &data->data);

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_send_to_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_send_to(llcp, invocation,
		result, arg_client_socket);

	return TRUE;
}

static gboolean llcp_handle_receive(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				guint32 arg_req_length,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpReceiveData *data = NULL;

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

	data = g_try_new0(LlcpReceiveData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;
	data->req_length = arg_req_length;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_receive_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_receive(llcp, invocation, result,
		net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static gboolean llcp_handle_receive_from(NetNfcGDbusLlcp *llcp,
					GDBusMethodInvocation *invocation,
					guint32 arg_handle,
					guint32 arg_client_socket,
					guint32 arg_req_length,
					GVariant *smack_privilege,
					gpointer user_data)
{
	gint result;
	LlcpReceiveData *data = NULL;

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

	data = g_try_new0(LlcpReceiveData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;
	data->req_length = arg_req_length;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_receive_from_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_receive_from(llcp, invocation,
		result, -1, net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static gboolean llcp_handle_close(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpCloseData *data = NULL;

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

	data = g_try_new0(LlcpCloseData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_close_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_close(llcp, invocation,
		result, arg_client_socket);

	return TRUE;
}

static gboolean llcp_handle_disconnect(NetNfcGDbusLlcp *llcp,
				GDBusMethodInvocation *invocation,
				guint32 arg_handle,
				guint32 arg_client_socket,
				GVariant *smack_privilege,
				gpointer user_data)
{
	gint result;
	LlcpDisconnectData *data = NULL;

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

	data = g_try_new0(LlcpDisconnectData, 1);
	if (data == NULL) {
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->llcp = g_object_ref(llcp);
	data->invocation = g_object_ref(invocation);
	data->handle = arg_handle;
	data->client_socket = arg_client_socket;

	if (net_nfc_server_controller_async_queue_push(
		llcp_handle_disconnect_thread_func, data) == FALSE)
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
		g_object_unref(data->llcp);

		g_free(data);
	}

	net_nfc_gdbus_llcp_complete_disconnect(llcp, invocation,
		result, arg_client_socket);

	return TRUE;
}

void net_nfc_server_llcp_deactivated(gpointer user_data)
{
	net_nfc_current_target_info_s *target_info = NULL;
	net_nfc_target_handle_s *handle = NULL;

	target_info = net_nfc_server_get_target_info();

	if(target_info != NULL && target_info->handle != NULL)
		handle = target_info->handle;

	if (handle != NULL)
	{
		net_nfc_error_e result = NET_NFC_OK;

		if (net_nfc_controller_disconnect(handle, &result) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_disconnect failed, [%d]", result);
#if 0
			if (result != NET_NFC_NOT_CONNECTED)
			{
				net_nfc_controller_exception_handler();
			}
			else
			{
				DEBUG_SERVER_MSG("target was not connected.");
			}
#endif
		}

		net_nfc_server_set_state(NET_NFC_SERVER_IDLE);
	}
	else
	{
		int ret_val = 0;

		ret_val = display_unlock_state(LCD_NORMAL, PM_RESET_TIMER);

		DEBUG_SERVER_MSG("the target was disconnected display_unlock_state = [%d]" , ret_val);
	}

	/* send p2p detatch */
	if (net_nfc_server_controller_async_queue_push(
		net_nfc_server_p2p_detached, NULL) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
	}
}

static void llcp_simple_socket_error_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	LlcpSimpleData *simple_data = (LlcpSimpleData *)user_param;

	DEBUG_SERVER_MSG("Check socket = [%x]" ,socket );

	g_assert(simple_data != NULL);

	if (simple_data->error_callback)
	{
		simple_data->error_callback(result,
			simple_data->handle,
			socket,
			data,
			simple_data->user_data);
	}

	g_free(simple_data);
	simple_data = NULL;
}

static void llcp_simple_listen_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	LlcpSimpleData *simple_data = (LlcpSimpleData *)user_param;

	g_assert(simple_data != NULL);

	if (result != NET_NFC_OK) {
		DEBUG_ERR_MSG("listen socket failed, [%d]", result);
	}

	if (simple_data->callback)
	{
		simple_data->callback(result,
			simple_data->handle,
			socket,
			data,
			simple_data->user_data);
	}

	/* 'simple_data' will be freed in socket error callback */
}

static void llcp_simple_connect_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	LlcpSimpleData *simple_data = (LlcpSimpleData *)user_param;

	g_assert(simple_data != NULL);

	if (result != NET_NFC_OK) {
		DEBUG_ERR_MSG("connect socket failed, [%d]", result);
	}

	if (simple_data->callback)
	{
		simple_data->callback(result,
			simple_data->handle,
			socket,
			data,
			simple_data->user_data);
	}

	/* 'simple_data' will be freed in socket error callback */
}

static void llcp_simple_send_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	LlcpSimpleData *simple_data = (LlcpSimpleData *)user_param;

	g_assert(simple_data != NULL);

	if (simple_data->callback)
	{
		simple_data->callback(result,
				simple_data->handle,
				socket,
				data,
				simple_data->user_data);
	}

	g_free(simple_data);
}

static void llcp_simple_receive_cb(net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	LlcpSimpleData *simple_data = (LlcpSimpleData *)user_param;

	g_assert(simple_data != NULL);

	if (simple_data->callback)
	{
		simple_data->callback(result,
			simple_data->handle,
			socket,
			data,
			simple_data->user_data);
	}

	g_free(simple_data);
}

static void _llcp_on_client_detached_cb(net_nfc_client_context_info_t *client)
{
	net_nfc_server_llcp_unregister_services(client->id);
}

/* Public Function */
gboolean net_nfc_server_llcp_init(GDBusConnection *connection)
{
	gboolean result;
	GError *error = NULL;

	if (llcp_skeleton)
		g_object_unref(llcp_skeleton);

	llcp_skeleton = net_nfc_gdbus_llcp_skeleton_new();

	g_signal_connect(llcp_skeleton,
			"handle-config",
			G_CALLBACK(llcp_handle_config),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-listen",
			G_CALLBACK(llcp_handle_listen),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-accept",
			G_CALLBACK(llcp_handle_accept),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-reject",
			G_CALLBACK(llcp_handle_reject),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-connect",
			G_CALLBACK(llcp_handle_connect),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-connect-sap",
			G_CALLBACK(llcp_handle_connect_sap),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-send",
			G_CALLBACK(llcp_handle_send),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-send-to",
			G_CALLBACK(llcp_handle_send_to),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-receive",
			G_CALLBACK(llcp_handle_receive),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-receive-from",
			G_CALLBACK(llcp_handle_receive_from),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-close",
			G_CALLBACK(llcp_handle_close),
			NULL);

	g_signal_connect(llcp_skeleton,
			"handle-disconnect",
			G_CALLBACK(llcp_handle_disconnect),
			NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(llcp_skeleton),
		connection,
		"/org/tizen/NetNfcService/Llcp",
		&error);
	if (result == TRUE) {
		net_nfc_server_gdbus_register_on_client_detached_cb(
			_llcp_on_client_detached_cb);
	} else {
		g_error_free(error);

		net_nfc_server_llcp_deinit();
	}


	return result;
}

void net_nfc_server_llcp_deinit(void)
{
	if (llcp_skeleton)
	{
		net_nfc_server_gdbus_unregister_on_client_detached_cb(
			_llcp_on_client_detached_cb);

		g_object_unref(llcp_skeleton);
		llcp_skeleton = NULL;
	}
}

net_nfc_error_e net_nfc_server_llcp_set_config(
					net_nfc_llcp_config_info_s *config)
{
	net_nfc_error_e result;

	if (config == NULL)
	{
		net_nfc_controller_llcp_config(&llcp_config, &result);
		return result;
	}

	net_nfc_controller_llcp_config(config, &result);
	memcpy(&llcp_config, config, sizeof(llcp_config));

	return result;
}

guint16 net_nfc_server_llcp_get_miu(void)
{
	return llcp_config.miu;
}

guint16 net_nfc_server_llcp_get_wks(void)
{
	return llcp_config.wks;
}

guint8 net_nfc_server_llcp_get_lto(void)
{
	return llcp_config.lto;
}

guint8 net_nfc_server_llcp_get_option(void)
{
	return llcp_config.option;
}

net_nfc_error_e net_nfc_server_llcp_simple_server(
				net_nfc_target_handle_s *handle,
				const char *san,
				sap_t sap,
				net_nfc_server_llcp_callback callback,
				net_nfc_server_llcp_callback error_callback,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	LlcpSimpleData *simple_data = NULL;
	net_nfc_llcp_socket_t socket = -1;
	net_nfc_llcp_config_info_s config;

	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_controller_llcp_get_remote_config(handle,
						&config,
						&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_get_remote_config failed [%d]", result);

		goto ERROR;
	}

	simple_data = g_try_new0(LlcpSimpleData, 1);
	if (simple_data == NULL) {
		DEBUG_ERR_MSG("g_try_new0 failed");

		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	simple_data->handle = handle;
	simple_data->callback = callback;
	simple_data->error_callback = error_callback;
	simple_data->user_data = user_data;

	simple_data->miu = MIN(config.miu, net_nfc_server_llcp_get_miu());

	if (net_nfc_controller_llcp_create_socket(&socket,
			NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED,
			simple_data->miu,
			1,
			&result,
			llcp_simple_socket_error_cb,
			simple_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_create_socket failed [%d]", result);

		goto ERROR;
	}

	simple_data->socket = socket;

	if (net_nfc_controller_llcp_bind(socket,
					sap,
					&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_bind failed [%d]", result);

		goto ERROR;
	}

	if (net_nfc_controller_llcp_listen(handle,
					(uint8_t *)san,
					socket,
					&result,
					llcp_simple_listen_cb,
					simple_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_listen failed [%d]", result);

		goto ERROR;
	}

	DEBUG_SERVER_MSG("result [%d]", result);

	if (result == NET_NFC_BUSY)
		result = NET_NFC_OK;

	return result;

ERROR :
	if (socket != -1) {
		net_nfc_error_e temp;

		net_nfc_controller_llcp_socket_close(socket, &temp);
	}

	return result;
}

net_nfc_error_e net_nfc_server_llcp_simple_client(
				net_nfc_target_handle_s *handle,
				const char *san,
				sap_t sap,
				net_nfc_server_llcp_callback callback,
				net_nfc_server_llcp_callback error_callback,
				gpointer user_data)
{
	net_nfc_error_e result;
	LlcpSimpleData *simple_data = NULL;
	net_nfc_llcp_socket_t socket = -1;
	net_nfc_llcp_config_info_s config;

	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_controller_llcp_get_remote_config(handle,
						&config,
						&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_get_remote_config failed [%d]", result);

		goto ERROR;
	}

	simple_data = g_try_new0(LlcpSimpleData, 1);
	if (simple_data == NULL) {
		DEBUG_ERR_MSG("g_try_new0 failed");

		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	simple_data->handle = handle;
	simple_data->callback = callback;
	simple_data->error_callback = error_callback;
	simple_data->user_data = user_data;

	simple_data->miu = MIN(config.miu, net_nfc_server_llcp_get_miu());

	if (net_nfc_controller_llcp_create_socket(&socket,
			NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED,
			simple_data->miu,
			1,
			&result,
			llcp_simple_socket_error_cb,
			simple_data) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_create_socket failed [%d]", result);

		goto ERROR;
	}

	simple_data->socket = socket;

	if (san == NULL)
	{
		if (net_nfc_controller_llcp_connect(handle,
						simple_data->socket,
						sap,
						&result,
						llcp_simple_connect_cb,
						simple_data) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_llcp_connect failed [%d]", result);

			goto ERROR;
		}
	}
	else
	{
		if (net_nfc_controller_llcp_connect_by_url(handle,
						simple_data->socket,
						(uint8_t *)san,
						&result,
						llcp_simple_connect_cb,
						simple_data) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_llcp_connect_by_url failed [%d]", result);

			goto ERROR;
		}
	}

	DEBUG_SERVER_MSG("result [%d]", result);

	if (result == NET_NFC_BUSY)
		result = NET_NFC_OK;

	return result;

ERROR :
	if (socket != -1) {
		net_nfc_error_e temp;

		net_nfc_controller_llcp_socket_close(socket, &temp);
	}
#if 1
	if (simple_data != NULL) {
		g_free(simple_data);
		simple_data = NULL;
	}
#endif
	return result;
}

net_nfc_error_e net_nfc_server_llcp_simple_accept(
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				net_nfc_server_llcp_callback error_callback,
				gpointer user_data)
{
	net_nfc_error_e result;
	LlcpSimpleData *simple_data;

	simple_data = g_try_new0(LlcpSimpleData, 1);
	if (simple_data != NULL) {
		simple_data->handle = handle;
		simple_data->socket = socket;
		simple_data->error_callback = error_callback;
		simple_data->user_data = user_data;

		if (net_nfc_controller_llcp_accept(socket,
						&result,
						llcp_simple_socket_error_cb,
						simple_data) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_llcp_accept failed [%d]", result);
		}
	} else {
		DEBUG_ERR_MSG("g_try_new0 failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	if (result == NET_NFC_BUSY)
		result = NET_NFC_OK;

	return result;
}

net_nfc_error_e net_nfc_server_llcp_simple_send(
					net_nfc_target_handle_s *handle,
					net_nfc_llcp_socket_t socket,
					data_s *data,
					net_nfc_server_llcp_callback callback,
					gpointer user_data)
{
	net_nfc_error_e result;
	LlcpSimpleData *simple_data;

	simple_data = g_try_new0(LlcpSimpleData, 1);
	if (simple_data != NULL) {
		simple_data->handle = handle;
		simple_data->socket = socket;
		simple_data->callback = callback;
		simple_data->user_data = user_data;

		if (net_nfc_controller_llcp_send(handle,
						socket,
						data,
						&result,
						llcp_simple_send_cb,
						simple_data) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_llcp_send failed [%d]",
				result);
		}
	} else {
		DEBUG_ERR_MSG("g_try_new0 failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	if (result == NET_NFC_BUSY)
		result = NET_NFC_OK;

	return result;
}

net_nfc_error_e net_nfc_server_llcp_simple_receive(
	net_nfc_target_handle_s *handle,
	net_nfc_llcp_socket_t socket,
	net_nfc_server_llcp_callback callback,
	gpointer user_data)
{
	net_nfc_error_e result;
	LlcpSimpleData *simple_data;

	simple_data = g_try_new0(LlcpSimpleData, 1);
	if (simple_data != NULL) {
		simple_data->handle = handle;
		simple_data->socket = socket;
		simple_data->callback = callback;
		simple_data->user_data = user_data;

		if (net_nfc_controller_llcp_recv(handle,
			socket,
			net_nfc_server_llcp_get_miu(),
			&result,
			llcp_simple_receive_cb,
			simple_data) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_llcp_recv failed [%d]", result);

			g_free(simple_data);
		}
	} else {
		DEBUG_ERR_MSG("g_try_new0 failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	if (result == NET_NFC_BUSY)
		result = NET_NFC_OK;

	return result;
}

typedef struct _service_t
{
	uint32_t sap;
	char *san;
	char *id;
	net_nfc_server_llcp_activate_cb cb;
	void *user_data;
}
service_t;

static GHashTable *service_table;

static void _llcp_init()
{
	if (service_table == NULL)
		service_table = g_hash_table_new(NULL, NULL);
}

inline static service_t *_llcp_find_service(uint32_t sap)
{
	return (service_t *)g_hash_table_lookup(service_table,
		(gconstpointer)sap);
}

static net_nfc_error_e _llcp_add_service(const char *id, uint32_t sap,
	const char *san, net_nfc_server_llcp_activate_cb cb, void *user_data)
{
	service_t *service = NULL;
	net_nfc_error_e result;

	if (cb == NULL) {
		DEBUG_ERR_MSG("callback is mandatory");

		return NET_NFC_NULL_PARAMETER;
	}

	_llcp_init();

	if (_llcp_find_service(sap) == NULL) {
		DEBUG_SERVER_MSG("new service, sap [%d]", sap);

		service = g_try_new0(service_t, 1);
		if (service != NULL) {
			service->sap = sap;
			if (san != NULL && strlen(san) > 0) {
				service->san = g_strdup(san);
			}
			if (id != NULL && strlen(id) > 0) {
				service->id = g_strdup(id);
			}
			service->cb = cb;
			service->user_data = user_data;

			g_hash_table_insert(service_table, (gpointer)sap,
				(gpointer)service);

			result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("alloc failed");

			result = NET_NFC_ALLOC_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("already registered");

		result = NET_NFC_ALREADY_REGISTERED;
	}

	return result;
}

static void _llcp_remove_service(uint32_t sap)
{
	service_t *service = NULL;

	service = _llcp_find_service(sap);
	if (service != NULL) {
		g_free(service->san);
		g_free(service->id);
		g_free(service);

		g_hash_table_remove(service_table, (gconstpointer)sap);
	}
}

static void _llcp_remove_services(const char *id)
{
	GHashTableIter iter;
	gpointer key;
	service_t *service;

	if (service_table == NULL)
		return;

	g_hash_table_iter_init (&iter, service_table);

	while (g_hash_table_iter_next (&iter, &key, (gpointer)&service)) {
		if (id == NULL || strcmp(service->id, id) == 0) {
			g_free(service->san);
			g_free(service->id);
			g_free(service);

			g_hash_table_iter_remove(&iter);
		}
	}
}

static void _llcp_start_services_cb(gpointer key, gpointer value,
	gpointer user_data)
{
	service_t *service = (service_t *)value;

	/* TODO : start service */
	if (service != NULL && service->cb != NULL) {
		service->cb(NET_NFC_LLCP_START,
			(net_nfc_target_handle_s *)user_data,
			service->sap,
			service->san, service->user_data);
	}
}

static void _llcp_start_services(net_nfc_target_handle_s *handle)
{
	g_hash_table_foreach(service_table, _llcp_start_services_cb, handle);
}

net_nfc_error_e net_nfc_server_llcp_register_service(const char *id,
	sap_t sap, const char *san, net_nfc_server_llcp_activate_cb cb,
	void *user_param)
{
	return _llcp_add_service(id, sap, san, cb, user_param);
}

net_nfc_error_e net_nfc_server_llcp_unregister_service(const char *id,
	sap_t sap, const char *san)
{
	net_nfc_error_e result;
	service_t *service;

	service = _llcp_find_service(sap);
	if (service != NULL) {
		/* invoke callback */
		service->cb(NET_NFC_LLCP_UNREGISTERED, NULL, service->sap,
			service->san, service->user_data);

		_llcp_remove_service(sap);

		result = NET_NFC_OK;
	} else {
		DEBUG_ERR_MSG("service is not registered");

		result = NET_NFC_NOT_REGISTERED;
	}

	return result;
}

net_nfc_error_e net_nfc_server_llcp_unregister_services(const char *id)
{
	_llcp_remove_services(id);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_server_llcp_unregister_all()
{
	GHashTableIter iter;
	gpointer key;
	service_t *service;

	if (service_table == NULL)
		return NET_NFC_OK;

	g_hash_table_iter_init(&iter, service_table);

	while (g_hash_table_iter_next(&iter, &key, (gpointer)&service)) {
		service->cb(NET_NFC_LLCP_UNREGISTERED, NULL, service->sap,
			service->san, service->user_data);

		g_free(service->san);
		g_free(service->id);
		g_free(service);

		g_hash_table_iter_remove(&iter);
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_server_llcp_start_registered_services(
	net_nfc_target_handle_s *handle)
{
	_llcp_start_services(handle);

	return NET_NFC_OK;
}

static void net_nfc_server_llcp_process(gpointer user_data)
{
	net_nfc_current_target_info_s *target;
	net_nfc_error_e result;
	net_nfc_target_type_e dev_type;
	net_nfc_target_handle_s *handle;

	net_nfc_server_set_target_info((net_nfc_current_target_info_s *)user_data);

	g_free(user_data);

	target = net_nfc_server_get_target_info();

	g_assert(target != NULL);

	handle = target->handle;
	dev_type = target->devType;

	DEBUG_SERVER_MSG("connection type = [%d]", handle->connection_type);
	if (dev_type == NET_NFC_NFCIP1_TARGET)
	{
		DEBUG_SERVER_MSG("LLCP : target, try to connect");

		if (net_nfc_controller_connect(handle, &result) == false)
		{
			DEBUG_SERVER_MSG("%s is failed, [%d]",
					"net_nfc_controller_connect",
					result);

			if (net_nfc_controller_configure_discovery(
					NET_NFC_DISCOVERY_MODE_RESUME,
					NET_NFC_ALL_ENABLE,
					&result) == false)
			{
				DEBUG_ERR_MSG("%s is failed [%d]",
				"net_nfc_controller_configure_discovery",
				result);

				net_nfc_controller_exception_handler();
			}

			return;
		}
	}

	DEBUG_SERVER_MSG("check LLCP");

	if (net_nfc_controller_llcp_check_llcp(handle, &result) == false)
	{
		DEBUG_ERR_MSG("%s is failed [%d]",
			"net_nfc_controller_llcp_check_llcp",
			result);

		return;
	}

	DEBUG_SERVER_MSG("activate LLCP");

	if (net_nfc_controller_llcp_activate_llcp(handle, &result) == false)
	{
		DEBUG_ERR_MSG("%s is failed [%d]",
			"net_nfc_controller_llcp_activate_llcp",
			result);

		return;
	}
	net_nfc_server_llcp_start_registered_services(handle);

	net_nfc_server_p2p_discovered(handle);
}

bool net_nfc_server_llcp_target_detected(void *info)
{
	if (net_nfc_server_controller_async_queue_push_force(
		net_nfc_server_llcp_process, info) == FALSE)
	{
		DEBUG_ERR_MSG("can not push to controller thread");
		return false;
	}

	return true;
}
