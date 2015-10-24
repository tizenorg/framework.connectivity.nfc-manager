/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vconf.h>

#include "net_nfc_server.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_util_hce.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_manager.h"
#include "net_nfc_server_route_table.h"
#include "net_nfc_app_util_internal.h"
#include "net_nfc_server_hce.h"

/*TODO : */
#include "net_nfc_app_util_internal.h"

#define OPERATION_APDU_RECEIVED		"http://tizen.org/appcontrol/operation/nfc/card_emulation/apdu_received"
#define OPERATION_TRANSACTION_RECEIVED	"http://tizen.org/appcontrol/operation/nfc/card_emulation/transaction_received"

static NetNfcGDbusHce *hce_skeleton = NULL;
/*Routing Table base on AID*/
static GHashTable *routing_table_aid;
static char *selected_aid;

//static uint8_t android_hce_aid_buffer[] = { 0xA0, 0x00, 0x00, 0x04, 0x76, 0x41, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x48, 0x43, 0x45 };
//static data_s android_hce_aid = { android_hce_aid_buffer, sizeof(android_hce_aid_buffer) };

typedef struct _hce_listener_t
{
	char *id;
	char *package;
	net_nfc_server_hce_listener_cb listener;
	net_nfc_server_hce_user_data_destroy_cb destroy_cb;
	void *user_data;
}
hce_listener_t;

/* server_side */
typedef struct _SeDataHandle SeDataHandle;

struct _SeDataHandle
{
	NetNfcGDbusHce *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s* handle;
};

typedef struct _ServerHceData ServerHceData;

struct _ServerHceData
{
	net_nfc_target_handle_s *handle;
	guint event;
	data_s apdu;
};

typedef struct _HceDataApdu HceDataApdu;

struct _HceDataApdu
{
	NetNfcGDbusHce *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s *handle;
	GVariant *data;
};

typedef struct _hce_client_context_s
{
	GDBusConnection *connection;
	char *id;
}
hce_client_context_s;

typedef bool (*route_table_iter_cb)(hce_listener_t *data, void *user_data);


static void __on_key_destroy(gpointer data)
{
	if (data != NULL) {
		g_free(data);
	}
}

static void __on_value_destroy(gpointer data)
{
	hce_listener_t *listener = (hce_listener_t *)data;

	if (data != NULL) {
		if (listener->id != NULL) {
			g_free(listener->id);
		}
		if (listener->package != NULL) {
			g_free(listener->package);
		}

		g_free(data);
	}
}

static void _routing_table_init()
{
	if (routing_table_aid == NULL)
		routing_table_aid = g_hash_table_new_full(g_str_hash,
			g_str_equal, __on_key_destroy, __on_value_destroy);
}

inline static hce_listener_t *_routing_table_find_aid(const char *package)
{
	return (hce_listener_t *)g_hash_table_lookup(routing_table_aid,
		(gconstpointer)package);
}

static net_nfc_error_e _routing_table_add(const char *package, const char *id,
	net_nfc_server_hce_listener_cb listener,
	net_nfc_server_hce_user_data_destroy_cb destroy_cb, void *user_data)
{
	net_nfc_error_e result;

	if (_routing_table_find_aid(package) == NULL) {
		hce_listener_t *data;
		DEBUG_SERVER_MSG("new hce package, [%s]", package);

		data = g_new0(hce_listener_t, 1);

		data->package = g_strdup(package);
		if (id != NULL) {
			data->id = g_strdup(id);
		}
		data->listener = listener;
		data->destroy_cb = destroy_cb;
		data->user_data = user_data;

		g_hash_table_insert(routing_table_aid,
			(gpointer)g_strdup(package), (gpointer)data);

		result = NET_NFC_OK;
	} else {
		DEBUG_ERR_MSG("already registered");

		result = NET_NFC_ALREADY_REGISTERED;
	}

	return result;
}

static void _routing_table_del(const char *package)
{
	hce_listener_t *data;

	data = _routing_table_find_aid(package);
	if (data != NULL) {
		DEBUG_SERVER_MSG("remove hce package, [%s]", package);

		if (data->destroy_cb != NULL) {
			data->destroy_cb(data->user_data);
		}

		g_hash_table_remove(routing_table_aid, package);
	}
}

static void _routing_table_iterate(route_table_iter_cb cb, void *user_data)
{
	GHashTableIter iter;
	gpointer key;
	hce_listener_t *data;

	if (routing_table_aid == NULL)
		return;

	g_hash_table_iter_init (&iter, routing_table_aid);

	while (g_hash_table_iter_next (&iter, &key, (gpointer)&data)) {
		if (cb(data, user_data) == false) {
			break;
		}
	}
}

static bool _del_by_id_cb(hce_listener_t *data, void *user_data)
{
	const char *id = user_data;
	bool result;

	if (data->id == NULL) {
		if (id == NULL) {
			DEBUG_MSG("remove context for nfc-manager");

			result = false;
		} else {
			result = true;
		}
	} else {
		if (id != NULL && g_ascii_strcasecmp(data->id, id) == 0) {
			DEBUG_MSG("deleting package [%s:%s]", data->id, data->package);

			_routing_table_del(data->package);

			result = false;
		} else {
			result = true;
		}
	}

	return result;
}

static void _routing_table_del_by_id(const char *id)
{
	_routing_table_iterate(_del_by_id_cb, (char *)id);
}

////////////////////////////////////////////////////////////////////////////////
net_nfc_error_e net_nfc_server_hce_start_hce_handler(const char *package,
	const char *id, net_nfc_server_hce_listener_cb listener,
	net_nfc_server_hce_user_data_destroy_cb destroy_cb, void *user_data)
{
	net_nfc_error_e result;

	if (package == NULL || listener == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	result = _routing_table_add(package, id, listener,
		destroy_cb, user_data);
	if (result == NET_NFC_OK) {
		result = net_nfc_server_route_table_add_handler(id, package);
	}

	return result;
}

net_nfc_error_e net_nfc_server_hce_stop_hce_handler(const char *package)
{
	if (package == NULL || strlen(package) == 0) {
		return NET_NFC_NULL_PARAMETER;
	}

	_routing_table_del(package);

	net_nfc_server_route_table_del_handler(NULL, package, false);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_server_hce_stop_hce_handler_by_id(const char *id)
{
	if (id == NULL || strlen(id) == 0) {
		return NET_NFC_NULL_PARAMETER;
	}

	_routing_table_del_by_id(id);

	net_nfc_server_route_table_del_handler_by_id(id);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_server_hce_send_apdu_response(
	net_nfc_target_handle_s *handle, data_s *response)
{
	net_nfc_error_e result = NET_NFC_OK;

	if (response == NULL || response->buffer == NULL ||
		response->length == 0) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (net_nfc_controller_hce_response_apdu(
		handle, response, &result) == true) {
	} else {
		DEBUG_ERR_MSG("net_nfc_controller_hce_response_apdu failed, [%d]", result);
	}

	return result;
}

////////////////////////////////////////////////////////////////////////////////

static void _emit_event_received_signal(GDBusConnection *connection,
	const char *id, int event,
	net_nfc_target_handle_h handle,
	data_s *data)
{
	GVariant *arg_data;
	GError *error = NULL;

	arg_data = net_nfc_util_gdbus_data_to_variant(data);

	if (g_dbus_connection_emit_signal(
		connection,
		id,
		"/org/tizen/NetNfcService/Hce",
		"org.tizen.NetNfcService.Hce",
		"EventReceived",
		g_variant_new("(uu@a(y))",
			GPOINTER_TO_UINT(handle),
			event,
			arg_data),
		&error) == false) {
		if (error != NULL && error->message != NULL) {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed : %s", error->message);
		} else {
			DEBUG_ERR_MSG("g_dbus_connection_emit_signal failed");
		}
	}
}

static void _hce_default_listener_cb(net_nfc_target_handle_s *handle,
	int event, data_s *data, void *user_data)
{
	hce_client_context_s *context = (hce_client_context_s *)user_data;

	if (context == NULL) {
		return;
	}

	switch (event) {
	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA :
		if (context->id != NULL) {
			/* app is running */
			_emit_event_received_signal(context->connection,
				context->id, event, handle, data);

		} else {
			/* launch app */
			DEBUG_SERVER_MSG("launch apdu app!!");
		}
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED :
	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED :
		DEBUG_SERVER_MSG("HCE %s", event == NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED ? "ACTIVATE" : "DEACTIVATE");

		if (context->id != NULL) {
			/* app is running */
			_emit_event_received_signal(context->connection,
				context->id, event, handle, data);
		}
		break;

	default :
		break;
	}
}

static void _hce_user_data_destroy_cb(void *user_data)
{
	hce_client_context_s *context = user_data;

	if (context != NULL) {
		g_object_unref(context->connection);
		if (context->id != NULL) {
			g_free(context->id);
		}

		g_free(context);
	}
}

static void hce_start_hce_handler_thread_func(gpointer user_data)
{
	HceDataApdu *data = (HceDataApdu *)user_data;
	net_nfc_error_e result;
	const char *id;
	char package[1024];
	pid_t pid;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> hce_start_hce_handler_thread_func!!");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	pid = net_nfc_server_gdbus_get_pid(id);

	if (net_nfc_util_get_pkgid_by_pid(pid, package, sizeof(package)) == true) {
		hce_client_context_s *context;
		GDBusConnection *connection;

		connection = g_dbus_method_invocation_get_connection(data->invocation);

		context = g_new0(hce_client_context_s, 1);
		context->connection = g_object_ref(connection);
		context->id = g_strdup(id);

		result = net_nfc_server_hce_start_hce_handler(package, id,
			_hce_default_listener_cb, _hce_user_data_destroy_cb,
			context);
	} else {
		DEBUG_ERR_MSG("net_nfc_util_get_pkgid_by_pid failed, pid [%d]", pid);

		result = NET_NFC_OPERATION_FAIL;
	}

	net_nfc_gdbus_hce_complete_start_hce_handler(data->object,
		data->invocation, result);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}


static gboolean hce_handle_start_hce_handler(
	NetNfcGDbusHce *object,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege)
{
	HceDataApdu *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(HceDataApdu, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push_force(
		hce_start_hce_handler_thread_func, data) == FALSE)
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
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_hce_complete_start_hce_handler(object, invocation,
		result);

	return TRUE;
}

static void hce_stop_hce_handler_thread_func(gpointer user_data)
{
	HceDataApdu *data = (HceDataApdu *)user_data;
	net_nfc_error_e result;
	const char *id;
	char package[1024];
	pid_t pid;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> hce_stop_hce_handler_thread_func!!");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	pid = net_nfc_server_gdbus_get_pid(id);

	if (net_nfc_util_get_pkgid_by_pid(pid, package, sizeof(package)) == true) {
		result = net_nfc_server_hce_stop_hce_handler(package);
	} else {
		DEBUG_ERR_MSG("net_nfc_util_get_pkgid_by_pid failed, pid [%d]", pid);

		result = NET_NFC_OPERATION_FAIL;
	}

	net_nfc_gdbus_hce_complete_stop_hce_handler(data->object,
		data->invocation, result);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}


static gboolean hce_handle_stop_hce_handler(
	NetNfcGDbusHce *object,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege)
{
	HceDataApdu *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(HceDataApdu, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push_force(
		hce_stop_hce_handler_thread_func, data) == FALSE)
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
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_hce_complete_stop_hce_handler(object, invocation,
		result);

	return TRUE;
}


static void hce_response_apdu_thread_func(gpointer user_data)
{
	HceDataApdu *detail = (HceDataApdu *)user_data;
	data_s apdu_data = { NULL, 0 };
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	INFO_MSG(">>> hce_response_apdu_thread_func!!");

	net_nfc_util_gdbus_variant_to_data_s(detail->data, &apdu_data);

	result = net_nfc_server_hce_send_apdu_response(detail->handle,
		&apdu_data);

	net_nfc_gdbus_hce_complete_response_apdu(
		detail->object,
		detail->invocation,
		result);

	net_nfc_util_clear_data(&apdu_data);

	g_variant_unref(detail->data);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}


static gboolean hce_handle_response_apdu(
	NetNfcGDbusHce *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	GVariant *apdudata,
	GVariant *smack_privilege)
{
	HceDataApdu *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(HceDataApdu, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->handle = (net_nfc_target_handle_s *)arg_handle;
	data->data = g_variant_ref(apdudata);

	if (net_nfc_server_controller_async_queue_push_force(
		hce_response_apdu_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_variant_unref(data->data);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_hce_complete_response_apdu(object, invocation,
		result);

	return TRUE;
}


typedef struct _apdu_header_t
{
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t data[0];
}
__attribute__((packed)) apdu_header_t;

static bool __extract_parameter(apdu_header_t *apdu, size_t len, uint16_t *lc,
	uint16_t *le, uint8_t **data)
{
	size_t l = sizeof(*apdu);
	bool result;

	*lc = -1;
	*le = -1;
	*data = NULL;

	DEBUG_SERVER_MSG("[%02X][%02X][%02X][%02X]", apdu->cla, apdu->ins, apdu->p1, apdu->p2);

	if (len > l) {
		if (len == l + 1) {
			*le = apdu->data[0];

			result = true;
		} else if (apdu->data[0] > 0) {
			l += apdu->data[0] + 1;

			if (l == len || l + 1 == len) {
				*lc = apdu->data[0];
				*data = apdu->data + 1;

				if (l + 1 == len) {
					*le = apdu->data[*lc + 1];
				}

				result = true;
			} else {
				DEBUG_ERR_MSG("l == len || l + 1 == len, [%d/%d]", len, l);

				result = false;
			}
		} else {
			DEBUG_ERR_MSG("apdu->data[0] == %d", apdu->data[0]);

			result = false;
		}
	} else if (len == l) {
		result = true;
	} else {
		DEBUG_ERR_MSG("len > l, [%d/%d]", len, l);

		result = false;
	}

	return result;
}

static bool _route_table_iter_cb(hce_listener_t *data, void *user_data)
{
	ServerHceData *detail = (ServerHceData *)user_data;

	if (data != NULL && data->listener != NULL) {
		data->listener(detail->handle, detail->event, NULL,
			data->user_data);
	}

	return true;
}

static bool __pre_process_apdu(net_nfc_target_handle_s *handle, data_s *cmd)
{
	apdu_header_t *apdu = (apdu_header_t *)cmd->buffer;
	uint16_t lc, le;
	uint8_t *data;
	bool result;

	if (__extract_parameter(apdu, cmd->length, &lc, &le, &data) == true) {
		switch (apdu->ins) {
		case 0x70 :
			DEBUG_ERR_MSG("not supported, [%d]", cmd->length);

			/* send response */
			uint8_t temp[] = { 0x69, 0x00 };
			data_s resp = { temp, sizeof(temp) };

			net_nfc_server_hce_send_apdu_response(handle, &resp);

			result = true; /* completed... skip passing to clients */
			break;

		case NET_NFC_HCE_INS_SELECT :
			if (apdu->p1 == NET_NFC_HCE_P1_SELECT_BY_NAME) {
				if (lc > 2) {
					char aid[1024];
					route_table_handler_t *listener;
					data_s temp = { data, lc };

					net_nfc_util_binary_to_hex_string(&temp, aid, sizeof(aid));

					listener = net_nfc_server_route_table_find_handler_by_aid(aid);
					if (listener != NULL) {
						g_free(selected_aid);
						selected_aid = g_strdup(aid);
					} else {
						DEBUG_ERR_MSG("file not found, [%s]", aid);

						/* send response */
						uint8_t temp[] = { 0x6A, 0x82 };
						data_s resp = { temp, sizeof(temp) };

						net_nfc_server_hce_send_apdu_response(handle, &resp);

						result = true; /* completed... skip passing to clients */
						break;
					}
				} else {
					DEBUG_ERR_MSG("wrong aid length, [%d]", cmd->length);

					/* send response */
					uint8_t temp[] = { 0x6B, 0x00 };
					data_s resp = { temp, sizeof(temp) };

					net_nfc_server_hce_send_apdu_response(handle, &resp);

					result = true; /* completed... skip passing to clients */
					break;
				}
			}
			/* no break */
		default :
			result = false; /* need to pass to client */
			break;
		}
	} else {
		DEBUG_ERR_MSG("wrong apdu length, [%d]", cmd->length);

		/* send response */
		uint8_t temp[] = { 0x67, 0x00 };
		data_s resp = { temp, sizeof(temp) };

		net_nfc_server_hce_send_apdu_response(handle, &resp);

		result = true; /* completed... skip passing to clients */
	}

	return result;
}

static void hce_apdu_thread_func(gpointer user_data)
{
	ServerHceData *data = (ServerHceData *)user_data;

	g_assert(data != NULL);

	if (data->event == NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA) {
		INFO_MSG("[HCE] Command arrived, handle [0x%x], len [%d]", (int)data->handle, data->apdu.length);

		if (__pre_process_apdu(data->handle,
			&data->apdu) == false) {
			/* finished */
			if (selected_aid != NULL) {
				route_table_handler_t *handler;

				handler = net_nfc_server_route_table_find_handler_by_aid(selected_aid);
				if (handler != NULL) {
					hce_listener_t *listener;

					listener = _routing_table_find_aid(handler->package);
					if(listener != NULL)
					{
						listener->listener(data->handle,
							data->event, &data->apdu,
							listener->user_data);
					}
				} else {
					uint8_t temp[] = { 0x69, 0x00 };
					data_s resp = { temp, sizeof(temp) };

					DEBUG_ERR_MSG("?????");

					net_nfc_server_hce_send_apdu_response(data->handle, &resp);
				}
			} else {
				uint8_t temp[] = { 0x69, 0x00 };
				data_s resp = { temp, sizeof(temp) };

				DEBUG_ERR_MSG("no aid selected");

				net_nfc_server_hce_send_apdu_response(data->handle, &resp);
			}
		} else {
			DEBUG_SERVER_MSG("pre-processed data");
		}
	} else {
		INFO_MSG("[HCE] %s!!!!, handle [0x%x]", data->event == NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED ? "Activated" : "Deactivated", (int)data->handle);

		_routing_table_iterate(_route_table_iter_cb, data);

		g_free(selected_aid);
		selected_aid = NULL;
	}

	net_nfc_util_clear_data(&data->apdu);

	g_free(data);
}

void net_nfc_server_hce_apdu_received(void *hce_event)
{
	net_nfc_request_hce_apdu_t *hce_apdu =
		(net_nfc_request_hce_apdu_t *)hce_event;
	net_nfc_target_handle_s *handle;
	ServerHceData *data;

	handle = (net_nfc_target_handle_s *)hce_apdu->user_param;

	data = g_try_new0(ServerHceData, 1);
	if (data != NULL) {

		data->event = hce_apdu->request_type;
		data->handle = handle;

		if (data->event == NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA &&
			hce_apdu->apdu.buffer != NULL &&
			hce_apdu->apdu.length > 0)
		{
			/* APDU from CLF*/
			if (net_nfc_util_init_data(&data->apdu,
				hce_apdu->apdu.length) == true) {
				memcpy(data->apdu.buffer, hce_apdu->apdu.buffer,
					hce_apdu->apdu.length);
			}
		}

		if (net_nfc_server_controller_async_queue_push_force(
			hce_apdu_thread_func, data) == FALSE) {
			DEBUG_ERR_MSG("can not push to controller thread");

			net_nfc_util_clear_data(&data->apdu);

			g_free(data);

			if (hce_apdu->request_type ==
				NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA) {
				uint8_t temp[] = { 0x69, 0x00 };
				data_s resp = { temp, sizeof(temp) };

				net_nfc_server_hce_send_apdu_response(handle, &resp);
			}
		}
	} else {
		DEBUG_ERR_MSG("g_new0 failed");

		if (hce_apdu->request_type ==
			NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA) {
			uint8_t temp[] = { 0x69, 0x00 };
			data_s resp = { temp, sizeof(temp) };

			net_nfc_server_hce_send_apdu_response(handle, &resp);
		}
	}

	net_nfc_util_clear_data(&hce_apdu->apdu);

	_net_nfc_util_free_mem(hce_event);
}

static void _hce_on_client_detached_cb(net_nfc_client_context_info_t *info)
{
	_routing_table_del_by_id(info->id);
}

gboolean net_nfc_server_hce_init(GDBusConnection *connection)
{
	GError *error = NULL;
	gboolean result;

	if (hce_skeleton)
		g_object_unref(hce_skeleton);

	hce_skeleton = net_nfc_gdbus_hce_skeleton_new();

	g_signal_connect(hce_skeleton,
		"handle-start-hce-handler",
		G_CALLBACK(hce_handle_start_hce_handler),
		NULL);

	g_signal_connect(hce_skeleton,
		"handle-stop-hce-handler",
		G_CALLBACK(hce_handle_stop_hce_handler),
		NULL);

	g_signal_connect(hce_skeleton,
		"handle-response-apdu",
		G_CALLBACK(hce_handle_response_apdu),
		NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(hce_skeleton),
		connection,
		"/org/tizen/NetNfcService/Hce",
		&error);

	if (result == TRUE) {
		/*TODO : Make the Routing Table for AID!*/
		/*TODO : Do i have to make other file for routing table?????*/
		_routing_table_init();

		net_nfc_server_gdbus_register_on_client_detached_cb(
			_hce_on_client_detached_cb);
	} else {
		DEBUG_ERR_MSG("can not skeleton_export %s", error->message);

		g_error_free(error);

		net_nfc_server_hce_deinit();
	}

	return result;
}

void net_nfc_server_hce_deinit(void)
{
	if (hce_skeleton)
	{
		net_nfc_server_gdbus_unregister_on_client_detached_cb(
			_hce_on_client_detached_cb);

		g_object_unref(hce_skeleton);
		hce_skeleton = NULL;
	}
}
