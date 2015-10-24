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

#include "vconf.h"

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_client.h"
#include "net_nfc_client_util_internal.h"
#include "net_nfc_client_manager.h"
#include "net_nfc_client_hce.h"


#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

typedef struct _HceHandler HceHandler;

struct _HceHandler
{
	net_nfc_client_hce_event_cb hce_event_cb;
	gpointer hce_data;
};

static NetNfcGDbusHce *hce_proxy = NULL;

static HceHandler hce_handler;
static char package_name[1024];

static void __load_package_name()
{
	if (net_nfc_util_get_pkgid_by_pid(getpid(),
		package_name, sizeof(package_name)) == false) {
		DEBUG_ERR_MSG("failed to get package name, pid [%d]", getpid());
	}
}

static void hce_event_received(GObject *source_object, guint arg_handle,
	guint arg_event, GVariant *arg_apdu, gchar *arg_package)
{
	INFO_MSG(">>> SIGNAL arrived hce_apdu_receive");

	if (hce_handler.hce_event_cb != NULL) {

		data_s apdu = { NULL, 0 };

		net_nfc_util_gdbus_variant_to_data_s(arg_apdu, &apdu);

		hce_handler.hce_event_cb((net_nfc_target_handle_h)arg_handle,
			(net_nfc_hce_event_t)arg_event, &apdu,
			hce_handler.hce_data);

		net_nfc_util_clear_data(&apdu);
	}
}



NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_hce_set_event_received_cb(
	net_nfc_client_hce_event_cb callback, void *user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	DEBUG_CLIENT_MSG("net_nfc_client_hce_set_event_received_cb set");

	if (hce_proxy == NULL)
	{
		result = net_nfc_client_hce_init();
		if (result != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("net_nfc_client_hce_init failed, [%d]", result);

			return result;
		}
	}

	if (net_nfc_gdbus_hce_call_start_hce_handler_sync(hce_proxy,
		net_nfc_client_gdbus_get_privilege(), &result,
		NULL, &error) == true) {
		hce_handler.hce_event_cb = callback;
		hce_handler.hce_data = user_data;
	} else {
		DEBUG_ERR_MSG("net_nfc_gdbus_hce_call_start_hce_handler_sync failed: %s", error->message);
		g_error_free(error);

		result = NET_NFC_IPC_FAIL;
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_hce_unset_event_received_cb(void)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (hce_proxy == NULL) {
		DEBUG_ERR_MSG("not initialized!!!");
		return NET_NFC_NOT_INITIALIZED;
	}

	if (net_nfc_gdbus_hce_call_stop_hce_handler_sync(hce_proxy,
		net_nfc_client_gdbus_get_privilege(), &result,
		NULL, &error) == true) {
		hce_handler.hce_event_cb = NULL;
		hce_handler.hce_data = NULL;
	} else {
		DEBUG_ERR_MSG("net_nfc_gdbus_hce_call_stop_hce_handler_sync failed: %s", error->message);
		g_error_free(error);

		result = NET_NFC_IPC_FAIL;
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_hce_response_apdu_sync(
				net_nfc_target_handle_h handle,
				data_h resp_apdu_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;
	GVariant *arg_data = NULL;

	INFO_MSG(">>> net_nfc_client_hce_response_apdu_sync!!");

	if (hce_proxy == NULL)
	{
		result = net_nfc_client_hce_init();
		if (result != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("net_nfc_client_hce_init failed, [%d]", result);

			return result;
		}
	}

	arg_data = net_nfc_util_gdbus_data_to_variant((data_s *)resp_apdu_data);
	if (arg_data == NULL)
	{

		INFO_MSG(">>> resp_apdu_data is null !!");
		return NET_NFC_INVALID_PARAM;
	}

	if (net_nfc_gdbus_hce_call_response_apdu_sync(
		hce_proxy,
		GPOINTER_TO_UINT(handle),
		arg_data,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == true) {
	} else {
		DEBUG_ERR_MSG("Response APDU failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

net_nfc_error_e net_nfc_client_hce_init(void)
{
	GError *error = NULL;

	DEBUG_CLIENT_MSG("net_nfc_client_hce_init call");

	if (hce_proxy)
	{
		DEBUG_CLIENT_MSG("Already initialized");

		return NET_NFC_OK;
	}

	hce_proxy = net_nfc_gdbus_hce_proxy_new_for_bus_sync(
				G_BUS_TYPE_SYSTEM,
				G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
				"org.tizen.NetNfcService",
				"/org/tizen/NetNfcService/Hce",
				NULL,
				&error);

	if (hce_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);

		g_error_free(error);

		return NET_NFC_UNKNOWN_ERROR;
	}

	g_signal_connect(hce_proxy, "event-received",
		G_CALLBACK(hce_event_received), NULL);

	/* get package name */
	__load_package_name();

	return NET_NFC_OK;
}

void net_nfc_client_hce_deinit(void)
{
	if (hce_proxy != NULL)
	{
		g_object_unref(hce_proxy);
		hce_proxy = NULL;
	}
}
