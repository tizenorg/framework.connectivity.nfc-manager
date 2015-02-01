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

#include "net_nfc_gdbus.h"
#include "net_nfc_client.h"
#include "net_nfc_client_util_internal.h"
#include "net_nfc_client_context.h"
#include "net_nfc_client_manager.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

#define DEACTIVATE_DELAY	500 /* ms */
#define ACTIVATE_DELAY 100 /* ms */

typedef struct _ManagerFuncData ManagerFuncData;

struct _ManagerFuncData
{
	gpointer callback;
	gpointer user_data;
	net_nfc_error_e result;
};

static NetNfcGDbusManager *manager_proxy = NULL;
static NetNfcGDbusManager *auto_start_proxy = NULL;
static ManagerFuncData activated_func_data;
static int is_activated = -1;
static guint timeout_id[2];

static void manager_call_set_active_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data);

static void manager_call_get_server_state_callback(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data);


static void manager_activated(NetNfcGDbusManager *manager,
				gboolean activated,
				gpointer user_data);


static gboolean _set_activate_time_elapsed_callback(gpointer user_data)
{
	ManagerFuncData *func_data = (ManagerFuncData *)user_data;
	net_nfc_client_manager_set_active_completed callback;

	if (timeout_id[0] > 0) {
		g_assert(func_data != NULL);

		g_source_remove(timeout_id[0]);
		timeout_id[0] = 0;

		callback = (net_nfc_client_manager_set_active_completed)func_data->callback;

		callback(func_data->result, func_data->user_data);

		g_free(func_data);
	}

	return false;
}

static void manager_call_set_active_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	ManagerFuncData *func_data = (ManagerFuncData *)user_data;
	net_nfc_error_e result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_manager_call_set_active_finish(
				NET_NFC_GDBUS_MANAGER(source_object),
				&result,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish call_set_active: %s",
			error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	func_data->result = result;
	net_nfc_client_get_nfc_state(&is_activated);

	if (is_activated == false) {
		/* FIXME : wait several times */
		timeout_id[0] = g_timeout_add(DEACTIVATE_DELAY,
			_set_activate_time_elapsed_callback,
			func_data);
	} else {
		timeout_id[0] = g_timeout_add(ACTIVATE_DELAY,
			_set_activate_time_elapsed_callback,
			func_data);
	}
}

static void manager_call_get_server_state_callback(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e result;
	guint out_state = 0;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_manager_call_get_server_state_finish(
				NET_NFC_GDBUS_MANAGER(source_object),
				&result,
				&out_state,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish get_server_state: %s",
			error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_manager_get_server_state_completed callback =
			(net_nfc_client_manager_get_server_state_completed)func_data->callback;

		callback(result, out_state, func_data->user_data);
	}

	g_free(func_data);
}

static gboolean _activated_time_elapsed_callback(gpointer user_data)
{
	net_nfc_client_manager_activated callback =
		(net_nfc_client_manager_activated)activated_func_data.callback;

	if (timeout_id[1] > 0) {
		g_source_remove(timeout_id[1]);
		timeout_id[1] = 0;

		callback(is_activated, activated_func_data.user_data);
	}

	return false;
}

static void manager_activated(NetNfcGDbusManager *manager,
				gboolean activated,
				gpointer user_data)
{
	INFO_MSG(">>> SIGNAL arrived");
	DEBUG_CLIENT_MSG("activated %d", activated);

	/* update current state */
	is_activated = (int)activated;

	if (activated_func_data.callback != NULL)
	{
		if (is_activated == false) {
			/* FIXME : wait several times */
			timeout_id[1] = g_timeout_add(DEACTIVATE_DELAY,
				_activated_time_elapsed_callback,
				NULL);
		} else {
			timeout_id[1] = g_timeout_add(ACTIVATE_DELAY,
				_activated_time_elapsed_callback,
				NULL);
		}
	}
}

NET_NFC_EXPORT_API
void net_nfc_client_manager_set_activated(
			net_nfc_client_manager_activated callback,
			void *user_data)
{
	if (callback == NULL)
		return;

	if (manager_proxy == NULL)
	{
		if (net_nfc_client_manager_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("manager_proxy fail");
			/* FIXME : return result of this error */
			return;
		}
	}

	activated_func_data.callback = callback;
	activated_func_data.user_data = user_data;
}

NET_NFC_EXPORT_API
void net_nfc_client_manager_unset_activated(void)
{
	activated_func_data.callback = NULL;
	activated_func_data.user_data = NULL;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_manager_set_active(int state,
			net_nfc_client_manager_set_active_completed callback,
			void *user_data)
{
	gboolean active = FALSE;
	ManagerFuncData *func_data;

	if (auto_start_proxy == NULL) {
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_manager_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/Manager",
			NULL,
			&error);
		if (auto_start_proxy == NULL)
		{
			DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
			g_error_free(error);

			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	/* allow this function even nfc is off */

	func_data = g_try_new0(ManagerFuncData, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	if (state == true)
		active = TRUE;

	net_nfc_gdbus_manager_call_set_active(auto_start_proxy,
		active,
		net_nfc_client_gdbus_get_privilege(),
		NULL,
		manager_call_set_active_callback,
		func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_manager_set_active_sync(int state)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	GError *error = NULL;

	if (auto_start_proxy == NULL) {
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_manager_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/Manager",
			NULL,
			&error);
		if (auto_start_proxy == NULL)
		{
			DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
			g_error_free(error);

			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	/* allow this function even nfc is off */

	if (net_nfc_gdbus_manager_call_set_active_sync(auto_start_proxy,
		(gboolean)state,
		net_nfc_client_gdbus_get_privilege(),
		&out_result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call SetActive: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_manager_get_server_state(
		net_nfc_client_manager_get_server_state_completed callback,
		void *user_data)
{
	NetNfcCallback *func_data;

	if (manager_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->callback = (gpointer) callback;
	func_data->user_data = user_data;

	net_nfc_gdbus_manager_call_get_server_state(manager_proxy,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					manager_call_get_server_state_callback,
					func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_manager_get_server_state_sync(
							unsigned int *state)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	guint out_state = 0;
	GError *error = NULL;

	if (state == NULL)
		return NET_NFC_NULL_PARAMETER;

	*state = 0;

	if (manager_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_manager_call_get_server_state_sync(manager_proxy,
					net_nfc_client_gdbus_get_privilege(),
					&out_result,
					&out_state,
					NULL,
					&error) == TRUE)
	{
		*state = out_state;
	}
	else
	{
		DEBUG_ERR_MSG("can not call GetServerState: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;

}

net_nfc_error_e net_nfc_client_manager_init(void)
{
	GError *error = NULL;

	if (manager_proxy)
	{
		DEBUG_CLIENT_MSG("Already initialized");

		return NET_NFC_OK;
	}

	manager_proxy = net_nfc_gdbus_manager_proxy_new_for_bus_sync(
		G_BUS_TYPE_SYSTEM,
		G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
		"org.tizen.NetNfcService",
		"/org/tizen/NetNfcService/Manager",
		NULL,
		&error);
	if (manager_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
		g_error_free(error);

		return NET_NFC_UNKNOWN_ERROR;
	}

	g_signal_connect(manager_proxy, "activated",
			G_CALLBACK(manager_activated), NULL);

	return NET_NFC_OK;
}

void net_nfc_client_manager_deinit(void)
{
	if (manager_proxy)
	{
		int i;

		for (i = 0; i < 2; i++) {
			if (timeout_id[i] > 0) {
				g_source_remove(timeout_id[i]);
				timeout_id[i] = 0;
			}
		}

		g_object_unref(manager_proxy);
		manager_proxy = NULL;
	}

	if (auto_start_proxy) {
		g_object_unref(auto_start_proxy);
		auto_start_proxy = NULL;
	}
}

/* internal function */
bool net_nfc_client_manager_is_activated()
{
	if (is_activated < 0) {
		net_nfc_client_get_nfc_state(&is_activated);
	}

	return is_activated;
}
