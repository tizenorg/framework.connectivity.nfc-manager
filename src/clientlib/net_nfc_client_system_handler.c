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

#include "Ecore_X.h"

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_client.h"
#include "net_nfc_client_util_internal.h"
#include "net_nfc_client_manager.h"
#include "net_nfc_client_system_handler.h"


#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

static NetNfcGDbusPopup *popup_proxy = NULL;
static int popup_state = 0;

static void popup_set_active_callback(GObject *source_object,
	GAsyncResult *res,
	gpointer user_data);

static void popup_set_active_callback(GObject *source_object,
	GAsyncResult *res,
	gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_popup_call_set_finish(
		NET_NFC_GDBUS_POPUP(source_object),
		&result,
		res,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish popup_set_active: %s",
			error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_popup_set_state_callback callback =
			(net_nfc_client_popup_set_state_callback)func_data->callback;

		callback(result, func_data->user_data);
	}

	g_free(func_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_set_state(int state,
	net_nfc_client_popup_set_state_callback callback,
	void *user_data)
{
	NetNfcCallback *func_data;

	if (popup_proxy == NULL)
	{
		if(net_nfc_client_sys_handler_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("popup_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL )
		return NET_NFC_ALLOC_FAIL;

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	net_nfc_gdbus_popup_call_set(popup_proxy,
		state,
		CHECK_FOREGROUND,
		net_nfc_client_gdbus_get_privilege(),
		NULL,
		popup_set_active_callback,
		func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_set_state_sync(int state)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (popup_proxy == NULL)
	{
		if(net_nfc_client_sys_handler_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("popup_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_popup_call_set_sync(popup_proxy,
		state,
		CHECK_FOREGROUND,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call SetActive: %s",
			error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_set_state_force(int state,
	net_nfc_client_popup_set_state_callback callback,
	void *user_data)
{
	NetNfcCallback *func_data;

	if (popup_proxy == NULL)
	{
		if(net_nfc_client_sys_handler_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("popup_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	net_nfc_gdbus_popup_call_set(popup_proxy,
		state,
		NO_CHECK_FOREGROUND,
		net_nfc_client_gdbus_get_privilege(),
		NULL,
		popup_set_active_callback,
		func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_set_state_force_sync(int state)
{
	net_nfc_error_e result;
	GError *error = NULL;

	if (popup_proxy == NULL)
	{
		if(net_nfc_client_sys_handler_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("popup_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_popup_call_set_sync(popup_proxy,
		state,
		NO_CHECK_FOREGROUND,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call SetActive: %s",
			error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_set_launch_popup_state(
	int enable)
{
	popup_state = enable;

	return net_nfc_client_sys_handler_set_state_sync(enable);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_set_launch_popup_state_force(
	int enable)
{
	popup_state = enable;

	return net_nfc_client_sys_handler_set_state_force_sync(enable);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_sys_handler_get_launch_popup_state(
			int *state)
{
	net_nfc_error_e result = NET_NFC_OK;
	gint out_state = NET_NFC_LAUNCH_APP_SELECT;
	GError *error = NULL;

	if (state == NULL)
		return NET_NFC_NULL_PARAMETER;

	*state = NET_NFC_LAUNCH_APP_SELECT;

	if (popup_proxy == NULL) {
		if(net_nfc_client_sys_handler_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("popup_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_popup_call_get_sync(popup_proxy,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		&out_state,
		NULL,
		&error) == true) {
		*state = out_state;
	} else {

		DEBUG_ERR_MSG("net_nfc_gdbus_popup_call_get_sync failed: %s",
				error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

net_nfc_error_e net_nfc_client_sys_handler_init(void)
{
	GError *error = NULL;

	if (popup_proxy)
	{
		DEBUG_CLIENT_MSG("Already initialized");

		return NET_NFC_OK;
	}

	popup_proxy = net_nfc_gdbus_popup_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM,
					G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
					"org.tizen.NetNfcService",
					"/org/tizen/NetNfcService/Popup",
					NULL,
					&error);
	if (popup_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
		g_error_free(error);

		return NET_NFC_OPERATION_FAIL;
	}

	return NET_NFC_OK;
}

void net_nfc_client_sys_handler_deinit(void)
{
	if (popup_proxy)
	{
		g_object_unref(popup_proxy);
		popup_proxy = NULL;
	}
}
