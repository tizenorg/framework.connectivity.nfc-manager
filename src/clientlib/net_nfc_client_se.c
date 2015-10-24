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
#include "net_nfc_client_se.h"


#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

typedef struct _SeFuncData SeFuncData;

struct _SeFuncData
{
	gpointer se_callback;
	gpointer se_data;
};

typedef struct _SeEventHandler SeEventHandler;

struct _SeEventHandler
{
	net_nfc_client_se_event se_event_cb;
	gpointer se_event_data;
};

typedef struct _SeTransEventHandler SeTransEventHandler;

struct _SeTransEventHandler
{
	net_nfc_client_se_transaction_event transaction_event_cb;
	gpointer transaction_event_data;
};

typedef struct _SeESEDetectedHandler SeESEDetectedHandler;

struct _SeESEDetectedHandler
{
	net_nfc_client_se_ese_detected_event se_ese_detected_cb;
	gpointer se_ese_detected_data;
};


static NetNfcGDbusSecureElement *se_proxy = NULL;
static NetNfcGDbusSecureElement *auto_start_proxy = NULL;

static SeEventHandler se_eventhandler;
static SeTransEventHandler uicc_transactionEventHandler;
static SeTransEventHandler ese_transactionEventHandler;
static SeESEDetectedHandler se_esedetecthandler;

static void se_ese_detected(GObject *source_object,
			guint arg_handle,
			gint arg_se_type,
			GVariant *arg_data);

static void se_type_changed(GObject *source_object,
				gint arg_se_type);

static void set_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void open_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void close_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void send_apdu_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void get_atr_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void se_rf_detected(GObject *source_object,
			gint arg_se_type,
			GVariant *arg_data);


static void se_ese_detected(GObject *source_object,
			guint arg_handle,
			gint arg_se_type,
			GVariant *arg_data)
{
	INFO_MSG(">>> SIGNAL arrived");

	if (se_esedetecthandler.se_ese_detected_cb != NULL) {
		data_s buffer_data = { NULL, 0 };
		net_nfc_client_se_ese_detected_event callback =
			(net_nfc_client_se_ese_detected_event)se_esedetecthandler.se_ese_detected_cb;

		net_nfc_util_gdbus_variant_to_data_s(arg_data, &buffer_data);

		callback((net_nfc_target_handle_h)arg_handle,
			arg_se_type, &buffer_data,
			se_esedetecthandler.se_ese_detected_data);

		net_nfc_util_clear_data(&buffer_data);
	}
}

static void se_rf_detected(GObject *source_object,
			gint arg_se_type,
			GVariant *arg_data)
{

	INFO_MSG(">>> SIGNAL arrived");

	if (se_eventhandler.se_event_cb != NULL)
	{
		net_nfc_client_se_event callback =
			(net_nfc_client_se_event)se_eventhandler.se_event_cb;

		callback((net_nfc_message_e)NET_NFC_MESSAGE_SE_FIELD_ON,
			se_eventhandler.se_event_data);
	}
}


static void se_type_changed(GObject *source_object,
			gint arg_se_type)
{
	INFO_MSG(">>> SIGNAL arrived");

	if (se_eventhandler.se_event_cb != NULL)
	{
		net_nfc_client_se_event callback =
			(net_nfc_client_se_event)se_eventhandler.se_event_cb;

		callback((net_nfc_message_e)NET_NFC_MESSAGE_SE_TYPE_CHANGED,
			se_eventhandler.se_event_data);
	}
}


static void se_transaction_event(GObject *source_object,
	gint arg_se_type,
	GVariant *arg_aid,
	GVariant *arg_param,
	gint fg_dispatch,
	gint focus_app_pid)
{
	void *user_data = NULL;
	net_nfc_client_se_transaction_event callback = NULL;
	GError *error = NULL;
	gint result = 0;
	pid_t mypid = getpid();

	INFO_MSG(">>> SIGNAL arrived");

	if (fg_dispatch == true && focus_app_pid != getpgid(mypid)) {
		DEBUG_MSG("skip transaction event, fg_dispatch [%d], focus_app_pid [%d]", fg_dispatch, focus_app_pid);
		return;
	}

	if (net_nfc_gdbus_secure_element_call_check_transaction_permission_sync(
		NET_NFC_GDBUS_SECURE_ELEMENT(source_object),
		arg_aid,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == false) {
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_check_transaction_permission_sync failed : %s", error->message);
		g_error_free(error);
		return;
	}

	if (result != NET_NFC_OK) {
		DEBUG_ERR_MSG("not allowed process [%d]", result);
		return;
	}

	switch (arg_se_type)
	{
	case NET_NFC_SE_TYPE_UICC :
		if (uicc_transactionEventHandler.transaction_event_cb != NULL)
		{
			callback = uicc_transactionEventHandler.transaction_event_cb;
			user_data = uicc_transactionEventHandler.transaction_event_data;
		}
		break;

	case NET_NFC_SE_TYPE_ESE :
		if (ese_transactionEventHandler.transaction_event_cb != NULL)
		{
			callback = ese_transactionEventHandler.transaction_event_cb;
			user_data = ese_transactionEventHandler.transaction_event_data;
		}
		break;

	default :
		DEBUG_ERR_MSG("Transaction event SE type wrong [%d]", arg_se_type);
		break;
	}

	if (callback != NULL) {
		data_s aid = { NULL, 0 };
		data_s param = { NULL, 0 };

		net_nfc_util_gdbus_variant_to_data_s(arg_aid, &aid);
		net_nfc_util_gdbus_variant_to_data_s(arg_param, &param);

		callback(arg_se_type, &aid, &param, user_data);

		net_nfc_util_clear_data(&param);
		net_nfc_util_clear_data(&aid);
	}
}

static void se_card_emulation_mode_changed(GObject *source_object,
			gint arg_se_type)
{
	INFO_MSG(">>> SIGNAL arrived");

	if (se_eventhandler.se_event_cb != NULL)
	{
		net_nfc_client_se_event callback =
			(net_nfc_client_se_event)se_eventhandler.se_event_cb;

		callback((net_nfc_message_e)NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED,
			se_eventhandler.se_event_data);
	}
}

static void set_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	SeFuncData *func_data = (SeFuncData *)user_data;
	net_nfc_error_e result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_secure_element_call_set_finish(se_proxy,
		&result,
		res,
		&error) == FALSE)
	{

		DEBUG_ERR_MSG("Could not set secure element: %s",
				error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->se_callback != NULL)
	{
		net_nfc_se_set_se_cb se_callback =
			(net_nfc_se_set_se_cb)func_data->se_callback;

		se_callback(result, func_data->se_data);
	}

	g_free(func_data);
}

static void open_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	SeFuncData *func_data = (SeFuncData *)user_data;
	net_nfc_error_e result;
	guint out_handle = 0;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_secure_element_call_open_secure_element_finish(
		auto_start_proxy,
		&result,
		&out_handle,
		res,
		&error) == FALSE)
	{

		DEBUG_ERR_MSG("Could not open secure element: %s",
				error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->se_callback != NULL)
	{
		net_nfc_se_open_se_cb se_callback =
			(net_nfc_se_open_se_cb)func_data->se_callback;

		se_callback(result,
			(net_nfc_target_handle_h)out_handle,
			func_data->se_data);
	}

	g_free(func_data);
}


static void close_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	SeFuncData *func_data = (SeFuncData *)user_data;
	net_nfc_error_e result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_secure_element_call_close_secure_element_finish(
		se_proxy,
		&result,
		res,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Could not close secure element: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->se_callback != NULL)
	{
		net_nfc_se_close_se_cb se_callback =
			(net_nfc_se_close_se_cb)func_data->se_callback;

		se_callback(result, func_data->se_data);
	}

	g_free(func_data);
}


static void send_apdu_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	SeFuncData *func_data = (SeFuncData *)user_data;
	net_nfc_error_e result;
	GVariant *out_response = NULL;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_secure_element_call_send_apdu_finish(
		se_proxy,
		&result,
		&out_response,
		res,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Could not send apdu: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->se_callback != NULL)
	{
		net_nfc_se_send_apdu_cb se_callback =
			(net_nfc_se_send_apdu_cb)func_data->se_callback;
		data_s data = { NULL, };

		net_nfc_util_gdbus_variant_to_data_s(out_response, &data);

		se_callback(result, &data, func_data->se_data);

		net_nfc_util_clear_data(&data);
	}

	g_free(func_data);
}


static void get_atr_secure_element(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	SeFuncData *func_data = (SeFuncData *)user_data;
	net_nfc_error_e result;
	GVariant *out_atr = NULL;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_secure_element_call_get_atr_finish(
		se_proxy,
		&result,
		&out_atr,
		res,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Could not get atr: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->se_callback != NULL)
	{
		net_nfc_se_get_atr_cb se_callback =
			(net_nfc_se_get_atr_cb)func_data->se_callback;
		data_s data = { NULL, };

		net_nfc_util_gdbus_variant_to_data_s(out_atr, &data);

		se_callback(result, &data, func_data->se_data);

		net_nfc_util_clear_data(&data);
	}

	g_free(func_data);
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_set_secure_element_type(
				net_nfc_se_type_e se_type,
				net_nfc_se_set_se_cb callback,
				void *user_data)
{
	SeFuncData *func_data;

	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			/* FIXME : return result of this error */
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	func_data = g_try_new0(SeFuncData, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->se_callback = (gpointer)callback;
	func_data->se_data = user_data;

	net_nfc_gdbus_secure_element_call_set(
				se_proxy,
				(gint)se_type,
				net_nfc_client_gdbus_get_privilege(),
				NULL,
				set_secure_element,
				func_data);

	return NET_NFC_OK;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_set_secure_element_type_sync(
				net_nfc_se_type_e se_type)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_secure_element_call_set_sync(
			se_proxy,
			(gint)se_type,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("Set secure element failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_get_secure_element_type_sync(
	net_nfc_se_type_e *se_type)
{
	net_nfc_error_e result = NET_NFC_OK;
	gint type;
#if 1
	GError *error = NULL;
#endif
	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}
#if 0
	if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &type) == 0) {
		*se_type = type;
	} else {
		result = NET_NFC_OPERATION_FAIL;
	}
#else
	if (net_nfc_gdbus_secure_element_call_get_sync(
			se_proxy,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&type,
			NULL,
			&error) == true) {

		DEBUG_CLIENT_MSG("type [%d]", type);
		*se_type = type;
	} else {
		DEBUG_ERR_MSG("get secure element failed: %s", error->message);

		g_error_free(error);

		result = NET_NFC_IPC_FAIL;
	}
#endif
	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_set_card_emulation_mode_sync(
	net_nfc_card_emulation_mode_t mode)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_secure_element_call_set_card_emulation_sync(
			se_proxy,
			(gint)mode,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("Set card emulation failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_card_emulation_mode_sync(
	net_nfc_card_emulation_mode_t *se_type)
{
	net_nfc_error_e result = NET_NFC_OK;
	gint type;
	GError *error = NULL;

	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_secure_element_call_get_card_emulation_sync(
			se_proxy,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&type,
			NULL,
			&error) == true) {
		*se_type = type;
	} else {
		DEBUG_ERR_MSG("get secure element failed: %s", error->message);

		g_error_free(error);

		result = NET_NFC_IPC_FAIL;
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_open_internal_secure_element(
					net_nfc_se_type_e se_type,
					net_nfc_se_open_se_cb callback,
					void *user_data)
{
	SeFuncData *func_data;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	func_data = g_try_new0(SeFuncData, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->se_callback = (gpointer)callback;
	func_data->se_data = user_data;

	net_nfc_gdbus_secure_element_call_open_secure_element(
					auto_start_proxy,
					(gint)se_type,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					open_secure_element,
					func_data);

	return NET_NFC_OK;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_open_internal_secure_element_sync(
					net_nfc_se_type_e se_type,
					net_nfc_target_handle_h *handle)
{
	net_nfc_error_e result = NET_NFC_OK;
	guint out_handle = 0;
	GError *error =  NULL;

	if (handle == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	if (net_nfc_gdbus_secure_element_call_open_secure_element_sync(
					auto_start_proxy,
					se_type,
					net_nfc_client_gdbus_get_privilege(),
					&result,
					&out_handle,
					NULL,
					&error) == true) {
		*handle = GUINT_TO_POINTER(out_handle);
	} else {
		DEBUG_ERR_MSG("Open internal secure element failed: %s",
					error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_close_internal_secure_element(
				net_nfc_target_handle_h handle,
				net_nfc_se_close_se_cb callback,
				void *user_data)
{
	SeFuncData *func_data;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	func_data = g_try_new0(SeFuncData, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->se_callback = (gpointer)callback;
	func_data->se_data = user_data;

	net_nfc_gdbus_secure_element_call_close_secure_element(
		auto_start_proxy,
		GPOINTER_TO_UINT(handle),
		net_nfc_client_gdbus_get_privilege(),
		NULL,
		close_secure_element,
		func_data);

	return NET_NFC_OK;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_close_internal_secure_element_sync(
					net_nfc_target_handle_h handle)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	if (net_nfc_gdbus_secure_element_call_close_secure_element_sync(
		auto_start_proxy,
		GPOINTER_TO_UINT(handle),
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("close internal secure element failed: %s",
					error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_get_atr(
				net_nfc_target_handle_h handle,
				net_nfc_se_get_atr_cb callback,
				void *user_data)
{
	SeFuncData *func_data;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	func_data = g_try_new0(SeFuncData, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->se_callback = (gpointer)callback;
	func_data->se_data = user_data;

	net_nfc_gdbus_secure_element_call_get_atr(
		auto_start_proxy,
		GPOINTER_TO_UINT(handle),
		net_nfc_client_gdbus_get_privilege(),
		NULL,
		get_atr_secure_element,
		func_data);

	return NET_NFC_OK;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_get_atr_sync(
				net_nfc_target_handle_h handle,
				data_h *atr)
{
	net_nfc_error_e result = NET_NFC_OK;
	GVariant *out_atr = NULL;
	GError *error = NULL;

	if (atr == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	*atr = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	if (net_nfc_gdbus_secure_element_call_get_atr_sync(
		auto_start_proxy,
		GPOINTER_TO_UINT(handle),
		net_nfc_client_gdbus_get_privilege(),
		&result,
		&out_atr,
		NULL,
		&error) == true) {
		*atr = net_nfc_util_gdbus_variant_to_data(out_atr);
	} else {
		DEBUG_ERR_MSG("Get attributes failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_send_apdu(
				net_nfc_target_handle_h handle,
				data_h apdu_data,
				net_nfc_se_send_apdu_cb callback,
				void *user_data)
{
	SeFuncData *func_data;
	GVariant *arg_data;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	arg_data = net_nfc_util_gdbus_data_to_variant((data_s *)apdu_data);
	if (arg_data == NULL)
		return NET_NFC_INVALID_PARAM;

	func_data = g_try_new0(SeFuncData, 1);
	if (func_data == NULL) {
		g_variant_unref(arg_data);

		return NET_NFC_ALLOC_FAIL;
	}

	func_data->se_callback = (gpointer)callback;
	func_data->se_data = user_data;

	net_nfc_gdbus_secure_element_call_send_apdu(
		auto_start_proxy,
		GPOINTER_TO_UINT(handle),
		arg_data,
		net_nfc_client_gdbus_get_privilege(),
		NULL,
		send_apdu_secure_element,
		func_data);

	return NET_NFC_OK;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_send_apdu_sync(
				net_nfc_target_handle_h handle,
				data_h apdu_data,
				data_h *response)
{
	net_nfc_error_e result = NET_NFC_OK;
	GVariant *out_data = NULL;
	GError *error = NULL;
	GVariant *arg_data;

	if (response == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	*response = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
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

	arg_data = net_nfc_util_gdbus_data_to_variant((data_s *)apdu_data);
	if (arg_data == NULL)
		return NET_NFC_INVALID_PARAM;

	if (net_nfc_gdbus_secure_element_call_send_apdu_sync(
		auto_start_proxy,
		GPOINTER_TO_UINT(handle),
		arg_data,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		&out_data,
		NULL,
		&error) == true) {
		*response = net_nfc_util_gdbus_variant_to_data(out_data);
	} else {
		DEBUG_ERR_MSG("Send APDU failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}


NET_NFC_EXPORT_API
void net_nfc_client_se_set_ese_detection_cb(
			net_nfc_client_se_ese_detected_event callback,
			void *user_data)
{
	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			/* FIXME : return result of this error */
			return;
		}
	}

	se_esedetecthandler.se_ese_detected_cb = callback;
	se_esedetecthandler.se_ese_detected_data = user_data;
}


NET_NFC_EXPORT_API
void net_nfc_client_se_unset_ese_detection_cb(void)
{
	se_esedetecthandler.se_ese_detected_cb = NULL;
	se_esedetecthandler.se_ese_detected_data = NULL;
}


NET_NFC_EXPORT_API
void net_nfc_client_se_set_transaction_event_cb(
			net_nfc_se_type_e se_type,
			net_nfc_client_se_transaction_event callback,
			void *user_data)
{
	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			/* FIXME : return result of this error */
			return;
		}
	}

	if (se_type == NET_NFC_SE_TYPE_ESE)
	{
		ese_transactionEventHandler.transaction_event_cb = callback;
		ese_transactionEventHandler.transaction_event_data = user_data;
	}
	else if (se_type == NET_NFC_SE_TYPE_UICC)
	{
		uicc_transactionEventHandler.transaction_event_cb = callback;
		uicc_transactionEventHandler.transaction_event_data = user_data;
	}
}


NET_NFC_EXPORT_API
void net_nfc_client_se_unset_transaction_event_cb(net_nfc_se_type_e type)
{
	if (type == NET_NFC_SE_TYPE_ESE)
	{
		ese_transactionEventHandler.transaction_event_cb = NULL;
		ese_transactionEventHandler.transaction_event_data = NULL;
	}
	else if (type == NET_NFC_SE_TYPE_UICC)
	{
		uicc_transactionEventHandler.transaction_event_cb = NULL;
		uicc_transactionEventHandler.transaction_event_data = NULL;
	}
}

NET_NFC_EXPORT_API
void net_nfc_client_se_set_event_cb(net_nfc_client_se_event callback,
					void *user_data)
{
	if (se_proxy == NULL)
	{
		if (net_nfc_client_se_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("se_proxy fail");
			/* FIXME : return result of this error */
			return;
		}
	}

	se_eventhandler.se_event_cb = callback;
	se_eventhandler.se_event_data = user_data;
}


NET_NFC_EXPORT_API
void net_nfc_client_se_unset_event_cb(void)
{
	se_eventhandler.se_event_cb = NULL;
	se_eventhandler.se_event_data = NULL;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_set_transaction_fg_dispatch(int mode)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
			NULL,
			&error);
		if (auto_start_proxy == NULL)
		{
			DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
			g_error_free(error);

			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	if (net_nfc_gdbus_secure_element_call_set_transaction_fg_dispatch_sync(
		auto_start_proxy,
		mode,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) != true) {

		DEBUG_ERR_MSG("set transaction fg dispatch failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_set_default_route_sync(
	net_nfc_se_type_e switch_on,
	net_nfc_se_type_e switch_off,
	net_nfc_se_type_e battery_off)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (se_proxy == NULL)
	{
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_set_default_route_sync(
		se_proxy,
		switch_on,
		switch_off,
		battery_off,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Set Route Aid failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	DEBUG_CLIENT_MSG("net_nfc_gdbus_secure_element_call_set_default_route_sync end");

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_is_activated_aid_handler_sync(
	net_nfc_se_type_e se_type, const char *aid, bool *activated)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;
	gboolean ret = false;

	if (activated == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_is_activated_aid_handler_sync(
			se_proxy,
			se_type,
			aid,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&ret,
			NULL,
			&error) == true) {
		*activated = ret;
	} else {
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_is_activated_aid_handler_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_is_activated_category_handler_sync(
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, bool *activated)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;
	gboolean ret = false;

	if (activated == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_is_activated_category_handler_sync(
			se_proxy,
			se_type,
			category,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&ret,
			NULL,
			&error) == true) {
		*activated = ret;
	} else {
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_is_activated_category_handler_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_get_registered_aids_count_sync(
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	size_t *count)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;
	GVariant *aids = NULL;

	if (count == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_get_registered_aids_sync(
			se_proxy,
			se_type,
			category,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&aids,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_get_registered_aids_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (result == NET_NFC_OK) {
		GVariantIter iter;

		g_variant_iter_init(&iter, aids);

		*count = g_variant_iter_n_children(&iter);

		g_variant_unref(aids);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_foreach_registered_aids_sync(
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	net_nfc_client_se_registered_aid_cb callback,
	void *user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;
	GVariant *aids = NULL;

	if (callback == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_get_registered_aids_sync(
			se_proxy,
			se_type,
			category,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&aids,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_get_registered_aids_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (result == NET_NFC_OK) {
		GVariantIter iter;
		const gchar *aid;
		gboolean manifest;

		g_variant_iter_init(&iter, aids);

		while (g_variant_iter_loop(&iter, "(sb)", &aid, &manifest) == true) {
			callback(se_type, aid, (bool)manifest, user_data);
		}
	}

	return result;
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_register_aids_sync(net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid, ...)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_register_aid_sync(
			se_proxy,
			se_type,
			category,
			aid,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_register_aid_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_unregister_aid_sync(net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_unregister_aid_sync(
			se_proxy,
			se_type,
			category,
			aid,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_unregister_aid_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_unregister_aids_sync(net_nfc_se_type_e se_type, net_nfc_card_emulation_category_t category)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_unregister_aids_sync(
			se_proxy,
			se_type,
			category,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_unregister_aids_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_foreach_registered_handlers_sync(
	net_nfc_card_emulation_category_t category,
	net_nfc_client_se_registered_handler_cb callback,
	void *user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;
	GVariant *handlers = NULL;

	if (callback == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (se_proxy == NULL) {
		result = net_nfc_client_se_init();
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_client_se_init failed, [%d]", result);

			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (net_nfc_gdbus_secure_element_call_get_registered_handlers_sync(
			se_proxy,
			category,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&handlers,
			NULL,
			&error) == FALSE)
	{
		DEBUG_ERR_MSG("net_nfc_gdbus_secure_element_call_get_registered_handlers_sync failed : %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (result == NET_NFC_OK) {
		GVariantIter iter;
		const gchar *handler;

		g_variant_iter_init(&iter, handlers);

		while (g_variant_iter_loop(&iter, "(s)", &handler) == true) {
			callback(handler, user_data);
		}
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_add_route_aid_sync(
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid,
	bool unlock_required, int power)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
			NULL,
			&error);
		if (auto_start_proxy == NULL)
		{
			DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
			g_error_free(error);

			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	if (net_nfc_gdbus_secure_element_call_add_route_aid_sync(
		auto_start_proxy,
		package,
		aid,
		se_type,
		category,
		unlock_required,
		power,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Set Route Aid failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	DEBUG_CLIENT_MSG("net_nfc_gdbus_secure_element_call_add_route_aid_sync end");

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_remove_route_aid_sync(
	const char *package, const char *aid)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
			NULL,
			&error);
		if (auto_start_proxy == NULL)
		{
			DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
			g_error_free(error);

			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	if (net_nfc_gdbus_secure_element_call_remove_route_aid_sync(
		auto_start_proxy,
		package,
		aid,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Remove Route Aid failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	DEBUG_CLIENT_MSG("net_nfc_gdbus_hce_call_set_route_aid_sync end");

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_se_remove_package_aids_sync(
	const char *package)
{
	net_nfc_error_e result = NET_NFC_OK;
	GError *error = NULL;

	if (auto_start_proxy == NULL)
	{
		GError *error = NULL;

		auto_start_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
			G_BUS_TYPE_SYSTEM,
			G_DBUS_PROXY_FLAGS_NONE,
			"org.tizen.NetNfcService",
			"/org/tizen/NetNfcService/SecureElement",
			NULL,
			&error);
		if (auto_start_proxy == NULL)
		{
			DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
			g_error_free(error);

			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	if (net_nfc_gdbus_secure_element_call_remove_package_aids_sync(
		auto_start_proxy,
		package,
		net_nfc_client_gdbus_get_privilege(),
		&result,
		NULL,
		&error) == FALSE)
	{
		DEBUG_ERR_MSG("Remove Package Aid failed: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	DEBUG_CLIENT_MSG("net_nfc_client_se_remove_package_aids_sync end");

	return result;
}


net_nfc_error_e net_nfc_client_se_init(void)
{
	GError *error = NULL;

	if (se_proxy)
	{
		DEBUG_CLIENT_MSG("Already initialized");

		return NET_NFC_OK;
	}

	se_proxy = net_nfc_gdbus_secure_element_proxy_new_for_bus_sync(
				G_BUS_TYPE_SYSTEM,
				G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
				"org.tizen.NetNfcService",
				"/org/tizen/NetNfcService/SecureElement",
				NULL,
				&error);
	if (se_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);

		g_error_free(error);

		return NET_NFC_UNKNOWN_ERROR;
	}

	g_signal_connect(se_proxy, "se-type-changed",
		G_CALLBACK(se_type_changed), NULL);

	g_signal_connect(se_proxy, "ese-detected",
		G_CALLBACK(se_ese_detected), NULL);

	g_signal_connect(se_proxy, "transaction-event",
		G_CALLBACK(se_transaction_event), NULL);

	g_signal_connect(se_proxy, "card-emulation-mode-changed",
		G_CALLBACK(se_card_emulation_mode_changed), NULL);

	g_signal_connect(se_proxy, "rf-detected",
		G_CALLBACK(se_rf_detected), NULL);

	return NET_NFC_OK;
}


void net_nfc_client_se_deinit(void)
{
	if (se_proxy)
	{
		g_object_unref(se_proxy);
		se_proxy = NULL;
	}

	if (auto_start_proxy)
	{
		g_object_unref(auto_start_proxy);
		auto_start_proxy = NULL;
	}
}
