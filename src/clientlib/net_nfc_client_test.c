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
#include "net_nfc_gdbus.h"
#include "net_nfc_client.h"
#include "net_nfc_client_util_internal.h"
#include "net_nfc_client_manager.h"
#include "net_nfc_client_test.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

static void test_call_sim_test_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data);

static void test_call_prbs_test_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data);

static void test_call_get_firmware_version_callback(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data);

static void test_call_set_ee_data_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data);

static void test_call_ese_test_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data);

static NetNfcGDbusTest *test_proxy = NULL;


static void test_call_sim_test_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_test_call_sim_test_finish(
				NET_NFC_GDBUS_TEST(source_object),
				(gint *)&out_result,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish sim_test: %s",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_test_sim_test_completed callback =
			(net_nfc_client_test_sim_test_completed)func_data->callback;

		callback(out_result, func_data->user_data);
	}

	g_free(func_data);
}

static void test_call_prbs_test_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_test_call_prbs_test_finish(
				NET_NFC_GDBUS_TEST(source_object),
				(gint *)&out_result,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish prbs test: %s",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_test_prbs_test_completed callback =
			(net_nfc_client_test_prbs_test_completed)func_data->callback;

		callback(out_result, func_data->user_data);
	}

	g_free(func_data);
}

static void test_call_get_firmware_version_callback(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	gchar *out_version = NULL;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_test_call_get_firmware_version_finish(
				NET_NFC_GDBUS_TEST(source_object),
				(gint *)&out_result,
				&out_version,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish get_firmware_version: %s",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_test_get_firmware_version_completed callback =
			(net_nfc_client_test_get_firmware_version_completed)func_data->callback;

		callback(out_result, out_version, func_data->user_data);
	}

	g_free(out_version);
	g_free(func_data);
}

static void test_call_set_ee_data_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_test_call_set_ee_data_finish(
				NET_NFC_GDBUS_TEST(source_object),
				(gint *)&out_result,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish set_ee_data: %s\n",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_test_set_ee_data_completed callback =
			(net_nfc_client_test_set_ee_data_completed)func_data->callback;

		callback(out_result, func_data->user_data);
	}

	g_free(func_data);
}

static void test_call_ese_test_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_test_call_ese_test_finish(
				NET_NFC_GDBUS_TEST(source_object),
				(gint *)&out_result,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish sim_test: %s",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_test_ese_test_completed callback =
			(net_nfc_client_test_ese_test_completed)func_data->callback;

		callback(out_result, func_data->user_data);
	}

	g_free(func_data);
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_sim_test(
			net_nfc_client_test_sim_test_completed callback,
			void *user_data)
{
	NetNfcCallback *func_data;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
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

	net_nfc_gdbus_test_call_sim_test(test_proxy,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					test_call_sim_test_callback,
					func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_sim_test_sync(void)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	GError *error = NULL;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_test_call_sim_test_sync(test_proxy,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call SimTest: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_prbs_test(uint32_t tech,
			uint32_t rate,
			net_nfc_client_test_prbs_test_completed callback,
			void *user_data)
{
	NetNfcCallback *func_data;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
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

	net_nfc_gdbus_test_call_prbs_test(test_proxy,
					tech,
					rate,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					test_call_prbs_test_callback,
					func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_prbs_test_sync(uint32_t tech,
						uint32_t rate)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	GError *error = NULL;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_test_call_prbs_test_sync(test_proxy,
					tech,
					rate,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call PrbsTest: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_get_firmware_version(
		net_nfc_client_test_get_firmware_version_completed callback,
		void *user_data)
{
	NetNfcCallback *func_data;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
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

	net_nfc_gdbus_test_call_get_firmware_version(test_proxy,
				net_nfc_client_gdbus_get_privilege(),
				NULL,
				test_call_get_firmware_version_callback,
				func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_get_firmware_version_sync(char **version)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	gchar *out_version = NULL;
	GError *error = NULL;

	if (version == NULL)
		return NET_NFC_NULL_PARAMETER;

	*version = NULL;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_test_call_get_firmware_version_sync(test_proxy,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					&out_version,
					NULL,
					&error) == TRUE)
	{
		*version = out_version;
	}
	else
	{
		DEBUG_ERR_MSG("can not call Get Firmware version: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_set_ee_data(int mode,
			int reg_id,
			data_h data,
			net_nfc_client_test_set_ee_data_completed callback,
			void *user_data)
{
	NetNfcCallback *func_data;
	GVariant *variant;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL) {
		return NET_NFC_ALLOC_FAIL;
	}

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	variant = net_nfc_util_gdbus_data_to_variant((data_s *)data);

	net_nfc_gdbus_test_call_set_ee_data(test_proxy,
					mode,
					reg_id,
					variant,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					test_call_set_ee_data_callback,
					func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_set_ee_data_sync(int mode,
						int reg_id,
						data_h data)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	GVariant *variant = NULL;
	GError *error = NULL;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	variant = net_nfc_util_gdbus_data_to_variant((data_s *)data);

	if (net_nfc_gdbus_test_call_set_ee_data_sync(test_proxy,
					mode,
					reg_id,
					variant,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call SetEeTest: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_ese_test(
			net_nfc_client_test_ese_test_completed callback,
			void *user_data)
{
	NetNfcCallback *func_data;

	DEBUG_CLIENT_MSG("NFC ESE Test!!!!");

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
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

	net_nfc_gdbus_test_call_ese_test(test_proxy,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					test_call_ese_test_callback,
					func_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_ese_test_sync(void)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	GError *error = NULL;

	DEBUG_CLIENT_MSG("NFC ESE Test SYNC!!!!");

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_test_call_ese_test_sync(test_proxy,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call ESE Test: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_test_set_se_tech_type_sync(
	net_nfc_se_type_e type, int tech)
{
	net_nfc_error_e out_result = NET_NFC_OK;
	GError *error = NULL;

	if (test_proxy == NULL)
	{
		if(net_nfc_client_test_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("test_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_test_call_set_se_tech_type_sync(test_proxy,
					(guint32)type,
					(guint32)tech,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not call SetSeTechType: %s",
				error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

net_nfc_error_e net_nfc_client_test_init(void)
{
	GError *error = NULL;

	if (test_proxy)
	{
		DEBUG_CLIENT_MSG("Already initialized");

		return NET_NFC_OK;
	}

	test_proxy = net_nfc_gdbus_test_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM,
					G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
					"org.tizen.NetNfcService",
					"/org/tizen/NetNfcService/Test",
					NULL,
					&error);
	if (test_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
		g_error_free(error);

		return NET_NFC_UNKNOWN_ERROR;
	}

	return NET_NFC_OK;
}

void net_nfc_client_test_deinit(void)
{
	if (test_proxy)
	{
		g_object_unref(test_proxy);
		test_proxy = NULL;
	}
}
