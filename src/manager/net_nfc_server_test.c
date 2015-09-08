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
#include "net_nfc_server_test.h"

typedef struct _TestData TestData;

struct _TestData
{
	NetNfcGDbusTest *test;
	GDBusMethodInvocation *invocation;
};

typedef struct _TestPrbsData TestPrbsData;

struct _TestPrbsData
{
	NetNfcGDbusTest *test;
	GDBusMethodInvocation *invocation;
	guint32 tech;
	guint32 rate;
};

typedef struct _TestSetEeData TestSetEeData;

struct _TestSetEeData
{
	NetNfcGDbusTest *test;
	GDBusMethodInvocation *invocation;

	guint32 mode;
	guint32 reg_id;
	data_s data;
};

static void test_handle_sim_test_thread_func(gpointer user_data);

static void test_handle_prbs_test_thread_func(gpointer user_data);

static void test_handle_get_firmware_version_thread_func(gpointer user_data);

static void test_handle_set_ee_data_thread_func(gpointer user_data);


static gboolean test_handle_sim_test(NetNfcGDbusTest *test,
				GDBusMethodInvocation *invocation,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean test_handle_prbs_test(NetNfcGDbusTest *test,
				GDBusMethodInvocation *invocation,
				guint32 arg_tech,
				guint32 arg_rate,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean test_handle_get_firmware_version(NetNfcGDbusTest *test,
				GDBusMethodInvocation *invocation,
				GVariant *smack_privilege,
				gpointer user_data);

static gboolean test_handle_set_ee_data(NetNfcGDbusTest *test,
				GDBusMethodInvocation *invocation,
				guint32 mode,
				guint32 reg_id,
				GVariant *variant,
				GVariant *smack_privilege,
				gpointer user_data);


static NetNfcGDbusTest *test_skeleton = NULL;

static void test_handle_sim_test_thread_func(gpointer user_data)
{
	TestData *data = (TestData *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->test != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_sim_test(&result);

	net_nfc_gdbus_test_complete_sim_test(data->test,
		data->invocation,
		(gint)result);

	g_object_unref(data->invocation);
	g_object_unref(data->test);

	g_free(data);
}

static void test_handle_prbs_test_thread_func(gpointer user_data)
{
	TestPrbsData *data = (TestPrbsData *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->test != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_prbs_test(&result, data->tech, data->rate);

	net_nfc_gdbus_test_complete_prbs_test(data->test,
		data->invocation,
		(gint)result);

	g_object_unref(data->invocation);
	g_object_unref(data->test);

	g_free(data);
}

static void test_handle_get_firmware_version_thread_func(gpointer user_data)
{
	TestData *data = (TestData *)user_data;
	data_s *tmp_data = NULL;
	net_nfc_error_e result = NET_NFC_OK;
	gchar *version = NULL;

	g_assert(data != NULL);
	g_assert(data->test != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_get_firmware_version(&tmp_data, &result);

	if (tmp_data)
	{
		version = g_new0(gchar, tmp_data->length +1);
		memcpy((void *)version, tmp_data->buffer, tmp_data->length);

		net_nfc_util_free_data(tmp_data);
	}
	else
	{
		version = g_strdup("");
	}

	net_nfc_gdbus_test_complete_get_firmware_version(data->test,
		data->invocation,
		(gint)result,
		version);

	g_free(version);

	g_object_unref(data->invocation);
	g_object_unref(data->test);

	g_free(data);
}

static void test_handle_set_ee_data_thread_func(gpointer user_data)
{
	TestSetEeData *data = (TestSetEeData *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->test != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_eedata_register_set(&result,
		data->mode,
		data->reg_id,
		&data->data);

	net_nfc_gdbus_test_complete_set_ee_data(data->test,
		data->invocation,
		(gint)result);

	net_nfc_util_clear_data(&data->data);

	g_object_unref(data->invocation);
	g_object_unref(data->test);

	g_free(data);
}

static void test_handle_ese_test_thread_func(gpointer user_data)
{
	TestData *data = (TestData *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	DEBUG_SERVER_MSG("test_handle_ese_test_thread_func working!!");

	g_assert(data != NULL);
	g_assert(data->test != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_ese_test(&result);

	net_nfc_gdbus_test_complete_ese_test(data->test,
		data->invocation,
		(gint)result);

	g_object_unref(data->invocation);
	g_object_unref(data->test);

	g_free(data);
}


static gboolean test_handle_sim_test(NetNfcGDbusTest *test,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege,
	gpointer user_data)
{
	TestData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	DEBUG_SERVER_MSG("sim_test");

	data = g_try_new0(TestData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->test = g_object_ref(test);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		test_handle_sim_test_thread_func, data) == FALSE)
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
		g_object_unref(data->test);

		g_free(data);
	}

	net_nfc_gdbus_test_complete_sim_test(test, invocation, result);

	return TRUE;
}

static gboolean test_handle_prbs_test(NetNfcGDbusTest *test,
	GDBusMethodInvocation *invocation,
	guint32 arg_tech,
	guint32 arg_rate,
	GVariant *smack_privilege,
	gpointer user_data)
{
	TestPrbsData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	DEBUG_SERVER_MSG("prbs_test");

	data = g_try_new0(TestPrbsData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->test = g_object_ref(test);
	data->invocation = g_object_ref(invocation);
	data->tech = arg_tech;
	data->rate = arg_rate;

	if (net_nfc_server_controller_async_queue_push(
		test_handle_prbs_test_thread_func, data) == FALSE)
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
		g_object_unref(data->test);

		g_free(data);
	}

	net_nfc_gdbus_test_complete_prbs_test(test, invocation, result);

	return TRUE;
}

static gboolean test_handle_get_firmware_version(NetNfcGDbusTest *test,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege,
	gpointer user_data)
{
	TestData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(TestData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->test = g_object_ref(test);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		test_handle_get_firmware_version_thread_func, data) == FALSE)
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
		g_object_unref(data->test);

		g_free(data);
	}

	net_nfc_gdbus_test_complete_get_firmware_version(test,
		invocation,
		result,
		NULL);

	return TRUE;
}

static gboolean test_handle_set_ee_data(NetNfcGDbusTest *test,
	GDBusMethodInvocation *invocation,
	guint32 mode,
	guint32 reg_id,
	GVariant *variant,
	GVariant *smack_privilege,
	gpointer user_data)
{
	TestSetEeData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(TestSetEeData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->test = g_object_ref(test);
	data->invocation = g_object_ref(invocation);
	data->mode = mode;
	data->reg_id = reg_id;
	net_nfc_util_gdbus_variant_to_data_s(variant, &data->data);

	if (net_nfc_server_controller_async_queue_push(
		test_handle_set_ee_data_thread_func, data) == FALSE)
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
		g_object_unref(data->test);

		g_free(data);
	}

	net_nfc_gdbus_test_complete_set_ee_data(test, invocation, result);

	return TRUE;
}

static gboolean test_handle_ese_test(NetNfcGDbusTest *test,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege,
	gpointer user_data)
{
	TestData *data = NULL;
	gint result;

	INFO_MSG(">>> ESE TEST REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));
#if 0
	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}
#endif
	DEBUG_SERVER_MSG("ese_test");

	data = g_try_new0(TestData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->test = g_object_ref(test);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		test_handle_ese_test_thread_func, data) == FALSE)
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
		g_object_unref(data->test);

		g_free(data);
	}

	net_nfc_gdbus_test_complete_ese_test(test, invocation, result);

	return TRUE;
}

static void test_handle_set_se_tech_type_thread_func(gpointer user_data)
{
	TestSetEeData *data = (TestSetEeData *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->test != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_controller_test_set_se_tech_type(&result,
		(net_nfc_se_type_e)data->mode, data->reg_id);

	net_nfc_gdbus_test_complete_set_se_tech_type(data->test,
		data->invocation,
		(gint)result);

	g_object_unref(data->invocation);
	g_object_unref(data->test);

	g_free(data);
}

static gboolean test_handle_set_se_tech_type(NetNfcGDbusTest *test,
	GDBusMethodInvocation *invocation,
	guint32 type,
	guint32 tech,
	GVariant *smack_privilege,
	gpointer user_data)
{
	TestSetEeData *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(TestSetEeData, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->test = g_object_ref(test);
	data->invocation = g_object_ref(invocation);
	data->mode = type;
	data->reg_id = tech;

	if (net_nfc_server_controller_async_queue_push(
		test_handle_set_se_tech_type_thread_func, data) == FALSE)
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
		g_object_unref(data->test);

		g_free(data);
	}

	net_nfc_gdbus_test_complete_set_se_tech_type(test, invocation, result);

	return TRUE;
}

gboolean net_nfc_server_test_init(GDBusConnection *connection)
{
	GError *error = NULL;
	gboolean result;

	if (test_skeleton)
		g_object_unref(test_skeleton);

	test_skeleton = net_nfc_gdbus_test_skeleton_new();

	g_signal_connect(test_skeleton,
			"handle-sim-test",
			G_CALLBACK(test_handle_sim_test),
			NULL);

	g_signal_connect(test_skeleton,
			"handle-prbs-test",
			G_CALLBACK(test_handle_prbs_test),
			NULL);

	g_signal_connect(test_skeleton,
			"handle-get-firmware-version",
			G_CALLBACK(test_handle_get_firmware_version),
			NULL);

	g_signal_connect(test_skeleton,
			"handle-set-ee-data",
			G_CALLBACK(test_handle_set_ee_data),
			NULL);

	g_signal_connect(test_skeleton,
			"handle-ese-test",
			G_CALLBACK(test_handle_ese_test),
			NULL);

	g_signal_connect(test_skeleton,
			"handle-set-se-tech-type",
			G_CALLBACK(test_handle_set_se_tech_type),
			NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(test_skeleton),
		connection,
		"/org/tizen/NetNfcService/Test",
		&error);
	if (result == FALSE)
	{
		DEBUG_ERR_MSG("Can not skeleton_export %s", error->message);
		g_error_free(error);
		g_object_unref(test_skeleton);

		test_skeleton = NULL;
	}

	return result;
}

void net_nfc_server_test_deinit(void)
{
	if (test_skeleton)
	{
		g_object_unref(test_skeleton);
		test_skeleton = NULL;
	}
}
