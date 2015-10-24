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

#include <libintl.h>

#include <notification.h>
#include <vconf.h>

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_manager_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_app_util_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_p2p.h"

#define CHECK_PRESENCE_DELAY	50 /* ms */

typedef struct _CurrentTagInfoData CurrentTagInfoData;

struct _CurrentTagInfoData
{
	NetNfcGDbusTag *tag;
	GDBusMethodInvocation *invocation;
};

typedef struct _CheckPresenceData CheckPresenceData;

struct _CheckPresenceData
{
	net_nfc_target_type_e dev_type;
	net_nfc_target_handle_s *handle;
};

static gboolean tag_read_ndef_message(net_nfc_target_handle_s *handle,
				int dev_type,
				data_s **read_ndef);

static void tag_check_presence_thread_func(gpointer user_data);

static void tag_get_current_tag_info_thread_func(gpointer user_data);

static void tag_slave_target_detected_thread_func(gpointer user_data);


/* methods */
static gboolean tag_handle_is_tag_connected(NetNfcGDbusTag *tag,
					GDBusMethodInvocation *invocation,
					GVariant *smack_privilege,
					gpointer user_data);

static gboolean tag_handle_get_barcode(NetNfcGDbusTag *tag,
					GDBusMethodInvocation *invocation,
					GVariant *smack_privilege,
					gpointer user_data);

static gboolean tag_handle_get_current_tag_info(NetNfcGDbusTag *tag,
					GDBusMethodInvocation *invocation,
					GVariant *smack_privilege,
					gpointer user_data);

static gboolean tag_handle_get_current_target_handle(NetNfcGDbusTag *tag,
					GDBusMethodInvocation *invocation,
					GVariant *smack_privilege,
					gpointer user_data);

static NetNfcGDbusTag *tag_skeleton = NULL;

static net_nfc_current_target_info_s *current_target_info = NULL;
#if 0
static gboolean tag_is_isp_dep_ndef_formatable(net_nfc_target_handle_s *handle,
					int dev_type)
{
	uint8_t cmd[] = { 0x90, 0x60, 0x00, 0x00, 0x00 };

	net_nfc_transceive_info_s info;
	data_s *response = NULL;
	net_nfc_error_e error = NET_NFC_OK;
	gboolean result = false;

	info.dev_type = dev_type;
	info.trans_data.buffer = cmd;
	info.trans_data.length = sizeof(cmd);

	if (net_nfc_controller_transceive(handle,
				&info,
				&response,
				&error) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_transceive is failed");

		return result;
	}

	if (response != NULL)
	{
		if (response->length == 9 &&
			response->buffer[7] == (uint8_t)0x91 &&
			response->buffer[8] == (uint8_t)0xAF)
		{
			result =  TRUE;
		}

		net_nfc_util_free_data(response);
	}
	else
	{
		DEBUG_ERR_MSG("response is NULL");
	}

	return result;
}
#endif
static gboolean tag_read_ndef_message(net_nfc_target_handle_s *handle,
				int dev_type,
				data_s **read_ndef)
{
	net_nfc_error_e result = NET_NFC_OK;
	data_s *temp = NULL;

	if (handle == NULL)
		return FALSE;

	if (read_ndef == NULL)
		return FALSE;

	*read_ndef = NULL;

	if (dev_type == NET_NFC_MIFARE_DESFIRE_PICC)
	{
#if 0
		if (tag_is_isp_dep_ndef_formatable(handle, dev_type) == FALSE)
		{
			DEBUG_ERR_MSG(
				"DESFIRE : ISO-DEP ndef not formatable");
			return FALSE;
		}

		DEBUG_SERVER_MSG("DESFIRE : ISO-DEP ndef formatable");
#endif
		if (net_nfc_controller_connect(handle, &result) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_connect failed");
#if 0
			DEBUG_ERR_MSG("net_nfc_controller_connect failed, & retry polling!!");

			if (net_nfc_controller_configure_discovery(
						NET_NFC_DISCOVERY_MODE_RESUME,
						NET_NFC_ALL_ENABLE,
						&result) == false)
			{
				net_nfc_controller_exception_handler();
			}
#endif
			return FALSE;
		}
	}

	if (net_nfc_controller_read_ndef(handle, &temp, &result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_read_ndef failed, [%d]", result);

		return FALSE;
	}

	DEBUG_SERVER_MSG("net_nfc_controller_read_ndef success");

	if (dev_type == NET_NFC_MIFARE_DESFIRE_PICC)
	{
		if (net_nfc_controller_connect(handle, &result) == false)
		{
			DEBUG_ERR_MSG("net_nfc_controller_connect failed");
#if 0
			DEBUG_ERR_MSG("net_nfc_controller_connect failed, & retry polling!!");

			if (net_nfc_controller_configure_discovery(
						NET_NFC_DISCOVERY_MODE_RESUME,
						NET_NFC_ALL_ENABLE,
						&result) == false)
			{
				net_nfc_controller_exception_handler();
			}
#endif
			if (temp)
			{
				net_nfc_util_free_data(temp);
				temp = NULL;
			}

			return FALSE;
		}
	}

	*read_ndef = temp;

	return TRUE;
}

static void tag_check_presence_thread_func(gpointer user_data)
{
	CheckPresenceData *data = (CheckPresenceData *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_target_handle_s *handle;

	g_assert(data != NULL);
	g_assert(data->handle != NULL);

	handle = data->handle;

	if (handle->connection_type == NET_NFC_P2P_CONNECTION_TARGET ||
		handle->connection_type == NET_NFC_TAG_CONNECTION)
	{
		bool present = false;

		present = net_nfc_controller_check_target_presence(
			handle, &result);
		if (present == true) {
			net_nfc_server_controller_async_queue_delayed_push_force(
				CHECK_PRESENCE_DELAY,
				tag_check_presence_thread_func,
				user_data);
		} else {
			INFO_MSG("all tags were detached");

			if (result != NET_NFC_NOT_INITIALIZED &&
				result != NET_NFC_INVALID_HANDLE)
			{
				if (net_nfc_controller_disconnect(handle,
					&result) == false)
				{
					DEBUG_ERR_MSG("try to disconnect result = [%d]", result);
#if 0
					net_nfc_controller_exception_handler();
#endif
				}
			}

			goto END;
		}
	} else {
		DEBUG_ERR_MSG("abnormal state");

		goto END;
	}

	return;

END :
	net_nfc_server_free_target_info();

	net_nfc_server_set_state(NET_NFC_SERVER_IDLE);

	net_nfc_gdbus_tag_emit_tag_detached(tag_skeleton,
		GPOINTER_TO_UINT(handle),
		data->dev_type);

	g_free(data);
}

static data_s *_get_barcode_from_target_info(net_nfc_current_target_info_s *target_info)
{
	gint i = 0;
	gint length;
	data_s *data = NULL;
	gchar *str = NULL;
	guint8 *pos = target_info->target_info_values.buffer;

	while (i < target_info->number_of_keys)
	{
		/* key */
		length = *pos; /* first values is length of key */
		pos++;

		str = g_new0(gchar, length + 1);
		memcpy(str, pos, length);

		DEBUG_CLIENT_MSG("key = [%s]", str);

		pos += length;

		length = *pos; /* first value is length of value */
		pos++;

		if(strncmp(str, "UID", 3) == 0 && length > 0)
		{
			data = (data_s *)calloc(1, sizeof(data_s));
			if(data == NULL)
				return NULL;

			data->length = length;

			data->buffer = (uint8_t *)calloc(data->length, sizeof(uint8_t));
			if(data->buffer == NULL)
			{
				free(data);
				return NULL;
			}

			memcpy(data->buffer, pos, data->length);

			break;
		}

		pos += length;
		i++;
	}

	if(str != NULL)
		g_free(str);

	return data;
}

static void tag_get_barcode_thread_func(gpointer user_data)
{
	data_s *data = NULL;
	net_nfc_current_target_info_s *target_info;
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;
	CurrentTagInfoData *info_data = (CurrentTagInfoData *)user_data;

	g_assert(info_data != NULL);
	g_assert(info_data->tag != NULL);
	g_assert(info_data->invocation != NULL);

	target_info = net_nfc_server_get_target_info();
	if(target_info != NULL)
	{
		if (target_info->devType == NET_NFC_BARCODE_128_PICC ||
			target_info->devType == NET_NFC_BARCODE_256_PICC)
		{
			data = _get_barcode_from_target_info(target_info);

			if(data != NULL && data->length != 0 && data->buffer != NULL)
				result = NET_NFC_OK;
		}
		else
		{
			result = NET_NFC_NOT_SUPPORTED;
		}
	}
	else
	{
		result = NET_NFC_NOT_CONNECTED;
	}

	net_nfc_gdbus_tag_complete_get_barcode(info_data->tag,
		info_data->invocation,
		result,
		net_nfc_util_gdbus_data_to_variant(data));

	if (data != NULL) {
		net_nfc_util_free_data(data);
	}

	g_object_unref(info_data->invocation);
	g_object_unref(info_data->tag);

	g_free(info_data);
}

static void tag_get_current_tag_info_thread_func(gpointer user_data)
{
	CurrentTagInfoData *info_data =
		(CurrentTagInfoData *)user_data;

	/* FIXME : net_nfc_current_target_info_s should be removed */
	net_nfc_current_target_info_s *target_info;
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;
	net_nfc_target_handle_s *handle = NULL;
	net_nfc_target_type_e dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean is_ndef_supported = FALSE;
	guint8 ndef_card_state = 0;
	guint32 max_data_size = 0;
	guint32 actual_data_size = 0;
	gint number_of_keys = 0;
	data_s target_info_values = { NULL, 0 };
	data_s *raw_data = NULL;

	g_assert(info_data != NULL);
	g_assert(info_data->tag != NULL);
	g_assert(info_data->invocation != NULL);

	target_info = net_nfc_server_get_target_info();
	if (target_info != NULL &&
		target_info->devType != NET_NFC_NFCIP1_TARGET &&
		target_info->devType != NET_NFC_NFCIP1_INITIATOR)
	{
		handle = target_info->handle;
		number_of_keys = target_info->number_of_keys;

		target_info_values.buffer = target_info->target_info_values.buffer;
		target_info_values.length = target_info->target_info_values.length;

		dev_type = target_info->devType ;

		if (net_nfc_controller_check_ndef(target_info->handle,
					&ndef_card_state,
					(int *)&max_data_size,
					(int *)&actual_data_size,
					&result) == true)
		{
			is_ndef_supported = TRUE;
		}

		if (is_ndef_supported)
		{
			if (net_nfc_controller_read_ndef(target_info->handle,
					&raw_data, &result) == true)
			{
				DEBUG_SERVER_MSG("%s is success",
						"net_nfc_controller_read_ndef");
			}
		}
	}

	net_nfc_gdbus_tag_complete_get_current_tag_info(info_data->tag,
		info_data->invocation,
		result,
		(dev_type != NET_NFC_UNKNOWN_TARGET),
		GPOINTER_TO_UINT(handle),
		dev_type,
		is_ndef_supported,
		ndef_card_state,
		max_data_size,
		actual_data_size,
		number_of_keys,
		net_nfc_util_gdbus_data_to_variant(&target_info_values),
		net_nfc_util_gdbus_data_to_variant(raw_data));

	if (raw_data != NULL) {
		net_nfc_util_free_data(raw_data);
	}

	g_object_unref(info_data->invocation);
	g_object_unref(info_data->tag);

	g_free(info_data);
}

static bool _is_supported_tags(net_nfc_current_target_info_s *target)
{
	return true;
}

static void _start_check_presence(net_nfc_current_target_info_s *target)
{
	CheckPresenceData *presence_data = NULL;

	/* start polling tags presence */
	INFO_MSG("start polling tags presence");

	presence_data = g_new0(CheckPresenceData, 1);
	presence_data->dev_type = target->devType;
	presence_data->handle = target->handle;

	net_nfc_server_controller_async_queue_delayed_push_force(
		CHECK_PRESENCE_DELAY,
		tag_check_presence_thread_func,
		presence_data);
}

static bool _process_attached_tags(net_nfc_current_target_info_s *target)
{
	net_nfc_error_e result = NET_NFC_OK;

	guint32 max_data_size = 0;
	guint32 actual_data_size = 0;
	guint8 ndef_card_state = 0;
	gboolean is_ndef_supported = FALSE;

	GVariant *target_info_values = NULL;
	GVariant *raw_data = NULL;

	net_nfc_server_set_target_info(target);
	target = net_nfc_server_get_target_info();

	g_assert(target != NULL);

	if (net_nfc_controller_connect(target->handle, &result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_connect failed, [%d]", result);
#if 0
		DEBUG_ERR_MSG("net_nfc_controller_connect failed & Retry Polling!!");

		if (net_nfc_controller_configure_discovery(
					NET_NFC_DISCOVERY_MODE_RESUME,
					NET_NFC_ALL_ENABLE,
					&result) == false)
		{
			net_nfc_controller_exception_handler();
		}
#endif
		return false;
	}

	net_nfc_server_set_state(NET_NFC_TAG_CONNECTED);

	INFO_MSG("tags are connected");

	target_info_values = net_nfc_util_gdbus_buffer_to_variant(
			target->target_info_values.buffer,
			target->target_info_values.length);
#if 1
	if (_is_supported_tags(target) == true) {
#endif
		is_ndef_supported = net_nfc_controller_check_ndef(target->handle,
			&ndef_card_state,
			(int *)&max_data_size,
			(int *)&actual_data_size,
			&result);
		if (is_ndef_supported)
		{
			data_s *recv_data = NULL;

			DEBUG_SERVER_MSG("support NDEF");

			if (tag_read_ndef_message(target->handle,
						target->devType,
						&recv_data) == TRUE)
			{
				net_nfc_app_util_process_ndef(recv_data);
				raw_data = net_nfc_util_gdbus_data_to_variant(recv_data);

				net_nfc_util_free_data(recv_data);
			}
			else
			{
				DEBUG_ERR_MSG("tag_read_ndef_message failed");
				raw_data = net_nfc_util_gdbus_buffer_to_variant(NULL, 0);
			}
		}
		else
		{
			/* raw-data of empty ndef msseages */
			uint8_t empty[] = { 0xd0, 0x00, 0x00 };
			data_s empty_data = { empty, sizeof(empty) };

			DEBUG_SERVER_MSG("not support NDEF");

			net_nfc_app_util_process_ndef(&empty_data);
			raw_data = net_nfc_util_gdbus_data_to_variant(&empty_data);
		}
#if 1
	} else {
		INFO_MSG("unsupported tags are attached");

		net_nfc_app_util_show_notification(IDS_SIGNAL_1, NULL);

		raw_data = net_nfc_util_gdbus_buffer_to_variant(NULL, 0);
	}
#endif

	if (tag_skeleton != NULL) {
		/* send TagDiscoverd signal */
		net_nfc_gdbus_tag_emit_tag_discovered(tag_skeleton,
			GPOINTER_TO_UINT(target->handle),
			target->devType,
			is_ndef_supported,
			ndef_card_state,
			max_data_size,
			actual_data_size,
			target->number_of_keys,
			target_info_values,
			raw_data);

		net_nfc_manager_util_play_sound(NET_NFC_TASK_START);
	} else {
		DEBUG_ERR_MSG("tag skeleton is not initialized");
	}

	return true;
}

static void tag_slave_target_detected_thread_func(gpointer user_data)
{
	net_nfc_current_target_info_s *target =
		(net_nfc_current_target_info_s *)user_data;

#if 0
	if (_is_supported_tags(target) == true) {
#endif
		if (_process_attached_tags(target) == false) {
			DEBUG_ERR_MSG("_process_attached_tags failed");
		}
#if 0
	} else {
		INFO_MSG("unsupported tags are attached");

		net_nfc_app_util_show_notification(IDS_SIGNAL_1);

	}
#endif

	_start_check_presence(target);

	g_free(user_data);
}


static gboolean tag_handle_is_tag_connected(NetNfcGDbusTag *tag,
					GDBusMethodInvocation *invocation,
					GVariant *smack_privilege,
					gpointer user_data)
{
	/* FIXME : net_nfc_current_target_info_s should be removed */
	net_nfc_current_target_info_s *target_info;
	net_nfc_target_type_e dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean is_connected = FALSE;
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

		goto END;
	}

	target_info = net_nfc_server_get_target_info();
	if (target_info != NULL)
	{
		dev_type = target_info->devType;
		is_connected = TRUE;
	}

	result = NET_NFC_OK;

END :
	net_nfc_gdbus_tag_complete_is_tag_connected(tag,
		invocation,
		result,
		is_connected,
		(gint32)dev_type);

	return TRUE;
}

static gboolean tag_handle_get_barcode(NetNfcGDbusTag *tag,
				GDBusMethodInvocation *invocation,
				GVariant *smack_privilege,
				gpointer user_data)
{
	CurrentTagInfoData *info_data = NULL;
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

	info_data = g_try_new0(CurrentTagInfoData, 1);
	if (info_data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	info_data->tag = g_object_ref(tag);
	info_data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		tag_get_barcode_thread_func, info_data) == FALSE)
	{
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}
	return TRUE;

ERROR :

	if (info_data != NULL) {
		g_object_unref(info_data->invocation);
		g_object_unref(info_data->tag);

		g_free(info_data);
	}

	net_nfc_gdbus_tag_complete_get_barcode(tag,
		invocation,
		result,
		net_nfc_util_gdbus_data_to_variant(NULL));

	return TRUE;
}

static gboolean tag_handle_get_current_tag_info(NetNfcGDbusTag *tag,
				GDBusMethodInvocation *invocation,
				GVariant *smack_privilege,
				gpointer user_data)
{
	CurrentTagInfoData *info_data = NULL;
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

	info_data = g_try_new0(CurrentTagInfoData, 1);
	if (info_data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	info_data->tag = g_object_ref(tag);
	info_data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		tag_get_current_tag_info_thread_func, info_data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (info_data != NULL) {
		g_object_unref(info_data->invocation);
		g_object_unref(info_data->tag);

		g_free(info_data);
	}

	net_nfc_gdbus_tag_complete_get_current_tag_info(tag,
		invocation,
		result,
		false,
		GPOINTER_TO_UINT(NULL),
		NET_NFC_UNKNOWN_TARGET,
		false,
		0,
		0,
		0,
		0,
		net_nfc_util_gdbus_buffer_to_variant(NULL, 0),
		net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static gboolean tag_handle_get_current_target_handle(NetNfcGDbusTag *tag,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege,
	gpointer user_data)
{
	/* FIXME : net_nfc_current_target_info_s should be removed */
	net_nfc_current_target_info_s *target_info;
	net_nfc_target_handle_s *handle = NULL;
	uint32_t devType = NET_NFC_UNKNOWN_TARGET;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::p2p",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto END;
	}

	target_info = net_nfc_server_get_target_info();
	if (target_info != NULL)
	{
		handle = target_info->handle;
		devType = target_info->devType;
	}

	result = NET_NFC_OK;

END :
	net_nfc_gdbus_tag_complete_get_current_target_handle(tag,
		invocation,
		result,
		(handle != NULL),
		GPOINTER_TO_UINT(handle),
		devType);

	return TRUE;
}


gboolean net_nfc_server_tag_init(GDBusConnection *connection)
{
	GError *error = NULL;
	gboolean result;

	if (tag_skeleton)
		net_nfc_server_tag_deinit();

	tag_skeleton = net_nfc_gdbus_tag_skeleton_new();

	g_signal_connect(tag_skeleton,
			"handle-is-tag-connected",
			G_CALLBACK(tag_handle_is_tag_connected),
			NULL);

	g_signal_connect(tag_skeleton,
			"handle-get-barcode",
			G_CALLBACK(tag_handle_get_barcode),
			NULL);

	g_signal_connect(tag_skeleton,
			"handle-get-current-tag-info",
			G_CALLBACK(tag_handle_get_current_tag_info),
			NULL);

	g_signal_connect(tag_skeleton,
			"handle-get-current-target-handle",
			G_CALLBACK(tag_handle_get_current_target_handle),
			NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(tag_skeleton),
		connection,
		"/org/tizen/NetNfcService/Tag",
		&error);
	if (result == FALSE)
	{
		DEBUG_ERR_MSG("can not skeleton_export %s", error->message);

		g_error_free(error);

		net_nfc_server_tag_deinit();
	}

	return result;
}

void net_nfc_server_tag_deinit(void)
{
	if (tag_skeleton)
	{
		g_object_unref(tag_skeleton);
		tag_skeleton = NULL;
	}
}

void net_nfc_server_set_target_info(net_nfc_current_target_info_s *info)
{
	if (current_target_info)
		g_free(current_target_info);

	current_target_info = g_malloc0(sizeof(net_nfc_current_target_info_s) +
		info->target_info_values.length);

	current_target_info->handle = info->handle;
	current_target_info->devType = info->devType;

	if (current_target_info->devType != NET_NFC_NFCIP1_INITIATOR &&
			current_target_info->devType != NET_NFC_NFCIP1_TARGET)
	{
		current_target_info->number_of_keys = info->number_of_keys;
		current_target_info->target_info_values.length =
			info->target_info_values.length;

		memcpy(&current_target_info->target_info_values,
			&info->target_info_values,
			current_target_info->target_info_values.length + sizeof(int));
	}
}

net_nfc_current_target_info_s *net_nfc_server_get_target_info(void)
{
	return current_target_info;
}

gboolean net_nfc_server_target_connected(net_nfc_target_handle_s *handle)
{
	if (current_target_info == NULL)
		return FALSE;

	if (current_target_info->handle != handle)
		return FALSE;

	return TRUE;
}

void net_nfc_server_free_target_info(void)
{
	g_free(current_target_info);
	current_target_info = NULL;
}

bool net_nfc_server_tag_target_detected(void *info)
{
	if (net_nfc_server_controller_async_queue_push_force(
		tag_slave_target_detected_thread_func, info) == FALSE)
	{
		DEBUG_ERR_MSG("can not push to controller thread");
		return false;
	}

	return true;
}
