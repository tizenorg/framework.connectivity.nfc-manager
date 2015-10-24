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
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_data.h"
#include "net_nfc_target_info.h"
#include "net_nfc_client.h"
#include "net_nfc_client_util_internal.h"
#include "net_nfc_client_manager.h"
#include "net_nfc_client_tag.h"
#include "net_nfc_client_tag_internal.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

static NetNfcGDbusTag *tag_proxy = NULL;

static NetNfcCallback tag_discovered_func_data;
static NetNfcCallback tag_detached_func_data;

static net_nfc_target_info_s *client_target_info = NULL;
static net_nfc_event_filter_e client_filter = NET_NFC_ALL_ENABLE;

static gboolean tag_check_filter(net_nfc_target_type_e type);

static void tag_get_info_list(guint8 *buffer,
			gint number_of_keys,
			net_nfc_tag_info_s **list);

static void tag_get_target_info(guint handle,
				guint dev_type,
				gboolean is_ndef_supported,
				guchar ndef_card_state,
				guint max_data_size,
				guint actual_data_size,
				guint number_of_keys,
				GVariant *target_info_values,
				GVariant *raw_data,
				net_nfc_target_info_s **info);

#if 0
/* async callback */
static void tag_is_tag_connected(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void tag_get_current_tag_info(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void tag_get_current_target_handle(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data);
#endif
/* signal callback */
static void tag_tag_discovered(NetNfcGDbusTag *object,
			guint arg_handle,
			gint arg_dev_type,
			gboolean arg_is_ndef_supported,
			guchar arg_ndef_card_state,
			guint arg_max_data_size,
			guint arg_actual_data_size,
			guint arg_number_of_keys,
			GVariant *arg_target_info_values,
			GVariant *arg_raw_data,
			gpointer user_data);

static void tag_tag_detached(NetNfcGDbusTag *object,
			guint arg_handle,
			gint arg_dev_type,
			gpointer user_data);

static gboolean tag_check_filter(net_nfc_target_type_e type)
{
	net_nfc_event_filter_e converted = NET_NFC_ALL_ENABLE;

	DEBUG_CLIENT_MSG("client filter =  %d", client_filter);

	if (type >= NET_NFC_ISO14443_A_PICC &&
		type <= NET_NFC_MIFARE_DESFIRE_PICC)
	{
		converted = NET_NFC_ISO14443A_ENABLE;
	}
	else if (type >= NET_NFC_ISO14443_B_PICC &&
		type <= NET_NFC_ISO14443_BPRIME_PICC)
	{
		converted = NET_NFC_ISO14443B_ENABLE;
	}
	else if (type == NET_NFC_FELICA_PICC)
	{
		converted = NET_NFC_FELICA_ENABLE;
	}
	else if (type == NET_NFC_JEWEL_PICC)
	{
		converted = NET_NFC_FELICA_ENABLE;
	}
	else if (type == NET_NFC_ISO15693_PICC)
	{
		converted = NET_NFC_ISO15693_ENABLE;
	}

	if ((converted & client_filter) == 0)
		return FALSE;

	return TRUE;
}

static void tag_get_info_list(guint8 *buffer,
			gint number_of_keys,
			net_nfc_tag_info_s **list)
{
	net_nfc_tag_info_s *tmp_list = NULL;
	net_nfc_tag_info_s *current = NULL;

	gint i = 0;
	gint length;

	guint8 *pos = buffer;

	if (buffer == NULL)
		return;

	tmp_list = g_new0(net_nfc_tag_info_s, number_of_keys);
	current = tmp_list;

	while (i < number_of_keys)
	{
		gchar *str = NULL;
		data_h value = NULL;

		/* key */
		length = *pos;	/* first values is length of key */
		pos++;

		str = g_new0(gchar, length + 1);
		memcpy(str, pos, length);

		DEBUG_CLIENT_MSG("key = [%s]", str);

		pos += length;

		current->key = str;

		/* value */
		length = *pos; /* first value is length of value */
		pos++;

		value = NULL;
		if (length > 0)
		{
			net_nfc_create_data(&value, pos, length);
			pos += length;
		}

		current->value = value;

		current++;
		i++;
	}

	*list = tmp_list;
}

static void tag_get_target_info(guint handle,
				guint dev_type,
				gboolean is_ndef_supported,
				guchar ndef_card_state,
				guint max_data_size,
				guint actual_data_size,
				guint number_of_keys,
				GVariant *target_info_values,
				GVariant *raw_data,
				net_nfc_target_info_s **info)
{
	guint8 *buffer = NULL;
	net_nfc_target_info_s *info_data = NULL;
	net_nfc_tag_info_s *list = NULL;

	if (info == NULL)
		return;

	net_nfc_util_gdbus_variant_to_buffer(target_info_values,
			&buffer, NULL);

	tag_get_info_list(buffer, number_of_keys, &list);

	info_data = g_new0(net_nfc_target_info_s, 1);

	info_data->ndefCardState = ndef_card_state;
	info_data->actualDataSize = actual_data_size;
	info_data->maxDataSize = max_data_size;
	info_data->devType = dev_type;
	info_data->handle = GUINT_TO_POINTER(handle);
	info_data->is_ndef_supported = (uint8_t)is_ndef_supported;
	info_data->number_of_keys = number_of_keys;
	info_data->tag_info_list = list;

	net_nfc_util_gdbus_variant_to_data_s(raw_data,
			&info_data->raw_data);

	*info = info_data;
}
#if 0
static void tag_is_tag_connected(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	gboolean out_is_connected = false;
	net_nfc_target_type_e out_dev_type = NET_NFC_UNKNOWN_TARGET;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_tag_call_is_tag_connected_finish(
				NET_NFC_GDBUS_TAG(source_object),
				&out_result,
				&out_is_connected,
				(gint32 *)&out_dev_type,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish is_tag_connected: %s",
				error->message);
		g_error_free(error);

		out_result = NET_NFC_IPC_FAIL;
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_tag_is_tag_connected_completed callback =
			(net_nfc_client_tag_is_tag_connected_completed)func_data->callback;

		if (out_is_connected == FALSE)
			out_result = NET_NFC_NOT_CONNECTED;

		callback(out_result, out_dev_type, func_data->user_data);
	}

	g_free(func_data);
}

static void tag_get_current_tag_info(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result = NET_NFC_OK;

	net_nfc_target_type_e out_dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean out_is_connected = FALSE;
	gboolean out_is_ndef_supported = FALSE;
	guchar out_ndef_card_state = 0;
	guint out_handle = 0;
	guint out_max_data_size = 0;
	guint out_actual_data_size = 0;
	guint out_number_of_keys = 0;
	GVariant *out_target_info_values = NULL;
	GVariant *out_raw_data = NULL;

	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_tag_call_get_current_tag_info_finish (
					NET_NFC_GDBUS_TAG(source_object),
					&out_result,
					&out_is_connected,
					&out_handle,
					(gint *)&out_dev_type,
					&out_is_ndef_supported,
					&out_ndef_card_state,
					&out_max_data_size,
					&out_actual_data_size,
					&out_number_of_keys,
					&out_target_info_values,
					&out_raw_data,
					res,
					&error) == FALSE)
	{
		out_result = NET_NFC_IPC_FAIL;

		DEBUG_ERR_MSG("Can not finish get_current_tag_info: %s",
				error->message);
		g_error_free(error);
	}

	if (out_result == NET_NFC_OK && out_is_connected == true) {
		net_nfc_release_tag_info((net_nfc_target_info_h)client_target_info);
		client_target_info = NULL;

		if (tag_check_filter(out_dev_type) == true) {
			tag_get_target_info(out_handle,
					out_dev_type,
					out_is_ndef_supported,
					out_ndef_card_state,
					out_max_data_size,
					out_actual_data_size,
					out_number_of_keys,
					out_target_info_values,
					out_raw_data,
					&client_target_info);
		} else {
			INFO_MSG("The detected target is filtered out, type [%d]", out_dev_type);

			out_is_connected = false;
		}
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_tag_get_current_tag_info_completed callback =
			(net_nfc_client_tag_get_current_tag_info_completed)func_data->callback;

		if (out_result == NET_NFC_OK && out_is_connected == false)
			out_result = NET_NFC_NOT_CONNECTED;

		callback(out_result, client_target_info, func_data->user_data);
	}

	g_free(func_data);
}

static void tag_get_current_target_handle(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result = NET_NFC_OK;
	net_nfc_target_handle_h out_handle = NULL;
	net_nfc_target_type_e out_dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean out_is_connected = false;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_tag_call_get_current_target_handle_finish(
					NET_NFC_GDBUS_TAG(source_object),
					&out_result,
					&out_is_connected,
					(guint *)&out_handle,
					(gint *)&out_dev_type,
					res,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish get_current_target_handle: %s",
				error->message);
		g_error_free(error);

		out_result = NET_NFC_IPC_FAIL;
	}

	if (func_data->callback != NULL)
	{
		net_nfc_client_tag_get_current_target_handle_completed callback =
			(net_nfc_client_tag_get_current_target_handle_completed)func_data->callback;

		if (out_result == NET_NFC_OK && out_is_connected == FALSE)
			out_result = NET_NFC_NOT_CONNECTED;

		callback(out_result,
			GUINT_TO_POINTER(out_handle),
			func_data->user_data);
	}

	g_free(func_data);
}
#endif
static void tag_tag_discovered(NetNfcGDbusTag *object,
			guint arg_handle,
			gint arg_dev_type,
			gboolean arg_is_ndef_supported,
			guchar arg_ndef_card_state,
			guint arg_max_data_size,
			guint arg_actual_data_size,
			guint arg_number_of_keys,
			GVariant *arg_target_info_values,
			GVariant *arg_raw_data,
			gpointer user_data)
{
	INFO_MSG(">>> SIGNAL arrived");

	net_nfc_release_tag_info((net_nfc_target_info_h)client_target_info);
	client_target_info = NULL;

	if (tag_check_filter(arg_dev_type) == FALSE) {
		INFO_MSG("The detected target is filtered out, type [%d]", arg_dev_type);

		return;
	}

	tag_get_target_info(arg_handle,
			arg_dev_type,
			arg_is_ndef_supported,
			arg_ndef_card_state,
			arg_max_data_size,
			arg_actual_data_size,
			arg_number_of_keys,
			arg_target_info_values,
			arg_raw_data,
			&client_target_info);

	if (tag_discovered_func_data.callback != NULL) {
		net_nfc_client_tag_tag_discovered callback =
			(net_nfc_client_tag_tag_discovered)tag_discovered_func_data.callback;

		callback(client_target_info,
			tag_discovered_func_data.user_data);
	}
}

static void tag_tag_detached(NetNfcGDbusTag *object,
			guint arg_handle,
			gint arg_dev_type,
			gpointer user_data)
{
	INFO_MSG(">>> SIGNAL arrived");

	if (tag_check_filter(arg_dev_type) == TRUE) {
		if (tag_detached_func_data.callback != NULL) {
			net_nfc_client_tag_tag_detached callback =
				(net_nfc_client_tag_tag_detached)tag_detached_func_data.callback;

			callback(tag_detached_func_data.user_data);
		}
	} else {
		INFO_MSG("The detected target is filtered out, type [%d]", arg_dev_type);
	}

	net_nfc_release_tag_info((net_nfc_target_info_h)client_target_info);
	client_target_info = NULL;
}

/* internal function */
gboolean net_nfc_client_tag_is_connected(void)
{
	if (client_target_info == NULL)
		return FALSE;

	if (client_target_info->handle == NULL)
		return FALSE;

	return TRUE;
}

net_nfc_target_info_s *net_nfc_client_tag_get_client_target_info(void)
{
	return client_target_info;
}

/* public APIs */
#if 0
NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_tag_is_tag_connected(
			net_nfc_client_tag_is_tag_connected_completed callback,
			void *user_data)
{
	NetNfcCallback *func_data;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_INVALID_STATE;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	net_nfc_gdbus_tag_call_is_tag_connected(tag_proxy,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					tag_is_tag_connected,
					func_data);

	return NET_NFC_OK;
}
#endif
NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_tag_is_tag_connected_sync(
					net_nfc_target_type_e *dev_type)
{
	net_nfc_target_info_s *info;
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_target_type_e out_dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean out_is_connected = false;
	GError *error = NULL;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	info = net_nfc_client_tag_get_client_target_info();
	if (info == NULL) {
		/* try to request target information from server */
		if (net_nfc_gdbus_tag_call_is_tag_connected_sync(tag_proxy,
					net_nfc_client_gdbus_get_privilege(),
					&result,
					&out_is_connected,
					(gint *)&out_dev_type,
					NULL,
					&error) == FALSE)
		{
			DEBUG_ERR_MSG("Can not get is_tag_connected result: %s",
					error->message);
			result = NET_NFC_IPC_FAIL;

			g_error_free(error);

			return result;
		}

		if (out_is_connected == true) {
			if (dev_type)
				*dev_type = out_dev_type;

			result = NET_NFC_OK;
		} else {
			result = NET_NFC_NOT_CONNECTED;
		}
	} else {
		/* target was connected */
		if (dev_type != NULL) {
			*dev_type = info->devType;
		}

		result = NET_NFC_OK;
	}

	return result;
}
#if 0
NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_tag_get_current_tag_info(
		net_nfc_client_tag_get_current_tag_info_completed callback,
		void *user_data)
{
	NetNfcCallback *func_data;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_INVALID_STATE;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL) {
		return NET_NFC_ALLOC_FAIL;
	}

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	net_nfc_gdbus_tag_call_get_current_tag_info(tag_proxy,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					tag_get_current_tag_info,
					func_data);

	return NET_NFC_OK;
}
#endif


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_barcode_get_barcode_sync(
						unsigned char **barcode, int* barcode_len)
{
	data_s *data;
	GError *error = NULL;
	GVariant *out_barcode = NULL;
	net_nfc_error_e result = NET_NFC_OK;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_gdbus_tag_call_get_barcode_sync(tag_proxy,
				net_nfc_client_gdbus_get_privilege(),
				&result,
				&out_barcode,
				NULL,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can no get barcode result: %s", error->message);
		result = NET_NFC_IPC_FAIL;

		g_error_free(error);

		return result;
	}

	if(result == NET_NFC_OK)
	{
		data = g_new0(data_s, 1);
		net_nfc_util_gdbus_variant_to_data_s(out_barcode, data);

		if(data == NULL || data->buffer == NULL || data->length == 0)
			return NET_NFC_OPERATION_FAIL;

		//alloc barcode
		*barcode_len = data->length;
		*barcode = (unsigned char *)calloc(*barcode_len, sizeof(unsigned char));
		memcpy(*barcode, data->buffer, *barcode_len);

		if (data != NULL) {
			net_nfc_util_free_data(data);
		}
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_tag_get_current_tag_info_sync(
						net_nfc_target_info_h *info)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_target_type_e out_dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean out_is_connected = false;
	gboolean out_is_ndef_supported = false;
	guchar out_ndef_card_state = 0;
	guint out_handle = 0;
	guint out_max_data_size = 0;
	guint out_actual_data_size = 0;
	guint out_number_of_keys = 0;
	GVariant *out_target_info_values = NULL;
	GVariant *out_raw_data = NULL;
	GError *error = NULL;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	if (net_nfc_client_tag_get_client_target_info() == NULL) {
		/* try to request target information from server */
		if (net_nfc_gdbus_tag_call_get_current_tag_info_sync(tag_proxy,
					net_nfc_client_gdbus_get_privilege(),
					&result,
					&out_is_connected,
					&out_handle,
					(gint *)&out_dev_type,
					&out_is_ndef_supported,
					&out_ndef_card_state,
					&out_max_data_size,
					&out_actual_data_size,
					&out_number_of_keys,
					&out_target_info_values,
					&out_raw_data,
					NULL,
					&error) == FALSE)
		{
			DEBUG_ERR_MSG("Can no get current_tag_info result: %s",
					error->message);
			result = NET_NFC_IPC_FAIL;

			g_error_free(error);

			return result;
		}

		if (result == NET_NFC_OK) {
			if (out_is_connected == true) {
				if (tag_check_filter(out_dev_type) == true) {
					tag_get_target_info(out_handle,
							out_dev_type,
							out_is_ndef_supported,
							out_ndef_card_state,
							out_max_data_size,
							out_actual_data_size,
							out_number_of_keys,
							out_target_info_values,
							out_raw_data,
							&client_target_info);

					result = NET_NFC_OK;
				} else {
					INFO_MSG("The detected target is filtered out");

					result = NET_NFC_NOT_CONNECTED;
				}
			} else {
				result = NET_NFC_NOT_CONNECTED;
			}
		}
	} else {
		result = NET_NFC_OK;
	}

	if (result == NET_NFC_OK && info != NULL) {
		*info = client_target_info;
	}

	return result;
}
#if 0
NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_tag_get_current_target_handle(
	net_nfc_client_tag_get_current_target_handle_completed callback,
	void *user_data)
{
	NetNfcCallback *func_data;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_INVALID_STATE;
	}

	func_data = g_try_new0(NetNfcCallback, 1);
	if (func_data == NULL) {
		return NET_NFC_ALLOC_FAIL;
	}

	func_data->callback = (gpointer)callback;
	func_data->user_data = user_data;

	net_nfc_gdbus_tag_call_get_current_target_handle(tag_proxy,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					tag_get_current_target_handle,
					func_data);

	return NET_NFC_OK;
}
#endif
NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_tag_get_current_target_handle_sync(
					net_nfc_target_handle_h *handle)
{
	net_nfc_target_info_s *info;
	net_nfc_error_e result;
	net_nfc_target_type_e out_dev_type = NET_NFC_UNKNOWN_TARGET;
	gboolean out_is_connected = false;
	guint out_handle = 0;
	GError *error = NULL;

	if (tag_proxy == NULL)
		return NET_NFC_NOT_INITIALIZED;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	info = net_nfc_client_tag_get_client_target_info();
	if (info == NULL) {
		if (net_nfc_gdbus_tag_call_get_current_target_handle_sync(
			tag_proxy,
			net_nfc_client_gdbus_get_privilege(),
			&result,
			&out_is_connected,
			&out_handle,
			(gint *)&out_dev_type,
			NULL,
			&error) == FALSE)
		{
			DEBUG_ERR_MSG("Can no get current_target_handle result: %s",
					error->message);
			result = NET_NFC_IPC_FAIL;

			g_error_free(error);

			return result;
		}

		if (result == NET_NFC_OK) {
			if (out_is_connected == true) {
				if (handle)
					*handle = GUINT_TO_POINTER(out_handle);

				result = NET_NFC_OK;
			} else {
				result = NET_NFC_NOT_CONNECTED;
			}
		}
	} else if (info->devType == NET_NFC_NFCIP1_INITIATOR ||
		info->devType == NET_NFC_NFCIP1_TARGET) {
		if (handle)
			*handle = info->handle;

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NOT_CONNECTED;
	}

	return result;
}

NET_NFC_EXPORT_API
void net_nfc_client_tag_set_tag_discovered(
			net_nfc_client_tag_tag_discovered callback,
			void *user_data)
{
	if (callback == NULL)
		return;

	if (tag_proxy == NULL)
	{
		if (net_nfc_client_tag_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("tag_proxy fail");
			/* FIXME : return result of this error */
			return;
		}
	}

	tag_discovered_func_data.callback = (gpointer)callback;
	tag_discovered_func_data.user_data = user_data;
}

NET_NFC_EXPORT_API
void net_nfc_client_tag_unset_tag_discovered(void)
{
	tag_discovered_func_data.callback = NULL;
	tag_discovered_func_data.user_data = NULL;
}

NET_NFC_EXPORT_API
void net_nfc_client_tag_set_tag_detached(
			net_nfc_client_tag_tag_detached callback,
			void *user_data)
{
	if (callback == NULL)
		return;

	if (tag_proxy == NULL)
	{
		if (net_nfc_client_tag_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("tag_proxy fail");
			/* FIXME : return result of this error */
			return;
		}
	}

	tag_detached_func_data.callback = (gpointer)callback;
	tag_detached_func_data.user_data = user_data;
}

NET_NFC_EXPORT_API
void net_nfc_client_tag_unset_tag_detached(void)
{
	tag_detached_func_data.callback = NULL;
	tag_detached_func_data.user_data = NULL;
}

NET_NFC_EXPORT_API
void net_nfc_client_tag_set_filter(net_nfc_event_filter_e filter)
{
	client_filter = filter;
}

NET_NFC_EXPORT_API
net_nfc_event_filter_e net_nfc_client_tag_get_filter(void)
{
	return client_filter;
}

net_nfc_error_e net_nfc_client_tag_init(void)
{
	GError *error = NULL;

	if (tag_proxy)
	{
		DEBUG_CLIENT_MSG("Alrady initialized");

		return NET_NFC_OK;
	}

	if (client_target_info)
	{
		net_nfc_release_tag_info(
				(net_nfc_target_info_h)client_target_info);
		client_target_info = NULL;
	}

	client_filter = NET_NFC_ALL_ENABLE;

	tag_proxy = net_nfc_gdbus_tag_proxy_new_for_bus_sync(
				G_BUS_TYPE_SYSTEM,
				G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
				"org.tizen.NetNfcService",
				"/org/tizen/NetNfcService/Tag",
				NULL,
				&error);
	if (tag_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
		g_error_free(error);

		return NET_NFC_UNKNOWN_ERROR;
	}

	g_signal_connect(tag_proxy, "tag-discovered",
			G_CALLBACK(tag_tag_discovered), NULL);

	g_signal_connect(tag_proxy, "tag-detached",
			G_CALLBACK(tag_tag_detached), NULL);

	return NET_NFC_OK;
}

void net_nfc_client_tag_deinit(void)
{
	client_filter = NET_NFC_ALL_ENABLE;

	net_nfc_release_tag_info((net_nfc_target_info_h)client_target_info);
	client_target_info = NULL;

	net_nfc_client_tag_unset_tag_discovered();
	net_nfc_client_tag_unset_tag_detached();

	if (tag_proxy)
	{
		g_object_unref(tag_proxy);
		tag_proxy = NULL;
	}
}
