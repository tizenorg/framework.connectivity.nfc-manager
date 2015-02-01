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

#include <string.h>

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_client.h"
#include "net_nfc_client_util_internal.h"
#include "net_nfc_client_manager.h"
#include "net_nfc_client_tag_internal.h"
#include "net_nfc_client_transceive.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

static NetNfcGDbusTransceive *transceive_proxy = NULL;

static GVariant *transceive_data_to_transceive_variant(
						net_nfc_target_type_e dev_type,
						data_s *data);

static void transceive_call(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static void transceive_data_call(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

static GVariant *transceive_data_to_transceive_variant(
						net_nfc_target_type_e devType,
						data_s *data)
{
	data_s transceive_info = { NULL, };
	GVariant *variant;

	if (data == NULL)
	{
		DEBUG_ERR_MSG("data is empty");

		return NULL;
	}

	switch (devType)
	{
	case NET_NFC_MIFARE_MINI_PICC :
	case NET_NFC_MIFARE_1K_PICC :
	case NET_NFC_MIFARE_4K_PICC :
	case NET_NFC_MIFARE_ULTRA_PICC :
		if (net_nfc_util_init_data(&transceive_info,
			data->length + 2) == true)
		{
			memcpy(transceive_info.buffer,
				data->buffer,
				data->length);

			net_nfc_util_compute_CRC(CRC_A,
				transceive_info.buffer,
				transceive_info.length);
		}
		break;

	case NET_NFC_JEWEL_PICC :
		if (data->length > 9)
		{
			DEBUG_ERR_MSG("data length is larger than 9");

			return NULL;
		}

		if (net_nfc_util_init_data(&transceive_info, 9) == true)
		{
			memcpy(transceive_info.buffer,
				data->buffer,
				data->length);

			net_nfc_util_compute_CRC(CRC_B,
					transceive_info.buffer,
					transceive_info.length);
		}
		break;

	default :
		if(net_nfc_util_init_data(&transceive_info,
			data->length) == true)
		{
			memcpy(transceive_info.buffer,
				data->buffer,
				data->length);
		}
		break;
	}

	variant = net_nfc_util_gdbus_data_to_variant(&transceive_info);

	net_nfc_util_clear_data(&transceive_info);

	return variant;
}

static void transceive_data_call(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	GVariant *out_data = NULL;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_transceive_call_transceive_data_finish(
				NET_NFC_GDBUS_TRANSCEIVE(source_object),
				(gint *)&out_result,
				&out_data,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish transceive: %s", error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		data_s resp = { NULL, };

		net_nfc_util_gdbus_variant_to_data_s(out_data, &resp);

		((nfc_transceive_data_callback)func_data->callback)(
					out_result,
					&resp,
					func_data->user_data);

		net_nfc_util_clear_data(&resp);
	}

	g_free(func_data);
}

static void transceive_call(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data)
{
	NetNfcCallback *func_data = (NetNfcCallback *)user_data;
	net_nfc_error_e out_result;
	GError *error = NULL;

	g_assert(user_data != NULL);

	if (net_nfc_gdbus_transceive_call_transceive_finish(
				NET_NFC_GDBUS_TRANSCEIVE(source_object),
				(gint *)&out_result,
				res,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("Can not finish transceive: %s", error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (func_data->callback != NULL)
	{
		((nfc_transceive_callback)func_data->callback)(
			out_result,
			func_data->user_data);
	}

	g_free(func_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_transceive(net_nfc_target_handle_h handle,
					data_h rawdata,
					nfc_transceive_callback callback,
					void *user_data)
{
	net_nfc_target_info_s *target_info;
	NetNfcCallback *funcdata;
	GVariant *arg_data;

	if (transceive_proxy == NULL)
	{
		if(net_nfc_client_transceive_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("transceive_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (handle == NULL || rawdata == NULL)
		return NET_NFC_NULL_PARAMETER;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	target_info = net_nfc_client_tag_get_client_target_info();
	if (target_info == NULL || target_info->handle == NULL)
		return NET_NFC_NOT_CONNECTED;

	DEBUG_CLIENT_MSG("send request :: transceive = [%p]", handle);

	arg_data = transceive_data_to_transceive_variant(target_info->devType,
		rawdata);
	if (arg_data == NULL) {
		return NET_NFC_INVALID_PARAM;
	}

	funcdata = g_try_new0(NetNfcCallback, 1);
	if (funcdata == NULL) {
		g_variant_unref(arg_data);

		return NET_NFC_ALLOC_FAIL;
	}

	funcdata->callback = (gpointer)callback;
	funcdata->user_data = user_data;

	net_nfc_gdbus_transceive_call_transceive(transceive_proxy,
					GPOINTER_TO_UINT(handle),
					target_info->devType,
					arg_data,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					transceive_call,
					funcdata);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_transceive_data(net_nfc_target_handle_h handle,
					data_h rawdata,
					nfc_transceive_data_callback callback,
					void *user_data)
{
	net_nfc_target_info_s *target_info;
	NetNfcCallback *funcdata;
	GVariant *arg_data;

	if (transceive_proxy == NULL)
	{
		if(net_nfc_client_transceive_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("transceive_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	if (handle == NULL || rawdata == NULL)
		return NET_NFC_NULL_PARAMETER;

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	target_info = net_nfc_client_tag_get_client_target_info();
	if (target_info == NULL || target_info->handle == NULL)
		return NET_NFC_NOT_CONNECTED;

	DEBUG_CLIENT_MSG("send request :: transceive = [%p]", handle);

	arg_data = transceive_data_to_transceive_variant(target_info->devType,
		rawdata);
	if (arg_data == NULL) {
		return NET_NFC_INVALID_PARAM;
	}

	funcdata = g_try_new0(NetNfcCallback, 1);
	if (funcdata == NULL) {
		g_variant_unref(arg_data);

		return NET_NFC_ALLOC_FAIL;
	}

	funcdata->callback = (gpointer)callback;
	funcdata->user_data = user_data;

	net_nfc_gdbus_transceive_call_transceive_data(transceive_proxy,
					GPOINTER_TO_UINT(handle),
					target_info->devType,
					arg_data,
					net_nfc_client_gdbus_get_privilege(),
					NULL,
					transceive_data_call,
					funcdata);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_transceive_sync(net_nfc_target_handle_h handle,
					data_h rawdata)
{
	net_nfc_target_info_s *target_info;
	net_nfc_error_e out_result = NET_NFC_OK;
	GError *error = NULL;
	GVariant *arg_data;

	if (handle == NULL || rawdata == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (transceive_proxy == NULL)
	{
		if(net_nfc_client_transceive_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("transceive_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	target_info = net_nfc_client_tag_get_client_target_info();
	if (target_info == NULL || target_info->handle == NULL)
		return NET_NFC_NOT_CONNECTED;

	DEBUG_CLIENT_MSG("send request :: transceive = [%p]", handle);

	arg_data = transceive_data_to_transceive_variant(target_info->devType,
		rawdata);
	if (arg_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	if (net_nfc_gdbus_transceive_call_transceive_sync(transceive_proxy,
					GPOINTER_TO_UINT(handle),
					target_info->devType,
					arg_data,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("Transceive (sync call) failed: %s",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	return out_result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_transceive_data_sync(
						net_nfc_target_handle_h handle,
						data_h rawdata,
						data_h *response)
{
	net_nfc_target_info_s *target_info;
	net_nfc_error_e out_result = NET_NFC_OK;
	GVariant *out_data = NULL;
	GError *error = NULL;
	GVariant *arg_data;

	if (handle == NULL || rawdata == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (transceive_proxy == NULL)
	{
		if(net_nfc_client_transceive_init() != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("transceive_proxy fail");
			return NET_NFC_NOT_INITIALIZED;
		}
	}

	/* prevent executing daemon when nfc is off */
	if (net_nfc_client_manager_is_activated() == false) {
		return NET_NFC_NOT_ACTIVATED;
	}

	target_info = net_nfc_client_tag_get_client_target_info();
	if (target_info == NULL || target_info->handle == NULL)
		return NET_NFC_NOT_CONNECTED;

	DEBUG_CLIENT_MSG("send request :: transceive = [%p]", handle);

	arg_data = transceive_data_to_transceive_variant(target_info->devType,
		rawdata);
	if (arg_data == NULL)
		return NET_NFC_ALLOC_FAIL;

	if (net_nfc_gdbus_transceive_call_transceive_data_sync(
					transceive_proxy,
					GPOINTER_TO_UINT(handle),
					target_info->devType,
					arg_data,
					net_nfc_client_gdbus_get_privilege(),
					(gint *)&out_result,
					&out_data,
					NULL,
					&error) == FALSE)
	{
		DEBUG_ERR_MSG("Transceive (sync call) failed: %s",
			error->message);
		out_result = NET_NFC_IPC_FAIL;

		g_error_free(error);
	}

	if (response && out_data != NULL)
	{
		*response = net_nfc_util_gdbus_variant_to_data(out_data);
	}

	return out_result;
}


net_nfc_error_e net_nfc_client_transceive_init(void)
{
	GError *error = NULL;

	if (transceive_proxy)
	{
		DEBUG_CLIENT_MSG("Already initialized");

		return NET_NFC_OK;
	}

	transceive_proxy = net_nfc_gdbus_transceive_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM,
					G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
					"org.tizen.NetNfcService",
					"/org/tizen/NetNfcService/Transceive",
					NULL,
					&error);
	if (transceive_proxy == NULL)
	{
		DEBUG_ERR_MSG("Can not create proxy : %s", error->message);
		g_error_free(error);

		return NET_NFC_UNKNOWN_ERROR;
	}

	return NET_NFC_OK;
}

void net_nfc_client_transceive_deinit(void)
{
	if (transceive_proxy)
	{
		g_object_unref(transceive_proxy);
		transceive_proxy = NULL;
	}
}
