/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.1 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://floralicense.org/license/
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

// libc header

// platform header

// nfc-manager header
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_util_ndef_message.h"

void net_nfc_util_gdbus_variant_to_buffer(GVariant *variant, uint8_t **buffer,
	size_t *length)
{
	GVariantIter *iter;
	guint8 *buf = NULL;
	guint size = 0;

	if (variant == NULL)
		return;

	g_variant_get(variant, "a(y)", &iter);

	size = g_variant_iter_n_children(iter);
	buf  = g_new0(guint8, size);
	if (buf != NULL)
	{
		guint8 element;
		guint i;

		i = 0;
		while (g_variant_iter_loop(iter, "(y)", &element))
		{
			*(buf + i) = element;
			i++;
		}

		g_variant_iter_free(iter);

		if (length)
			*length = size;

		if (buffer)
			*buffer = buf;
		else
			g_free(buf);
	}
}

data_s *net_nfc_util_gdbus_variant_to_data(GVariant *variant)
{
	GVariantIter *iter;
	guint size;
	data_s *result = NULL;

	if (variant == NULL)
		return result;

	g_variant_get(variant, "a(y)", &iter);

	size = g_variant_iter_n_children(iter);
	if (size > 0) {
		result = net_nfc_util_create_data(size);
		if (result != NULL && result->buffer != NULL)
		{
			guint i = 0;
			guint8 element;

			while (g_variant_iter_loop(iter, "(y)", &element))
			{
				*(result->buffer + i) = element;
				i++;
			}

			g_variant_iter_free(iter);
		}
	}

	return result;
}

void net_nfc_util_gdbus_variant_to_data_s(GVariant *variant, data_s *data)
{
	GVariantIter *iter;
	guint size;

	if (data == NULL)
		return;

	data->buffer = NULL;
	data->length = 0;

	if (variant == NULL)
	{
		return;
	}

	g_variant_get(variant, "a(y)", &iter);

	size = g_variant_iter_n_children(iter);
	if (size > 0) {
		if (net_nfc_util_init_data(data, size) == true) {
			guint i = 0;
			guint8 element;

			while (g_variant_iter_loop(iter, "(y)", &element))
			{
				*(data->buffer + i) = element;
				i++;
			}

			g_variant_iter_free(iter);
		}
	}
}

GVariant *net_nfc_util_gdbus_buffer_to_variant(const uint8_t *buffer,
	size_t length)
{
	GVariantBuilder builder;

	g_variant_builder_init(&builder, G_VARIANT_TYPE("a(y)"));

	if (buffer && length > 0)
	{
		int i;

		for(i = 0; i < length; i++)
			g_variant_builder_add(&builder, "(y)", *(buffer + i));
	}

	return g_variant_builder_end(&builder);
}

GVariant *net_nfc_util_gdbus_data_to_variant(const data_s *data)
{
	if (data != NULL)
	{
		return net_nfc_util_gdbus_buffer_to_variant(data->buffer,
			data->length);
	}
	else
	{
		return net_nfc_util_gdbus_buffer_to_variant(NULL, 0);
	}
}

ndef_message_s *net_nfc_util_gdbus_variant_to_ndef_message(GVariant *variant)
{
	ndef_message_s *message = NULL;
	data_s data = { NULL, 0 };

	if (variant == NULL)
		return NULL;

	net_nfc_util_gdbus_variant_to_data_s(variant, &data);

	if (data.buffer && data.length > 0)
	{
		ndef_message_s *temp = NULL;

		if (net_nfc_util_create_ndef_message(&temp) == NET_NFC_OK) {
			if (net_nfc_util_convert_rawdata_to_ndef_message(
				&data, temp) == NET_NFC_OK) {
				message = temp;
			} else {
				DEBUG_ERR_MSG("net_nfc_create_ndef_message_from_rawdata failed");

				net_nfc_util_free_ndef_message(temp);
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_util_create_ndef_message failed");
		}

		net_nfc_util_clear_data(&data);
	}

	return message;
}

GVariant *net_nfc_util_gdbus_ndef_message_to_variant(
	const ndef_message_s *message)
{
	GVariant *variant = NULL;
	data_s temp = { NULL, 0 };
	data_s *data = NULL;
	size_t length;

	length = net_nfc_util_get_ndef_message_length(
		(ndef_message_s *)message);
	if (length > 0) {
		if (net_nfc_util_init_data(&temp, length) == true) {
			if (net_nfc_util_convert_ndef_message_to_rawdata(
				(ndef_message_s *)message,
				&temp) == NET_NFC_OK) {
				data = &temp;
			} else {
				DEBUG_ERR_MSG("can not convert ndef_message to rawdata");
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_util_alloc_data failed");
		}
	} else {
		DEBUG_ERR_MSG("message length is 0");
	}

	variant = net_nfc_util_gdbus_data_to_variant(data);

	if (data != NULL)
		net_nfc_util_clear_data(data);

	return variant;
}
