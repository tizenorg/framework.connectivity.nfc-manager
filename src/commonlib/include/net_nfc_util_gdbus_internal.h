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
#ifndef __NET_NFC_UTIL_GDBUS_INTERNAL_H__
#define __NET_NFC_UTIL_GDBUS_INTERNAL_H__

#include <glib.h>

#include "net_nfc_typedef_internal.h"

void net_nfc_util_gdbus_variant_to_buffer(GVariant *variant, uint8_t **buffer,
		size_t *length);

data_s *net_nfc_util_gdbus_variant_to_data(GVariant *variant);

void net_nfc_util_gdbus_variant_to_data_s(GVariant *variant, data_s *data);

GVariant *net_nfc_util_gdbus_buffer_to_variant(const uint8_t *buffer,
	size_t length);

GVariant *net_nfc_util_gdbus_data_to_variant(const data_s *data);

ndef_message_s *net_nfc_util_gdbus_variant_to_ndef_message(GVariant *variant);

GVariant *net_nfc_util_gdbus_ndef_message_to_variant(
	const ndef_message_s *message);

#endif //__NET_NFC_UTIL_GDBUS_INTERNAL_H__
