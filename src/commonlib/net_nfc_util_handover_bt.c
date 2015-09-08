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

#include <glib.h>

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_handover.h"

#define CH_BT_MIME		"application/vnd.bluetooth.ep.oob"
#define CH_BT_MIME_LEN		32

bool net_nfc_util_handover_bt_check_carrier_record(ndef_record_s *record)
{
	bool result;

	g_assert(record != NULL);

	if ((record->type_s.length == CH_CAR_RECORD_TYPE_LEN) &&
		(memcmp(CH_CAR_RECORD_TYPE, record->type_s.buffer,
			CH_CAR_RECORD_TYPE_LEN) == 0)) {

		/* FIXME */
		if ((record->type_s.length == CH_BT_MIME_LEN) &&
			(memcmp(CH_BT_MIME, record->type_s.buffer,
				CH_BT_MIME_LEN) == 0)) {
			result = true;
		} else {
			result = false;
		}
	} else if ((record->type_s.length == CH_BT_MIME_LEN) &&
		(memcmp(CH_BT_MIME, record->type_s.buffer,
			CH_BT_MIME_LEN) == 0)) {
		result = true;
	} else {
		result = false;
	}

	return result;
}

typedef struct _oob_header_t
{
	uint16_t length;
	uint8_t address[6];
	uint8_t data[0];
}
oob_header_t;

typedef struct _eir_header_t
{
	uint8_t l;
	uint8_t t;
	uint8_t v[0];
}
__attribute__((packed)) eir_header_t;

static void __calc_total_length_cb(GNode *node, gpointer data)
{
	net_nfc_carrier_property_s *info = node->data;
	uint32_t *length = (uint32_t *)data;

	if (info == NULL)
		return;

	if (info->attribute == NET_NFC_BT_ATTRIBUTE_ADDRESS)
		return;

	*length += sizeof(eir_header_t);

	if (info->is_group) {
		uint32_t temp_len = 0;

		g_node_children_foreach(node, G_TRAVERSE_ALL,
			__calc_total_length_cb, &temp_len);

		info->length = temp_len;

		*length += info->length;
	}
	else
	{
		*length += info->length;
	}
}

static uint32_t _calc_total_length(net_nfc_carrier_config_s *config)
{
	uint32_t result = sizeof(oob_header_t);

	g_node_children_foreach(config->data, G_TRAVERSE_ALL,
		__calc_total_length_cb, &result);

	config->length = result;

	return result;
}

static void _serialize_cb(GNode *node, gpointer data)
{
	net_nfc_carrier_property_s *prop = node->data;
	data_s *payload = (data_s *)data;
	eir_header_t *header;

	if (prop == NULL)
		return;

	if (prop->attribute == NET_NFC_BT_ATTRIBUTE_ADDRESS) /* skip property */
		return;

	header = (eir_header_t *)(payload->buffer + payload->length);

	header->t = prop->attribute;
	header->l = prop->length + sizeof(header->t);

	payload->length += sizeof(eir_header_t);

	memcpy(header->v, prop->data, prop->length);

	payload->length += (prop->length);
}

net_nfc_error_e net_nfc_util_handover_bt_create_record_from_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config)
{
	net_nfc_error_e result;
	uint32_t len;
	uint8_t *buffer = NULL;
	data_s type = { (uint8_t *)CH_BT_MIME, CH_BT_MIME_LEN };

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	len = _calc_total_length(config);

	DEBUG_MSG("payload length [%d]", len);

	_net_nfc_util_alloc_mem(buffer, len);
	if (buffer != NULL) {
		oob_header_t *header = (oob_header_t *)buffer;
		uint16_t addr_len = 0;
		uint8_t *addr = NULL;
		data_s payload;

		/* total length */
		header->length = len;

		/* address */
		net_nfc_util_get_carrier_config_property(config,
			NET_NFC_BT_ATTRIBUTE_ADDRESS,
			&addr_len, &addr);

		if (addr_len == sizeof(header->address)) {
			memcpy(header->address, addr, addr_len);
		}

		payload.buffer = buffer;
		payload.length = sizeof(oob_header_t); /* offset */

		/* eirs */
		g_node_children_foreach(config->data, G_TRAVERSE_ALL,
			_serialize_cb, &payload);

		g_assert(len == payload.length);

		result = net_nfc_util_create_record(NET_NFC_RECORD_MIME_TYPE,
			&type, NULL, &payload, record);

		_net_nfc_util_free_mem(buffer);
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

typedef void (*_parse_eir_cb)(uint8_t t, uint8_t l,
	uint8_t *v, void *user_data);

static void _parse_eir(uint8_t *buffer, uint32_t len,
	_parse_eir_cb cb, void *user_data)
{
	eir_header_t *tlv;
	uint32_t offset = 0;
	uint8_t l;

	if (buffer == NULL || len == 0 || cb == NULL)
		return;

	do
	{
		tlv = (eir_header_t *)(buffer + offset);
		l = tlv->l - sizeof(tlv->t); /* length includes tag's size */
		cb(tlv->t, l, tlv->v, user_data);
		offset += sizeof(eir_header_t) + l;
	}
	while (offset < len);
}

static void _bt_eir_cb(uint8_t t, uint8_t l,
	uint8_t *v, void *user_data)
{
	GNode *node = (GNode *)user_data;
	net_nfc_carrier_property_s *elem;

	elem = g_new0(net_nfc_carrier_property_s, 1);

	elem->attribute = t;
	elem->length = l;
	elem->data = g_malloc0(l);

	if(elem->data != NULL)
	{
		memcpy(elem->data, v, l);

		g_node_append_data(node, elem);
	}
}

net_nfc_error_e net_nfc_util_handover_bt_create_config_from_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_carrier_config_s *temp = NULL;

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	result = net_nfc_util_create_carrier_config(&temp,
		NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS);
	if (temp != NULL) {
		oob_header_t *header = (oob_header_t *)record->payload_s.buffer;

		temp->length = header->length;

		net_nfc_util_add_carrier_config_property(temp,
			NET_NFC_BT_ATTRIBUTE_ADDRESS, sizeof(header->address),
			header->address);

		_parse_eir(header->data, temp->length - sizeof(oob_header_t),
			_bt_eir_cb, temp->data);

		*config = temp;
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
