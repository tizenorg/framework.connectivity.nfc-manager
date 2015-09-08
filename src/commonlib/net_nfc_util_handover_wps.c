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

bool net_nfc_util_handover_wps_check_carrier_record(ndef_record_s *record)
{
	bool result;

	g_assert(record != NULL);

	if ((record->type_s.length == CH_CAR_RECORD_TYPE_LEN) &&
		(memcmp(CH_CAR_RECORD_TYPE, record->type_s.buffer,
			CH_CAR_RECORD_TYPE_LEN) == 0)) {

		/* FIXME */
		if ((record->type_s.length == CH_WIFI_WPS_MIME_LEN) &&
			(memcmp(CH_WIFI_WPS_MIME, record->type_s.buffer,
				CH_WIFI_WPS_MIME_LEN) == 0)) {
			result = true;
		} else {
			result = false;
		}
	} else if ((record->type_s.length == CH_WIFI_WPS_MIME_LEN) &&
		(memcmp(CH_WIFI_WPS_MIME, record->type_s.buffer,
			CH_WIFI_WPS_MIME_LEN) == 0)) {
		result = true;
	} else {
		result = false;
	}

	return result;
}

typedef struct _tlv_header_t
{
	uint16_t t;
	uint16_t l;
	uint8_t v[0];
}
__attribute__((packed)) tlv_header_t;

typedef void (*_parse_tlv_cb)(uint16_t t, uint16_t l,
	uint8_t *v, void *user_data);

static void _parse_tlv(uint8_t *buffer, uint32_t len,
	_parse_tlv_cb cb, void *user_data)
{
	tlv_header_t *tlv;
	uint32_t offset = 0;
	uint16_t l;

	if (buffer == NULL || len == 0 || cb == NULL)
		return;

	do
	{
		tlv = (tlv_header_t *)(buffer + offset);
		l = htons(tlv->l);
		cb(htons(tlv->t), l, tlv->v, user_data);
		offset += sizeof(tlv_header_t) + l;
	}
	while (offset < len);
}

static void _wifi_tlv_cb(uint16_t t, uint16_t l,
	uint8_t *v, void *user_data)
{
	GNode *node = (GNode *)user_data;
	net_nfc_carrier_property_s *elem;

	elem = g_new0(net_nfc_carrier_property_s, 1);

	elem->attribute = t;
	elem->length = l;

	node = g_node_append_data(node, elem);

	if (t == NET_NFC_WIFI_ATTRIBUTE_CREDENTIAL) {
		elem->is_group = true;
		elem->data = node;

		_parse_tlv(v, l, _wifi_tlv_cb, node);
	} else {
		elem->data = g_malloc0(l);
		if(elem->data != NULL)
			memcpy(elem->data, v, l);
	}
}

net_nfc_error_e net_nfc_util_handover_wps_create_config_from_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_carrier_config_s *temp = NULL;

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	result = net_nfc_util_create_carrier_config(&temp,
		NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P);
	if (temp != NULL) {
		temp->length = record->payload_s.length;
		_parse_tlv(record->payload_s.buffer, record->payload_s.length,
			_wifi_tlv_cb, temp->data);
		*config = temp;
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

static void __calc_total_length_cb(GNode *node, gpointer data)
{
	net_nfc_carrier_property_s *info = node->data;
	uint32_t *length = (uint32_t *)data;

	if (info == NULL)
		return;

	*length += sizeof(tlv_header_t);

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
	uint32_t result = 0;

	g_node_children_foreach(config->data, G_TRAVERSE_ALL,
		__calc_total_length_cb, &result);

	config->length = result;

	return result;
}

static void _serialize_cb(GNode *node, gpointer data)
{
	net_nfc_carrier_property_s *prop = node->data;
	data_s *payload = (data_s *)data;
	tlv_header_t *header;

	header = (tlv_header_t *)(payload->buffer + payload->length);

	header->t = htons(prop->attribute);
	header->l = htons(prop->length);

	payload->length += sizeof(tlv_header_t);

	if (prop->is_group == true) {
		g_node_children_foreach(node, G_TRAVERSE_ALL,
			_serialize_cb, payload);
	} else {
		memcpy(header->v, prop->data, prop->length);

		payload->length += (prop->length);
	}
}

net_nfc_error_e net_nfc_util_handover_wps_create_record_from_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config)
{
	net_nfc_error_e result;
	uint32_t len;
	data_s payload = { 0, };
	data_s type = { (uint8_t *)CH_WIFI_P2P_MIME, CH_WIFI_P2P_MIME_LEN };

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	len = _calc_total_length(config);

	DEBUG_MSG("payload length = %d", len);

	if (net_nfc_util_init_data(&payload, len) == true) {
		g_node_children_foreach(config->data, G_TRAVERSE_ALL,
			_serialize_cb, &payload);

		g_assert(len == payload.length);

		result = net_nfc_util_create_record(NET_NFC_RECORD_MIME_TYPE,
			&type, NULL, &payload, record);

		net_nfc_util_clear_data(&payload);
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
