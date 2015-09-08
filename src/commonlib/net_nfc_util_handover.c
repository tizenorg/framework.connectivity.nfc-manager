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
#include "net_nfc_util_handover_internal.h"


#define CHECK_TYPE(__x, __y) (\
	(__x.length == __y##_LEN) && \
	(memcmp(__x.buffer, __y, __y##_LEN) == 0))

static gboolean _find_by_attribute_cb(GNode *node, gpointer data)
{
	net_nfc_carrier_property_s *prop = node->data;
	gpointer *temp = data;
	gboolean result;

	if (prop != NULL && prop->attribute == (uint16_t)(uint32_t)temp[0]) {
		temp[1] = node;

		result = true;
	} else {
		result = false;
	}

	return result;
}

static GNode *__find_property_by_attribute(GNode *list,
	uint16_t attribute)
{
	gpointer context[2];

	context[0] = (gpointer)(uint32_t)attribute;
	context[1] = NULL;

	g_node_traverse(list, G_IN_ORDER, G_TRAVERSE_ALL,
		-1, _find_by_attribute_cb, context);

	return (GNode *)context[1];
}

static gboolean _destroy_cb(GNode *node, gpointer data)
{
	net_nfc_carrier_property_s *prop = node->data;

	if (prop != NULL) {
		if (prop->is_group) {
			prop->data = NULL;
		}

		_net_nfc_util_free_mem(prop->data);
		_net_nfc_util_free_mem(prop);
	}

	return false;
}

net_nfc_error_e net_nfc_util_create_carrier_config(
	net_nfc_carrier_config_s **config,
	net_nfc_conn_handover_carrier_type_e type)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (type < 0 || type >= NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	_net_nfc_util_alloc_mem(*config, sizeof(net_nfc_carrier_config_s));
	if (*config == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	(*config)->type = type;
	(*config)->data = g_node_new(NULL);

	return NET_NFC_OK;
}

static net_nfc_error_e _append_tree_node(GNode *root, uint16_t attribute,
	uint16_t size, uint8_t *data)
{
	net_nfc_error_e result;
	net_nfc_carrier_property_s *elem = NULL;

	_net_nfc_util_alloc_mem(elem, sizeof (net_nfc_carrier_property_s));
	if (elem != NULL) {
		_net_nfc_util_alloc_mem(elem->data, size);
		if (elem->data != NULL) {
			elem->attribute = attribute;
			elem->length = size;
			elem->is_group = false;
			memcpy(elem->data, data, size);

			g_node_append_data(root, elem);

			result = NET_NFC_OK;
		} else {
			_net_nfc_util_free_mem(elem);
			result = NET_NFC_ALLOC_FAIL;
		}

	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

net_nfc_error_e net_nfc_util_add_carrier_config_property(
	net_nfc_carrier_config_s *config,
	uint16_t attribute, uint16_t size, uint8_t *data)
{
	DEBUG_MSG("ADD property: [ATTRIB:0x%02X, SIZE:%d]", attribute, size);

	if (config == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (__find_property_by_attribute(config->data, attribute) != NULL)
	{
		return NET_NFC_ALREADY_REGISTERED;
	}

	return _append_tree_node(config->data, attribute, size, data);
}

static void _release_tree(GNode *root)
{
	g_node_traverse(root, G_IN_ORDER, G_TRAVERSE_ALL,
		-1, _destroy_cb, NULL);
	g_node_destroy(root);
}

net_nfc_error_e net_nfc_util_remove_carrier_config_property(
	net_nfc_carrier_config_s *config, uint16_t attribute)
{
	net_nfc_error_e result;
	GNode *node;

	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	node = __find_property_by_attribute(config->data, attribute);
	if (node != NULL) {
		_release_tree(node);

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_get_carrier_config_property(
	net_nfc_carrier_config_s *config,
	uint16_t attribute,
	uint16_t *size, uint8_t **data)
{
	GNode *node;
	net_nfc_error_e result;

	if (config == NULL || size == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	node = __find_property_by_attribute(config->data, attribute);
	if (node != NULL) {
		net_nfc_carrier_property_s *elem = node->data;

		if (elem->is_group == false) {
			*size = elem->length;
			*data = elem->data;

			result = NET_NFC_OK;
		} else {
			*size = 0;
			*data = NULL;

			result = NET_NFC_NO_DATA_FOUND;
		}
	} else {
		*size = 0;
		*data = NULL;

		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_append_carrier_config_group(
	net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group)
{
	if (config == NULL || group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (__find_property_by_attribute(config->data,
		group->attribute) != NULL) {
		return NET_NFC_ALREADY_REGISTERED;
	}

	g_node_append_data(config->data, group);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_carrier_config_group(
	net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group)
{
	if (config == NULL || group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (__find_property_by_attribute(config->data,
		group->attribute) != NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	net_nfc_util_free_carrier_group(group);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_carrier_config_group(
	net_nfc_carrier_config_s *config,
	uint16_t attribute, net_nfc_carrier_property_s **group)
{
	GNode *node;
	net_nfc_error_e result;

	if (config == NULL || group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	node = __find_property_by_attribute(config->data, attribute);
	if (node != NULL) {
		net_nfc_carrier_property_s *temp = node->data;

		if (temp->is_group) {
			*group = node->data;

			result = NET_NFC_OK;
		} else {
			result = NET_NFC_NO_DATA_FOUND;
		}
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_free_carrier_config(
	net_nfc_carrier_config_s *config)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_release_tree(config->data);

	_net_nfc_util_free_mem(config);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_carrier_config_group(
	net_nfc_carrier_property_s **group, uint16_t attribute)
{
	net_nfc_carrier_property_s *temp;
	net_nfc_error_e result;

	if (group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(temp, sizeof(net_nfc_carrier_property_s));
	if (temp != NULL) {
		(*group)->attribute = attribute;
		(*group)->length = 0;
		(*group)->is_group = true;
		(*group)->data = g_node_new(temp);

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

net_nfc_error_e net_nfc_util_add_carrier_config_group_property(
	net_nfc_carrier_property_s *group,
	uint16_t attribute, uint16_t size, uint8_t *data)
{
	DEBUG_MSG("ADD group property: [ATTRIB:0x%X, SIZE:%d]", attribute, size);

	if (group == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (__find_property_by_attribute(group->data, attribute) != NULL)
	{
		return NET_NFC_ALREADY_REGISTERED;
	}

//	group->length += size + 2 * __net_nfc_get_size_of_attribute(attribute);
//	DEBUG_MSG("ADD group completed total length %d", group->length);

	return _append_tree_node((GNode *)group->data, attribute, size, data);
}

net_nfc_error_e net_nfc_util_get_carrier_config_group_property(
	net_nfc_carrier_property_s *group,
	uint16_t attribute, uint16_t *size, uint8_t **data)
{
	GNode *node;
	net_nfc_error_e result;

	if (group == NULL || size == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	node = __find_property_by_attribute((GNode *)(group->data), attribute);
	if (node != NULL) {
		net_nfc_carrier_property_s *elem = node->data;

		*size = elem->length;
		*data = elem->data;

		result = NET_NFC_OK;
	} else {
		*size = 0;
		*data = NULL;

		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_remove_carrier_config_group_property(
	net_nfc_carrier_property_s *group, uint16_t attribute)
{
	GNode *node;
	net_nfc_error_e result;

	if (group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	node = __find_property_by_attribute((GNode *)(group->data), attribute);
	if (node != NULL) {
		_release_tree(node);

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_free_carrier_group(
	net_nfc_carrier_property_s *group)
{
	if (group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_release_tree(group->data);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_ndef_record_with_carrier_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config)
{
	net_nfc_error_e result;

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	switch (config->type) {
	case NET_NFC_CONN_HANDOVER_CARRIER_BT :
		result = net_nfc_util_handover_bt_create_record_from_config(record, config);
		break;

	case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS :
		result = net_nfc_util_handover_wps_create_record_from_config(record, config);
		break;

	case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P :
		result = net_nfc_util_handover_wfd_create_record_from_config(record, config);
		break;

	default :
		result = NET_NFC_NOT_SUPPORTED;
		break;
	}

	return result;
}

net_nfc_error_e net_nfc_util_create_carrier_config_from_config_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record)
{
	net_nfc_error_e result;

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (net_nfc_util_handover_bt_check_carrier_record(record)) {
		result = net_nfc_util_handover_bt_create_config_from_record(config, record);
	} else if (net_nfc_util_handover_wps_check_carrier_record(record)) {
		result = net_nfc_util_handover_wps_create_config_from_record(config, record);
	} else if (net_nfc_util_handover_wfd_check_carrier_record(record)) {
		result = net_nfc_util_handover_wfd_create_config_from_record(config, record);
	} else {
		result = NET_NFC_NOT_SUPPORTED;
	}

	return result;
}

net_nfc_error_e net_nfc_util_create_carrier_config_from_carrier(
	net_nfc_carrier_config_s **config, net_nfc_ch_carrier_s *carrier)
{
	net_nfc_error_e result;
	ndef_record_s *record;

	if (carrier == NULL || carrier->carrier_record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	result = net_nfc_util_get_handover_carrier_record(carrier, &record);
	if (result == NET_NFC_OK) {
		result = net_nfc_util_create_carrier_config_from_config_record(config, record);
	}

	return result;
}

static net_nfc_error_e _create_collision_resolution_record(
	ndef_record_s **record)
{
	uint32_t state;
	uint16_t random_num;
	data_s typeName = { (uint8_t *)CH_CR_RECORD_TYPE,
		CH_CR_RECORD_TYPE_LEN };
	data_s payload = { (uint8_t *)&random_num, sizeof(random_num) };

	if (record == NULL)
		return NET_NFC_NULL_PARAMETER;

	state = (uint32_t)time(NULL);
	random_num = htons((unsigned short)rand_r(&state));

	return net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE,
		&typeName, NULL, &payload, record);
}

net_nfc_error_e net_nfc_util_create_handover_error_record(
	ndef_record_s **record, uint8_t reason, uint32_t data)
{
	data_s type = { (uint8_t *)CH_ERR_RECORD_TYPE, CH_ERR_RECORD_TYPE_LEN };
	data_s payload;
	int size = 1;

	switch (reason)
	{
	case 0x01 :
		size = 1;
		break;
	case 0x02 :
		size = 4;
		break;
	case 0x03 :
		size = 1;
		break;
	}

	_net_nfc_util_alloc_mem(payload.buffer, size);
	if (payload.buffer == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}
	payload.length = size;

	memcpy(payload.buffer, &data, size);

	net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE, &type, NULL,
		&payload, record);

	_net_nfc_util_free_mem(payload.buffer);

	return NET_NFC_OK;
}


net_nfc_error_e net_nfc_util_create_handover_carrier(
	net_nfc_ch_carrier_s **carrier,
	net_nfc_conn_handover_carrier_state_e cps)
{
	net_nfc_ch_carrier_s *temp;

	if (carrier == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	temp = g_new0(net_nfc_ch_carrier_s, 1);

	temp->cps = cps;

	*carrier = temp;

	return NET_NFC_OK;
}

static void _duplicate_carrier_cb(gpointer data, gpointer user_data)
{
	ndef_record_s *record = (ndef_record_s *)data;
	net_nfc_ch_carrier_s *temp = (net_nfc_ch_carrier_s *)user_data;

	if (record != NULL) {
		ndef_record_s *temp_record;

		net_nfc_util_create_record(record->TNF,
			&record->type_s,
			&record->id_s,
			&record->payload_s,
			&temp_record);

		temp->aux_records = g_list_append(temp->aux_records,
			temp_record);
	}
}

net_nfc_error_e net_nfc_util_duplicate_handover_carrier(
	net_nfc_ch_carrier_s **dest,
	net_nfc_ch_carrier_s *src)
{
	net_nfc_ch_carrier_s *temp;

	if (dest == NULL || src == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	temp = g_new0(net_nfc_ch_carrier_s, 1);

	temp->type = src->type;
	temp->cps = src->cps;

	if (src->carrier_record != NULL) {
		net_nfc_util_create_record(src->carrier_record->TNF,
			&src->carrier_record->type_s,
			&src->carrier_record->id_s,
			&src->carrier_record->payload_s,
			&temp->carrier_record);
	}

	g_list_foreach(src->aux_records, _duplicate_carrier_cb, temp);

	*dest = temp;

	return NET_NFC_OK;
}


static void _ch_carrier_free_cb(gpointer data)
{
	ndef_record_s *record = (ndef_record_s *)data;

	net_nfc_util_free_record(record);
}

net_nfc_error_e net_nfc_util_free_handover_carrier(
	net_nfc_ch_carrier_s *carrier)
{
	if (carrier == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	g_list_free_full(carrier->aux_records, _ch_carrier_free_cb);

	net_nfc_util_free_record(carrier->carrier_record);

	g_free(carrier);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_set_handover_carrier_cps(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_state_e cps)
{
	if (carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	carrier->cps = cps;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_handover_carrier_cps(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_state_e *cps)
{
	if (carrier == NULL || cps == NULL)
		return NET_NFC_NULL_PARAMETER;

	*cps = carrier->cps;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_set_handover_carrier_type(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_type_e type)
{
	if (carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	carrier->type = type;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_handover_carrier_type(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_type_e *type)
{
	if (carrier == NULL || type == NULL)
		return NET_NFC_NULL_PARAMETER;

	*type = carrier->type;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_append_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s *record)
{
	if (carrier == NULL || record == NULL)
		return NET_NFC_NULL_PARAMETER;

	net_nfc_util_remove_handover_carrier_record(carrier);

	return net_nfc_util_create_record(record->TNF, &record->type_s, NULL,
		&record->payload_s, &carrier->carrier_record);
}

net_nfc_error_e net_nfc_util_get_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s **record)
{
	if (carrier == NULL || record == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (carrier->carrier_record != NULL) {
		*record = carrier->carrier_record;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier)
{
	if (carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (carrier->carrier_record != NULL) {
		net_nfc_util_free_record(carrier->carrier_record);
		carrier->carrier_record = NULL;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_append_handover_auxiliary_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s *record)
{
	net_nfc_error_e result;
	ndef_record_s *temp = NULL;

	if (carrier == NULL || record == NULL)
		return NET_NFC_NULL_PARAMETER;

	result = net_nfc_util_create_record(record->TNF, &record->type_s, NULL,
			&record->payload_s, &temp);
	if (result == NET_NFC_OK) {
		carrier->aux_records = g_list_append(carrier->aux_records,
			temp);
	}

	return result;
}

net_nfc_error_e net_nfc_util_get_handover_auxiliary_record_count(
	net_nfc_ch_carrier_s *carrier, uint32_t *count)
{
	if (carrier == NULL || count == NULL)
		return NET_NFC_NULL_PARAMETER;

	*count = g_list_length(carrier->aux_records);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_handover_auxiliary_record(
	net_nfc_ch_carrier_s *carrier, int index, ndef_record_s **record)
{
	net_nfc_error_e result;
	GList *item;

	if (carrier == NULL || record == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (index < 0 || index >= g_list_length(carrier->aux_records))
		return NET_NFC_OUT_OF_BOUND;

	item = g_list_nth(carrier->aux_records, index);
	if (item != NULL) {
		*record = (ndef_record_s *)item->data;
		result = NET_NFC_OK;
	} else {
		result = NET_NFC_OUT_OF_BOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_remove_handover_auxiliary_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s *record)
{
	net_nfc_error_e result;
	GList *list;

	if (carrier == NULL || record == NULL)
		return NET_NFC_NULL_PARAMETER;

	list = g_list_find(carrier->aux_records, record);
	if (list != NULL) {
		net_nfc_util_free_record((ndef_record_s *)list->data);
		carrier->aux_records = g_list_delete_link(carrier->aux_records,
			list);

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

net_nfc_error_e net_nfc_util_create_handover_message(
	net_nfc_ch_message_s **message)
{
	net_nfc_ch_message_s *temp;

	if (message == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	temp = g_new0(net_nfc_ch_message_s, 1);

	temp->version = CH_VERSION;

	*message = temp;

	return NET_NFC_OK;
}

static void _ch_message_free_cb(gpointer data)
{
	net_nfc_ch_carrier_s *carrier = (net_nfc_ch_carrier_s *)data;

	net_nfc_util_free_handover_carrier(carrier);
}

net_nfc_error_e net_nfc_util_free_handover_message(
	net_nfc_ch_message_s *message)
{
	if (message == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	DEBUG_MSG("free [%p]", message);

	g_list_free_full(message->carriers, _ch_message_free_cb);
	message->carriers = NULL;

	g_free(message);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_set_handover_message_type(
	net_nfc_ch_message_s *message, net_nfc_ch_type_e type)
{
	if (message == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (type >= NET_NFC_CH_TYPE_MAX) {
		return NET_NFC_OUT_OF_BOUND;
	}

	message->type = type;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_handover_message_type(
	net_nfc_ch_message_s *message, net_nfc_ch_type_e *type)
{
	if (message == NULL || type == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	*type = message->type;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_append_handover_carrier(
	net_nfc_ch_message_s *message, net_nfc_ch_carrier_s *carrier)
{
	if (message == NULL || carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	message->carriers = g_list_append(message->carriers, carrier);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_handover_carrier_count(
	net_nfc_ch_message_s *message, uint32_t *count)
{
	if (message == NULL || count == NULL)
		return NET_NFC_NULL_PARAMETER;

	*count = g_list_length(message->carriers);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_handover_carrier(
	net_nfc_ch_message_s *message, int index,
	net_nfc_ch_carrier_s **carrier)
{
	net_nfc_error_e result;
	GList *list;

	if (message == NULL || carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (index < 0 || index >= g_list_length(message->carriers))
		return NET_NFC_INVALID_PARAM;

	list = g_list_nth(message->carriers, index);
	if (list != NULL) {
		*carrier = list->data;
		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

static gint _compare_cb(gconstpointer a, gconstpointer b)
{
	net_nfc_ch_carrier_s *carrier = (net_nfc_ch_carrier_s *)a;
	net_nfc_conn_handover_carrier_type_e type =
		(net_nfc_conn_handover_carrier_type_e)b;

	if (carrier->type == type)
		return 0;
	else
		return 1;
}

net_nfc_error_e net_nfc_util_get_handover_carrier_by_type(
	net_nfc_ch_message_s *message,
	net_nfc_conn_handover_carrier_type_e type,
	net_nfc_ch_carrier_s **carrier)
{
	net_nfc_error_e result;
	GList *list;

	if (message == NULL || carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	list = g_list_find_custom(message->carriers, (gconstpointer)type,
		_compare_cb);
	if (list != NULL) {
		*carrier = list->data;

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

typedef struct _ch_payload_t
{
	uint8_t version;
	uint8_t message[0];
}
__attribute__((packed)) ch_payload_t;

typedef struct _ch_ac_ref_t
{
	uint8_t ref_len;
	uint8_t ref[0];
}
__attribute__((packed)) ch_ac_ref_t;

typedef struct _ch_ac_header_t
{
	uint8_t cps : 3;
	uint8_t rfu : 5;
	uint8_t data[0];
}
__attribute__((packed)) ch_ac_header_t;

typedef struct _ch_ac_aux_header_t
{
	uint8_t count;
	uint8_t data[0];
}
__attribute__((packed)) ch_ac_aux_header_t;

static void _change_id_field_and_add_record(uint8_t *buffer, uint32_t length,
	ndef_record_s *record, ndef_message_s *message)
{
	data_s id = { buffer, length };
	ndef_record_s *temp = NULL;

	net_nfc_util_create_record(record->TNF,
		&record->type_s,
		&id, &record->payload_s, &temp);

	net_nfc_util_append_record(message, temp);
}

static void _ch_message_export_cb(gpointer data, gpointer user_data)
{
	gpointer *params = (gpointer *)user_data;
	net_nfc_ch_carrier_s *carrier = (net_nfc_ch_carrier_s *)data;
	ndef_message_s *inner_msg;
	ndef_message_s *main_msg;
	int count;
	data_s type = { (uint8_t *)CH_AC_RECORD_TYPE, CH_AC_RECORD_TYPE_LEN };
	data_s payload;
	ndef_record_s *record = NULL;
	char *id;

	if (carrier->carrier_record == NULL)
		return;

	id = (char *)params[0];
	inner_msg = (ndef_message_s *)params[1];
	main_msg = (ndef_message_s *)params[2];

	/* count total record */
	count = 1/* carrier record */ + g_list_length(carrier->aux_records);

	/* create ac record */
	net_nfc_util_init_data(&payload,
		sizeof(ch_ac_header_t) + sizeof(ch_ac_aux_header_t) +
		count * (sizeof(ch_ac_ref_t) + 4/* max length is 4 */));

	ch_ac_header_t *header = (ch_ac_header_t *)payload.buffer;

	header->cps = carrier->cps;

	payload.length = sizeof(ch_ac_header_t);

	/* carrier record */
	ch_ac_ref_t *ref = (ch_ac_ref_t *)header->data;

	ref->ref[0] = *id++;
	ref->ref_len = 1;

	_change_id_field_and_add_record(ref->ref, ref->ref_len,
		carrier->carrier_record, main_msg);

	payload.length += sizeof(ch_ac_ref_t) + ref->ref_len;

	/* aux record */
	ch_ac_aux_header_t *aux = (ch_ac_aux_header_t *)(ref->ref +
		ref->ref_len);

	aux->count = g_list_length(carrier->aux_records);

	payload.length += sizeof(ch_ac_aux_header_t);

	GList *list = g_list_first(carrier->aux_records);
	ref = (ch_ac_ref_t *)aux->data;

	while (list != NULL) {
		ref->ref[0] = *id++;
		ref->ref_len = 1;

		_change_id_field_and_add_record(ref->ref, ref->ref_len,
			(ndef_record_s *)list->data, main_msg);

		payload.length += sizeof(ch_ac_ref_t) + ref->ref_len;
		ref = (ch_ac_ref_t *)(ref->ref + ref->ref_len);

		list = g_list_next(list);
	}

	/* append ac record */
	net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE,
		&type, NULL, &payload, &record);

	net_nfc_util_append_record(inner_msg, record);

	net_nfc_util_clear_data(&payload);
}

static void _get_handover_type_field(net_nfc_ch_type_e type, data_s *result)
{
	switch (type) {
	case NET_NFC_CH_TYPE_REQUEST :
		result->buffer = (uint8_t *)CH_REQ_RECORD_TYPE;
		result->length = CH_REQ_RECORD_TYPE_LEN;
		break;

	case NET_NFC_CH_TYPE_SELECT :
		result->buffer = (uint8_t *)CH_SEL_RECORD_TYPE;
		result->length = CH_SEL_RECORD_TYPE_LEN;
		break;

	case NET_NFC_CH_TYPE_MEDIATION :
		result->buffer = (uint8_t *)CH_MED_RECORD_TYPE;
		result->length = CH_MED_RECORD_TYPE_LEN;
		break;

	case NET_NFC_CH_TYPE_INITIAITE :
		result->buffer = (uint8_t *)CH_INI_RECORD_TYPE;
		result->length = CH_INI_RECORD_TYPE_LEN;
		break;

	default :
		break;
	}
}

net_nfc_error_e net_nfc_util_export_handover_to_ndef_message(
	net_nfc_ch_message_s *message, ndef_message_s **result)
{
	net_nfc_error_e error;
	gpointer params[3];
	ndef_message_s *inner_msg = NULL;
	ndef_message_s *main_msg = NULL;
	data_s payload;
	uint32_t len;
	char id = 'A';

	if (message == NULL || result == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	error = net_nfc_util_create_ndef_message(&inner_msg);
	if (error != NET_NFC_OK)
	{
		return error;
	}

	error = net_nfc_util_create_ndef_message(&main_msg);
	if (error != NET_NFC_OK)
	{
		net_nfc_util_free_ndef_message(inner_msg);

		return error;
	}

	params[0] = &id;
	params[1] = inner_msg;
	params[2] = main_msg;

	g_list_foreach(message->carriers, _ch_message_export_cb, params);

	if (message->type == NET_NFC_CH_TYPE_REQUEST) {
		ndef_record_s *cr = NULL;

		/* append collision resolution record */
		_create_collision_resolution_record(&cr);

		net_nfc_util_append_record_by_index(inner_msg, 0, cr);
	}

	/* convert message to raw data */
	len = net_nfc_util_get_ndef_message_length(inner_msg);

	if (net_nfc_util_init_data(&payload, sizeof(ch_payload_t) + len) ==
		true) {
		data_s data;
		ch_payload_t *header;

		header = (ch_payload_t *)payload.buffer;

		data.buffer = header->message;
		data.length = len;

		error = net_nfc_util_convert_ndef_message_to_rawdata(inner_msg,
			&data);
		if (error == NET_NFC_OK) {
			ndef_record_s *hr = NULL;
			data_s type;

			/* set version */
			header->version = CH_VERSION;

			_get_handover_type_field(message->type, &type);

			/* create Hr record */
			error = net_nfc_util_create_record(
				NET_NFC_RECORD_WELL_KNOWN_TYPE,
				&type, NULL, &payload, &hr);
			if (error == NET_NFC_OK) {
				/* append first record */
				net_nfc_util_append_record_by_index(main_msg, 0,
					hr);

				*result = main_msg;
			} else {
				DEBUG_ERR_MSG("net_nfc_util_create_record failed, [%d]", error);
			}

			net_nfc_util_free_ndef_message(inner_msg);
		} else {
			DEBUG_ERR_MSG("net_nfc_util_convert_ndef_message_to_rawdata failed, [%d]", error);
		}

		net_nfc_util_clear_data(&payload);
	} else {
		DEBUG_ERR_MSG("net_nfc_util_alloc_data failed");
	}

	return error;
}

static ndef_message_s *_raw_data_to_ndef_message(data_s *data)
{
	net_nfc_error_e result;
	ndef_message_s *msg = NULL;

	result = net_nfc_util_create_ndef_message(&msg);
	if (result == NET_NFC_OK) {
		result = net_nfc_util_convert_rawdata_to_ndef_message(data,
			msg);
		if (result != NET_NFC_OK) {
			net_nfc_util_free_ndef_message(msg);
			msg = NULL;
		}
	}

	return msg;
}

static ndef_record_s *_find_record_by_id(uint8_t *id, uint8_t id_len,
	ndef_record_s *records)
{
	ndef_record_s *record = NULL;

	while (records != NULL) {
		if (records->id_s.length == id_len &&
			memcmp(id, records->id_s.buffer, id_len) == 0) {
			record = records;

			break;
		}
		records = records->next;
	}

	return record;
}

static void _fill_aux_rec(net_nfc_ch_carrier_s *carrier,
	ch_ac_aux_header_t *header, ndef_record_s *content)
{
	if (header == NULL)
		return;

	/* copy auxiliary record */
	if (header->count > 0) {
		int i;
		ndef_record_s *record;
		ndef_record_s *temp;
		ch_ac_ref_t *ref;

		ref = (ch_ac_ref_t *)header->data;

		for (i = 0; i < header->count; i++) {
			record = _find_record_by_id(ref->ref, ref->ref_len,
				content);
			if (record != NULL) {
				net_nfc_util_create_record(record->TNF,
					&record->type_s,
					NULL, &record->payload_s,
					&temp);

				carrier->aux_records = g_list_append(
					carrier->aux_records, temp);
			}

			ref = (ch_ac_ref_t *)(ref->ref + ref->ref_len);
		}
	}
}

static net_nfc_conn_handover_carrier_type_e _get_carrier_type_from_record(
	ndef_record_s *record)
{
	net_nfc_conn_handover_carrier_type_e result;

	if (net_nfc_util_handover_bt_check_carrier_record(record))
	{
		result = NET_NFC_CONN_HANDOVER_CARRIER_BT;
	}
	else if (net_nfc_util_handover_wps_check_carrier_record(record))
	{
		result = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS;
	}
	else if (net_nfc_util_handover_wfd_check_carrier_record(record))
	{
		result = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P;
	}
	else
	{
		result = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
	}

	return result;
}

static net_nfc_error_e _fill_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier,
	ch_ac_ref_t *ref, ndef_record_s *content)
{
	net_nfc_error_e result;
	ndef_record_s *record;

	if (carrier == NULL)
		return NET_NFC_NULL_PARAMETER;

	/* copy carrier record */
	record = _find_record_by_id(ref->ref, ref->ref_len, content);
	if (record != NULL) {
		DEBUG_MSG("carrier found [%p]", ref->ref);

		carrier->type = _get_carrier_type_from_record(record);

		result = net_nfc_util_create_record(record->TNF,
			&record->type_s, NULL,
			&record->payload_s,
			&carrier->carrier_record);

		_fill_aux_rec(carrier,
			(ch_ac_aux_header_t *)(ref->ref + ref->ref_len),
			content);

		result = NET_NFC_OK;
	} else {
		DEBUG_ERR_MSG("carrier record not found, [%s]", ref->ref);

		result = NET_NFC_NO_DATA_FOUND;
	}

	return result;
}

static net_nfc_error_e _fill_handover_message(net_nfc_ch_message_s *msg,
	ndef_record_s *header, ndef_record_s *content)
{
	net_nfc_error_e result = NET_NFC_OK;
	ndef_record_s *current = header;

	DEBUG_MSG("header [%p], content [%p]", header, content);

	while (current != NULL &&
		CHECK_TYPE(current->type_s, CH_AC_RECORD_TYPE) == true) {
		net_nfc_ch_carrier_s *carrier;
		ch_ac_header_t *ac_header;
		net_nfc_conn_handover_carrier_state_e cps;

		ac_header = (ch_ac_header_t *)current->payload_s.buffer;

		cps = ac_header->cps;

		result = net_nfc_util_create_handover_carrier(&carrier, cps);
		if (result == NET_NFC_OK) {
			ch_ac_ref_t *ref;

			/* copy carrier record */
			ref = (ch_ac_ref_t *)ac_header->data;

			result = _fill_handover_carrier_record(carrier, ref,
				content);
			if (result == NET_NFC_OK) {
				net_nfc_util_append_handover_carrier(msg,
					carrier);
			} else {
				DEBUG_ERR_MSG("_fill_handover_carrier_record failed, [%d]", result);

				net_nfc_util_free_handover_carrier(carrier);
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_util_create_handover_carrier failed, [%d]", result);
		}

		current = current->next;
	}

	return result;
}

static net_nfc_ch_type_e _get_handover_type_from_type_data(data_s *result)
{
	net_nfc_ch_type_e type;

	if (CHECK_TYPE((*result), CH_REQ_RECORD_TYPE) == true) {
		type = NET_NFC_CH_TYPE_REQUEST;
	} else if (CHECK_TYPE((*result), CH_SEL_RECORD_TYPE) == true) {
		type = NET_NFC_CH_TYPE_SELECT;
	} else if (CHECK_TYPE((*result), CH_MED_RECORD_TYPE) == true) {
		type = NET_NFC_CH_TYPE_MEDIATION;
	} else if (CHECK_TYPE((*result), CH_INI_RECORD_TYPE) == true) {
		type = NET_NFC_CH_TYPE_INITIAITE;
	} else {
		type = NET_NFC_CH_TYPE_UNKNOWN;
	}

	return type;
}

net_nfc_error_e net_nfc_util_import_handover_from_ndef_message(
	ndef_message_s *msg, net_nfc_ch_message_s **result)
{
	net_nfc_error_e error;
	ndef_record_s *hr = NULL;
	net_nfc_ch_type_e type;

	if (msg == NULL || result == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	/* first record */
	error = net_nfc_util_get_record_by_index(msg, 0, &hr);
	if (error != NET_NFC_OK) {
		DEBUG_ERR_MSG("net_nfc_util_get_record_by_index failed, [%d]", error);

		return error;
	}

	if (hr->TNF != NET_NFC_RECORD_WELL_KNOWN_TYPE) {
		return NET_NFC_INVALID_FORMAT;
	}

	type = _get_handover_type_from_type_data(&hr->type_s);
	if (type == NET_NFC_CH_TYPE_UNKNOWN) {
		return NET_NFC_INVALID_FORMAT;
	}

	ndef_message_s *inner;
	data_s data;
	ch_payload_t *header;

	/* check type */
	header = (ch_payload_t *)hr->payload_s.buffer;

	/* check version */

	/* get records */
	data.buffer = header->message;
	data.length = hr->payload_s.length - sizeof(ch_payload_t);

	DEBUG_MSG("data [%p][%d]", data.buffer, data.length);

	inner = _raw_data_to_ndef_message(&data);
	if (inner != NULL) {
		net_nfc_ch_message_s *temp;

		error = net_nfc_util_create_handover_message(&temp);
		if (error == NET_NFC_OK) {
			ndef_record_s *record = NULL;

			temp->version = header->version;
			temp->type = _get_handover_type_from_type_data(
				&hr->type_s);

			record = inner->records;

			if (temp->type == NET_NFC_CH_TYPE_REQUEST) {
				/* get cr */
				if (CHECK_TYPE(record->type_s, CH_CR_RECORD_TYPE) == true) {
					temp->cr = htons(*(uint16_t *)record->payload_s.buffer);

					record = record->next;
				}
			}

			_fill_handover_message(temp, record, msg->records);

			*result = temp;
		} else {
			DEBUG_ERR_MSG("net_nfc_util_create_handover_message failed, [%d]", error);
		}

		net_nfc_util_free_ndef_message(inner);
	} else {
		DEBUG_ERR_MSG("_raw_data_to_ndef_message failed");

		error = NET_NFC_ALLOC_FAIL;
	}

	return error;
}

net_nfc_error_e net_nfc_util_get_handover_random_number(
	net_nfc_ch_message_s *message, uint16_t *random_number)
{
	if (message == NULL || random_number == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (message->type != NET_NFC_CH_TYPE_REQUEST) {
		return NET_NFC_INVALID_PARAM;
	}

	*random_number = message->cr;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_selector_power_status(
	net_nfc_ch_message_s *message,
	net_nfc_conn_handover_carrier_state_e *cps)
{
	net_nfc_error_e error;
	int count;

	if (message == NULL || cps == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	count = g_list_length(message->carriers);

	if (count > 1) {
		int i;
		GList *list;
		net_nfc_ch_carrier_s *carrier;

		*cps = NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE;

		for (i = 0; i < count; i++) {
			list = g_list_nth(message->carriers, i);
			carrier = list->data;
			if (carrier->cps == NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE ||
				carrier->cps == NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING) {

				*cps = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;
				break;
			}
		}

		error = NET_NFC_OK;
	} else if (count == 1) {
		*cps = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;

		error = NET_NFC_OK;
	} else {
		error = NET_NFC_NO_DATA_FOUND;
	}

	return error;
}
