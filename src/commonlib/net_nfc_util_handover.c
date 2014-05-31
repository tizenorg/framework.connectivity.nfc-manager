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


#include <glib.h>

#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_handover.h"

typedef struct _search_index
{
	int target;
	int current;
	void *found;
} search_index;

static int __property_equal_to(gconstpointer key1, gconstpointer key2)
{
	net_nfc_carrier_property_s *arg1 = (net_nfc_carrier_property_s *)key1;
	net_nfc_carrier_property_s *arg2 = (net_nfc_carrier_property_s *)key2;

	if (arg1->attribute < arg2->attribute)
	{
		return -1;
	}
	else if (arg1->attribute > arg2->attribute)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static net_nfc_carrier_property_s *__find_property_by_attrubute(GList *list, uint16_t attribute)
{
	GList *found = NULL;
	net_nfc_carrier_property_s temp;

	temp.attribute = attribute;
	found = g_list_find_custom(list, &temp, __property_equal_to);

	if (found == NULL)
	{
		return NULL;
	}

	return (net_nfc_carrier_property_s *)found->data;
}

static void __find_nth_group(gpointer data, gpointer user_data)
{
	net_nfc_carrier_property_s *info = (net_nfc_carrier_property_s *)data;
	search_index *nth = (search_index *)user_data;

	if (info == NULL || user_data == NULL)
		return;

	if (info->is_group)
	{
		if (nth->current == nth->target)
		{
			nth->found = data;
		}
		nth->current++;
	}
}

static void __free_all_data(gpointer data, gpointer user_data)
{
	net_nfc_carrier_property_s *info = (net_nfc_carrier_property_s *)data;

	if (info == NULL)
		return;

	if (info->is_group)
	{
		DEBUG_MSG("FREE: group is found");
		net_nfc_util_free_carrier_group((net_nfc_carrier_property_s *)info);
	}
	else
	{
		DEBUG_MSG("FREE: element is found ATTRIB:0x%X length:%d", info->attribute, info->length);
		_net_nfc_util_free_mem(info->data);
		_net_nfc_util_free_mem(info);
	}
}

static net_nfc_error_e __net_nfc_util_create_connection_handover_collsion_resolution_record(ndef_record_s **record)
{
	uint32_t state = 0;
	data_s typeName = { 0 };
	data_s payload = { 0 };
	uint8_t rand_buffer[2] = { 0, 0 };
	uint16_t random_num;

	if (record == NULL)
		return NET_NFC_NULL_PARAMETER;

	state = (uint32_t)time(NULL);
	random_num = (unsigned short)rand_r(&state);

	typeName.buffer = (uint8_t *)COLLISION_DETECT_RECORD_TYPE;
	typeName.length = strlen(COLLISION_DETECT_RECORD_TYPE);

	rand_buffer[0] = (random_num & 0xff00) >> 8;	// MSB
	rand_buffer[1] = (random_num & 0x00ff);	// LSB

	payload.buffer = rand_buffer;
	payload.length = 2;

	DEBUG_MSG("rand number = [0x%x] [0x%x] => [0x%x]", payload.buffer[0], payload.buffer[1], random_num);

	return net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE, &typeName, NULL, &payload, record);
}

static int __net_nfc_get_size_of_attribute(int attribute)
{
	switch (attribute)
	{
	case NET_NFC_BT_ATTRIBUTE_UUID16_PART :
	case NET_NFC_BT_ATTRIBUTE_UUID16 :
	case NET_NFC_BT_ATTRIBUTE_UUID32_PART :
	case NET_NFC_BT_ATTRIBUTE_UUID32 :
	case NET_NFC_BT_ATTRIBUTE_UUID128_PART :
	case NET_NFC_BT_ATTRIBUTE_UUID128 :
	case NET_NFC_BT_ATTRIBUTE_NAME_PART :
	case NET_NFC_BT_ATTRIBUTE_NAME :
	case NET_NFC_BT_ATTRIBUTE_TXPOWER :
	case NET_NFC_BT_ATTRIBUTE_OOB_COD :
	case NET_NFC_BT_ATTRIBUTE_OOB_HASH_C :
	case NET_NFC_BT_ATTRIBUTE_OOB_HASH_R :
	case NET_NFC_BT_ATTRIBUTE_ID :
	case NET_NFC_BT_ATTRIBUTE_MANUFACTURER :
	case NET_NFC_BT_ATTRIBUTE_ADDRESS :
		//		case NET_NFC_WIFI_ATTRIBUTE_VERSION2:
		return 1;

	default :
		return 2;
	}
}

net_nfc_error_e net_nfc_util_create_carrier_config(net_nfc_carrier_config_s **config, net_nfc_conn_handover_carrier_type_e type)
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
	(*config)->length = 0;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_add_carrier_config_property(net_nfc_carrier_config_s *config, uint16_t attribute, uint16_t size, uint8_t * data)
{
	net_nfc_carrier_property_s *elem = NULL;

	DEBUG_MSG("ADD property: [ATTRIB:0x%X, SIZE:%d]", attribute, size);

	if (config == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (__find_property_by_attrubute(config->data, attribute) != NULL)
	{
		return NET_NFC_ALREADY_REGISTERED;
	}

	_net_nfc_util_alloc_mem(elem, sizeof (net_nfc_carrier_property_s));
	if (elem == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}
	elem->attribute = attribute;
	elem->length = size;
	elem->is_group = false;
	_net_nfc_util_alloc_mem(elem->data, size);

	if (elem->data == NULL)
	{
		_net_nfc_util_free_mem(elem);
		return NET_NFC_ALLOC_FAIL;
	}
	memcpy(elem->data, data, size);

	config->data = g_list_append(config->data, elem);
	config->length += size + 2 * __net_nfc_get_size_of_attribute(attribute);

	DEBUG_MSG("ADD completed total length %d", config->length);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_carrier_config_property(net_nfc_carrier_config_s *config, uint16_t attribute)
{
	net_nfc_carrier_property_s *elem = NULL;

	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	elem = __find_property_by_attrubute(config->data, attribute);
	if (elem == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	config->data = g_list_remove(config->data, elem);
	config->length -= (elem->length + 2 * __net_nfc_get_size_of_attribute(attribute));

	if (elem->is_group)
	{
		net_nfc_util_free_carrier_group((net_nfc_carrier_property_s *)elem);
	}
	else
	{
		_net_nfc_util_free_mem(elem->data);
		_net_nfc_util_free_mem(elem);
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_carrier_config_property(net_nfc_carrier_config_s *config, uint16_t attribute, uint16_t * size, uint8_t ** data)
{
	net_nfc_carrier_property_s *elem = NULL;

	if (config == NULL || size == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	elem = __find_property_by_attrubute(config->data, attribute);
	if (elem == NULL)
	{
		*size = 0;
		*data = NULL;
		return NET_NFC_NO_DATA_FOUND;
	}

	*size = elem->length;
	if (elem->is_group)
	{
		*data = NULL;
	}
	else
	{
		*data = elem->data;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_append_carrier_config_group(net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group)
{
	if (config == NULL || group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	if (g_list_find(config->data, group) != NULL)
	{
		return NET_NFC_ALREADY_REGISTERED;
	}

	config->data = g_list_append(config->data, group);
	config->length += group->length;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_carrier_config_group(net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group)
{
	if (config == NULL || group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (g_list_find(config->data, group) != NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	config->length -= group->length;
	config->data = g_list_remove(config->data, group);

	net_nfc_util_free_carrier_group((net_nfc_carrier_property_s *)group);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_carrier_config_group(net_nfc_carrier_config_s *config, int index, net_nfc_carrier_property_s **group)
{
	search_index result;

	if (config == NULL || group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (index < 0)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	result.current = 0;
	result.target = index;
	result.found = NULL;

	g_list_foreach(config->data, __find_nth_group, &result);

	if (result.found == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}
	*group = (net_nfc_carrier_property_s *)result.found;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_free_carrier_config(net_nfc_carrier_config_s *config)
{
	if (config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	g_list_foreach(config->data, __free_all_data, NULL);
	g_list_free(config->data);

	_net_nfc_util_free_mem(config);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_carrier_config_group(net_nfc_carrier_property_s **group, uint16_t attribute)
{
	if (group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(*group, sizeof(net_nfc_carrier_property_s));
	if (*group == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	(*group)->attribute = attribute;
	(*group)->is_group = true;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_add_carrier_config_group_property(net_nfc_carrier_property_s *group, uint16_t attribute, uint16_t size, uint8_t *data)
{
	net_nfc_carrier_property_s *elem = NULL;

	DEBUG_MSG("ADD group property: [ATTRIB:0x%X, SIZE:%d]", attribute, size);

	if (group == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (__find_property_by_attrubute((GList *)group->data, attribute) != NULL)
	{
		return NET_NFC_ALREADY_REGISTERED;
	}

	_net_nfc_util_alloc_mem(elem, sizeof (net_nfc_carrier_property_s));
	if (elem == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}
	elem->attribute = attribute;
	elem->length = size;
	elem->is_group = false;

	_net_nfc_util_alloc_mem(elem->data, size);
	if (elem->data == NULL)
	{
		_net_nfc_util_free_mem(elem);
		return NET_NFC_ALLOC_FAIL;
	}
	memcpy(elem->data, data, size);
	group->length += size + 2 * __net_nfc_get_size_of_attribute(attribute);
	group->data = g_list_append((GList *)(group->data), elem);

	DEBUG_MSG("ADD group completed total length %d", group->length);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_carrier_config_group_property(net_nfc_carrier_property_s *group, uint16_t attribute, uint16_t *size, uint8_t ** data)
{
	net_nfc_carrier_property_s *elem = NULL;

	if (group == NULL || size == NULL || data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	elem = __find_property_by_attrubute((GList*)(group->data), attribute);
	if (elem == NULL)
	{
		*size = 0;
		*data = NULL;
		return NET_NFC_NO_DATA_FOUND;
	}

	*size = elem->length;
	*data = elem->data;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_carrier_config_group_property(net_nfc_carrier_property_s *group, uint16_t attribute)
{
	net_nfc_carrier_property_s *elem = NULL;

	if (group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	elem = __find_property_by_attrubute((GList*)(group->data), attribute);
	if (elem == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}
	group->length -= elem->length;
	group->data = g_list_remove((GList*)(group->data), elem);

	_net_nfc_util_free_mem(elem->data);
	_net_nfc_util_free_mem(elem);

	return NET_NFC_OK;

}

net_nfc_error_e net_nfc_util_free_carrier_group(net_nfc_carrier_property_s *group)
{
	if (group == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	g_list_foreach((GList*)(group->data), __free_all_data, NULL);
	g_list_free((GList*)(group->data));

	_net_nfc_util_free_mem(group);

	return NET_NFC_OK;
}

static void __make_serial_wifi(gpointer data, gpointer user_data)
{
	net_nfc_carrier_property_s *info = (net_nfc_carrier_property_s *)data;
	data_s *payload = (data_s *)user_data;
	uint8_t *current;
	int inc = 0;

	if (info == NULL || user_data == NULL)
		return;

	current = payload->buffer + payload->length;
	inc = __net_nfc_get_size_of_attribute(info->attribute);

	if (info->is_group)
	{
		DEBUG_MSG("[WIFI]Found Group make recursive");
		*(uint16_t *)current = info->attribute;
		*(uint16_t *)(current + inc) = info->length;
		payload->length += (inc + inc);
		g_list_foreach((GList *)info->data, __make_serial_wifi, payload);
	}
	else
	{
		DEBUG_MSG("[WIFI]Element is found attrib:0x%X length:%d current:%d", info->attribute, info->length, payload->length);
		*(uint16_t *)current = info->attribute;
		*(uint16_t *)(current + inc) = info->length;
		memcpy(current + inc + inc, info->data, info->length);
		payload->length += (inc + inc + info->length);
	}
}

static void __make_serial_bt(gpointer data, gpointer user_data)
{
	net_nfc_carrier_property_s *info = (net_nfc_carrier_property_s *)data;
	data_s *payload = (data_s *)user_data;
	uint8_t *current;
	int inc = 0;

	if (info == NULL || user_data == NULL)
		return;

	current = payload->buffer + payload->length; /* payload->length is zero */

	if (info->is_group)
	{
		DEBUG_MSG("[BT]Found Group. call recursive");
		g_list_foreach((GList *)info->data, __make_serial_bt, payload);
	}
	else
	{
		if (info->attribute != NET_NFC_BT_ATTRIBUTE_ADDRESS)
		{
			DEBUG_MSG("[BT]Element is found attrib:0x%X length:%d current:%d", info->attribute, info->length, payload->length);
			inc = __net_nfc_get_size_of_attribute(info->attribute);
			*current = info->length + 1;
			*(current + inc) = info->attribute;
			memcpy(current + inc + inc, info->data, info->length);
			payload->length += (inc + inc + info->length);
		}
		else
		{
			DEBUG_MSG("[BT]BT address is found length:%d", info->length);
			memcpy(current, info->data, info->length);
			payload->length += (info->length);
		}
	}
}

net_nfc_error_e net_nfc_util_create_ndef_record_with_carrier_config(ndef_record_s **record, net_nfc_carrier_config_s *config)
{
	data_s payload = { NULL, 0 };
	data_s record_type = { NULL, 0 };

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(payload.buffer, config->length);
	if (payload.buffer == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}
	payload.length = 0; /* this should be zero because this will be used as current position of data written */

	if (config->type == NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS)
	{
		record_type.buffer = (uint8_t *)CONN_HANDOVER_WIFI_BSS_CARRIER_MIME_NAME;
		record_type.length = strlen(CONN_HANDOVER_WIFI_BSS_CARRIER_MIME_NAME);
		g_list_foreach(config->data, __make_serial_wifi, &payload);
	}
	else if (config->type == NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS)
	{
		record_type.buffer = (uint8_t *)CONN_HANDOVER_WIFI_IBSS_CARRIER_MIME_NAME;
		record_type.length = strlen(CONN_HANDOVER_WIFI_IBSS_CARRIER_MIME_NAME);
		g_list_foreach(config->data, __make_serial_wifi, &payload);
	}
	else if (config->type == NET_NFC_CONN_HANDOVER_CARRIER_BT)
	{
		record_type.buffer = (uint8_t *)CONN_HANDOVER_BT_CARRIER_MIME_NAME;
		record_type.length = strlen(CONN_HANDOVER_BT_CARRIER_MIME_NAME);
		payload.buffer += 2; /* OOB total length */
		g_list_foreach(config->data, __make_serial_bt, &payload);
		payload.buffer -= 2; /* return to original */
		payload.length += 2;
		payload.buffer[0] = payload.length & 0xFF;
		payload.buffer[1] = (payload.length >> 8) & 0xFF;
	}
	else
	{
		return NET_NFC_NOT_SUPPORTED;
	}

	DEBUG_MSG("payload length = %d", payload.length);

	return net_nfc_util_create_record(NET_NFC_RECORD_MIME_TYPE, &record_type, NULL, &payload, record);
}

static net_nfc_error_e __net_nfc_get_list_from_serial_for_wifi(GList **list, uint8_t *data, uint32_t length)
{
	net_nfc_carrier_property_s *elem = NULL;
	uint8_t *current = data;
	uint8_t *last = current + length;

	while (current < last)
	{
		_net_nfc_util_alloc_mem(elem, sizeof(net_nfc_carrier_property_s));
		if (elem == NULL)
		{
			return NET_NFC_ALLOC_FAIL;
		}
		elem->attribute = *((uint16_t *)current);
		elem->length = *((uint16_t *)(current + 2));

		if (elem->attribute == NET_NFC_WIFI_ATTRIBUTE_CREDENTIAL)
		{
			__net_nfc_get_list_from_serial_for_wifi((GList **)&(elem->data), (current + 4), elem->length);
			elem->is_group = true;
		}
		else
		{
			_net_nfc_util_alloc_mem(elem->data, elem->length);
			if (elem->data == NULL)
			{
				_net_nfc_util_free_mem(elem);
				return NET_NFC_ALLOC_FAIL;
			}
			memcpy(elem->data, (current + 4), elem->length);
			elem->is_group = false;
		}
		*list = g_list_append(*list, elem);
		current += (4 + elem->length);
	}

	return NET_NFC_OK;
}

net_nfc_error_e __net_nfc_get_list_from_serial_for_bt(GList **list, uint8_t *data, uint32_t length)
{
	net_nfc_carrier_property_s *elem = NULL;
	uint8_t *current = data;
	uint8_t *last = NULL;

	current += 2; /* remove oob data length  two bytes length*/
	length -= 2;

	_net_nfc_util_alloc_mem(elem, sizeof(net_nfc_carrier_property_s));
	if (elem == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}
	elem->attribute = (uint16_t)NET_NFC_BT_ATTRIBUTE_ADDRESS;
	elem->length = 6; /* BT address length is always 6 */

	_net_nfc_util_alloc_mem(elem->data, elem->length);
	if (elem->data == NULL)
	{
		_net_nfc_util_free_mem(elem);
		return NET_NFC_ALLOC_FAIL;
	}
	memcpy(elem->data, current, elem->length);
	elem->is_group = false;

	current += 6; /* BT address length is always 6 */
	length -= 6; /* substracted by 6 (Address length)*/
	*list = g_list_append(*list, elem);

	last = current + length;

	while (current < last)
	{
		_net_nfc_util_alloc_mem(elem, sizeof(net_nfc_carrier_property_s));
		if (elem == NULL)
		{
			return NET_NFC_ALLOC_FAIL;
		}
		elem->length = *((uint8_t *)current) - 1;
		elem->attribute = *((uint8_t *)(++current));

		_net_nfc_util_alloc_mem(elem->data, elem->length);
		if (elem->data == NULL)
		{
			_net_nfc_util_free_mem(elem);
			return NET_NFC_ALLOC_FAIL;
		}
		memcpy(elem->data, (++current), elem->length);
		elem->is_group = false;

		current += elem->length;
		*list = g_list_append(*list, elem);
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_carrier_config_from_config_record(net_nfc_carrier_config_s **config, ndef_record_s *record)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_conn_handover_carrier_type_e type;

	if (record == NULL || config == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (strncmp((char *)record->type_s.buffer, CONN_HANDOVER_WIFI_BSS_CARRIER_MIME_NAME, record->type_s.length) == 0)
	{
		type = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS;
	}
	else if (strncmp((char *)record->type_s.buffer, CONN_HANDOVER_WIFI_IBSS_CARRIER_MIME_NAME, record->type_s.length) == 0)
	{
		type = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS;
	}
	else if (strncmp((char *)record->type_s.buffer, CONN_HANDOVER_BT_CARRIER_MIME_NAME, record->type_s.length) == 0)
	{
		type = NET_NFC_CONN_HANDOVER_CARRIER_BT;
	}
	else
	{
		DEBUG_MSG("Record type is not config type");
		return NET_NFC_INVALID_FORMAT;
	}

	result = net_nfc_util_create_carrier_config(config, type);
	if (*config == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	switch ((*config)->type)
	{
	case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS :
		case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS :
		result = __net_nfc_get_list_from_serial_for_wifi((GList **)&((*config)->data), record->payload_s.buffer, record->payload_s.length);
		break;
	case NET_NFC_CONN_HANDOVER_CARRIER_BT :
		result = __net_nfc_get_list_from_serial_for_bt((GList **)&((*config)->data), record->payload_s.buffer, record->payload_s.length);
		break;
	case NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN :
		result = NET_NFC_NOT_SUPPORTED;
		break;
	}

	if (result != NET_NFC_OK)
	{
		net_nfc_util_free_carrier_config((net_nfc_carrier_config_s *)*config);
	}

	return result;
}

net_nfc_error_e net_nfc_util_create_handover_request_message(ndef_message_s **message)
{
	ndef_message_s *inner_message = NULL;
	net_nfc_error_e error;
	ndef_record_s *record = NULL;
	data_s type = { NULL, 0 };
	data_s payload = { NULL, 0 };
	int size = 0;

	if (message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	error = net_nfc_util_create_ndef_message(message);
	if (error != NET_NFC_OK)
	{
		return error;
	}

	error = net_nfc_util_create_ndef_message(&inner_message);
	if (error != NET_NFC_OK)
	{
		net_nfc_util_free_ndef_message(*message);
		*message = NULL;

		return error;
	}

	__net_nfc_util_create_connection_handover_collsion_resolution_record(&record);
	net_nfc_util_append_record(inner_message, record);

	size = net_nfc_util_get_ndef_message_length(inner_message) + 1;
	_net_nfc_util_alloc_mem(payload.buffer, size);
	if (payload.buffer == NULL)
	{
		net_nfc_util_free_ndef_message(inner_message);
		net_nfc_util_free_ndef_message(*message);
		*message = NULL;

		return NET_NFC_ALLOC_FAIL;
	}
	payload.length = size;

	uint8_t version = ((CONN_HANOVER_MAJOR_VER << 4) & 0xf0) | (CONN_HANOVER_MINOR_VER & 0x0f);

	(payload.buffer)[0] = version;
	(payload.buffer)++;
	(payload.length)--;

	error = net_nfc_util_convert_ndef_message_to_rawdata(inner_message, &payload);
	if (error != NET_NFC_OK)
	{
		_net_nfc_util_free_mem(payload.buffer);
		net_nfc_util_free_ndef_message(inner_message);
		net_nfc_util_free_ndef_message(*message);
		*message = NULL;

		return error;
	}

	net_nfc_util_free_ndef_message(inner_message);
	(payload.buffer)--;
	(payload.length)++;

	type.buffer = (uint8_t *)CONN_HANDOVER_REQ_RECORD_TYPE;
	type.length = strlen(CONN_HANDOVER_REQ_RECORD_TYPE);

	net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE, &type, NULL, &payload, &record);
	net_nfc_util_append_record(*message, record);

	_net_nfc_util_free_mem(payload.buffer);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_handover_select_message(ndef_message_s **message)
{
	net_nfc_error_e error = NET_NFC_OK;
	ndef_record_s *record = NULL;
	data_s type = { NULL, 0 };
	data_s payload = { NULL, 0 };

	if (message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	error = net_nfc_util_create_ndef_message(message);
	if (error != NET_NFC_OK)
	{
		return error;
	}

	_net_nfc_util_alloc_mem(payload.buffer, 1);
	if (payload.buffer == NULL)
	{
		net_nfc_util_free_ndef_message(*message);
		return NET_NFC_ALLOC_FAIL;
	}
	payload.length = (uint32_t)1;

	(payload.buffer)[0] = ((CONN_HANOVER_MAJOR_VER << 4) & 0xf0) | (CONN_HANOVER_MINOR_VER & 0x0f);

	type.buffer = (uint8_t*)CONN_HANDOVER_SEL_RECORD_TYPE;
	type.length = strlen(CONN_HANDOVER_SEL_RECORD_TYPE);

	net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE, &type, NULL, &payload, &record);
	net_nfc_util_append_record(*message, record);

	_net_nfc_util_free_mem(payload.buffer);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_handover_error_record(ndef_record_s **record, uint8_t reason, uint32_t data)
{
	data_s type;
	data_s payload;
	int size = 1;

	switch (reason)
	{
	case 0x01 :
		size += 1;
		break;
	case 0x02 :
		size += 4;
		break;
	case 0x03 :
		size += 1;
		break;
	}

	_net_nfc_util_alloc_mem(payload.buffer, size);
	if (payload.buffer == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}
	payload.length = size;

	type.buffer = (uint8_t *)ERROR_RECORD_TYPE;
	type.length = strlen(ERROR_RECORD_TYPE);

	net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE, &type, NULL, &payload, (ndef_record_s **)record);

	_net_nfc_util_free_mem(payload.buffer);

	return NET_NFC_OK;
}

/*
 inner_msg should be freed after using
 */

static net_nfc_error_e __net_nfc_get_inner_message(ndef_message_s *message, ndef_message_s *inner_msg)
{
	net_nfc_error_e error;
	ndef_record_s *inner_record = NULL;

	if (message == NULL || inner_msg == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	inner_record = message->records;
	if (inner_record == NULL)
	{
		// This message is not connection handover message
		return NET_NFC_INVALID_FORMAT;
	}

	if (strncmp((char*)(inner_record->type_s.buffer), CONN_HANDOVER_REQ_RECORD_TYPE, (size_t)(inner_record->type_s.length)) != 0
		&& strncmp((char*)(inner_record->type_s.buffer), CONN_HANDOVER_SEL_RECORD_TYPE, (size_t)(inner_record->type_s.length)) != 0)
	{
		// This message is not connection handover message
		return NET_NFC_INVALID_FORMAT;
	}

	if (inner_record->payload_s.length > 1)
	{
		/* There is Alternative Carrier Record or Collision Res. Rec. */
		(inner_record->payload_s.buffer)++; /* version */
		(inner_record->payload_s.length)--;
		error = net_nfc_util_convert_rawdata_to_ndef_message(&(inner_record->payload_s), inner_msg);
		(inner_record->payload_s.buffer)--;
		(inner_record->payload_s.length)++;
	}
	else
	{
		error = NET_NFC_NO_DATA_FOUND;
	}

	return error;
}

static net_nfc_error_e __net_nfc_replace_inner_message(ndef_message_s *message, ndef_message_s *inner_msg)
{
	net_nfc_error_e error;
	ndef_record_s *inner_record = NULL;

	if (message == NULL || inner_msg == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	inner_record = message->records;
	if (inner_record == NULL)
	{
		// This message is not connection handover message
		DEBUG_ERR_MSG("inner_record == NULL");
		return NET_NFC_INVALID_FORMAT;
	}

	if (strncmp((char *)(inner_record->type_s.buffer), CONN_HANDOVER_REQ_RECORD_TYPE, (size_t)(inner_record->type_s.length)) != 0
		&& strncmp((char *)(inner_record->type_s.buffer), CONN_HANDOVER_SEL_RECORD_TYPE, (size_t)(inner_record->type_s.length)) != 0)
	{
		// This message is not connection handover message
		DEBUG_ERR_MSG("unknown type [%s]", inner_record->type_s.buffer);
		return NET_NFC_INVALID_FORMAT;
	}

	if (inner_record->payload_s.length >= 1)
	{
		/* There is Alternative Carrier Record or Collision Res. Rec. */
		data_s tdata = { NULL, 0 };
		int inner_length;

		inner_length = net_nfc_util_get_ndef_message_length(inner_msg);

		_net_nfc_util_alloc_mem(tdata.buffer, inner_length + 1);
		if (tdata.buffer == NULL)
		{
			return NET_NFC_ALLOC_FAIL;
		}

		(tdata.buffer)++;
		tdata.length = inner_length;
		error = net_nfc_util_convert_ndef_message_to_rawdata(inner_msg, &tdata);
		if (error == NET_NFC_OK)
		{
			(tdata.buffer)--;
			(tdata.length)++;
			(tdata.buffer)[0] = (inner_record->payload_s.buffer)[0];
			_net_nfc_util_free_mem(inner_record->payload_s.buffer);
			inner_record->payload_s.buffer = tdata.buffer;
			inner_record->payload_s.length = tdata.length;
		}
		else
		{
			DEBUG_ERR_MSG("net_nfc_util_convert_ndef_message_to_rawdata failed [%d]", error);
			_net_nfc_util_free_mem(tdata.buffer);
		}
	}
	else
	{
		DEBUG_ERR_MSG("inner_record->payload_s.length(%d) < 1 ", inner_record->payload_s.length);
		error = NET_NFC_INVALID_FORMAT;
	}

	return error;
}

net_nfc_error_e net_nfc_util_append_carrier_config_record(ndef_message_s *message, ndef_record_s *record, net_nfc_conn_handover_carrier_state_e power_status)
{
	ndef_message_s *inner_msg = NULL;
	ndef_record_s *carrier_rec = NULL;
	data_s payload = { NULL, 0 };
	data_s type = { NULL, 0 };
	int config_ref_count = 0;
	net_nfc_error_e error;
	char buffer[256] = { 0, };

	if (message == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		int idx = 1;
		ndef_record_s *last_rec = inner_msg->records;

		for (; idx < inner_msg->recordCount; idx++)
		{
			last_rec = last_rec->next;
		}

		if (strncmp((char *)last_rec->type_s.buffer, COLLISION_DETECT_RECORD_TYPE, (size_t)last_rec->type_s.length) == 0)
		{
			config_ref_count = 0;
		}
		else if (strncmp((char *)last_rec->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)last_rec->type_s.length) == 0)
		{
			strncpy(buffer, (char *)((last_rec->payload_s.buffer) + 2), (size_t)(last_rec->payload_s.buffer[1]));
			config_ref_count = atoi(buffer);
		}
	}
	else
	{
		/* selector record type can include empty inner message. so that case, we will continue */
		if (memcmp((char *)message->records->type_s.buffer, CONN_HANDOVER_SEL_RECORD_TYPE, (size_t)message->records->type_s.length) != 0)
		{
			DEBUG_ERR_MSG("ERROR [%d]", error);

			net_nfc_util_free_ndef_message(inner_msg);

			return error;
		}
	}

	type.buffer = (uint8_t *)ALTERNATIVE_RECORD_TYPE;
	type.length = strlen(ALTERNATIVE_RECORD_TYPE);

	config_ref_count++;
	snprintf(buffer, sizeof(buffer), "  %d ", config_ref_count);	/* total size of payload is generally greater than 4. this is a trick :)*/

	payload.length = strlen(buffer);
	payload.buffer = (uint8_t *)buffer;
	payload.buffer[0] = (uint8_t)(power_status & 0x3);	/* first byte, power status */
	payload.buffer[1] = (uint8_t)payload.length - 2;	/* payload length except 2 bytes (power status and itself) */

	error = net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE, &type, NULL, &payload, &carrier_rec);
	if (error != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_create_record failed [%d]", error);

		net_nfc_util_free_ndef_message(inner_msg);

		return error;
	}

	error = net_nfc_util_append_record(inner_msg, carrier_rec);
	if (error != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_create_record failed [%d]", error);

		net_nfc_util_free_record(carrier_rec);
		net_nfc_util_free_ndef_message(inner_msg);

		return error;
	}

	error = __net_nfc_replace_inner_message(message, inner_msg);
	net_nfc_util_free_ndef_message(inner_msg);
	if (error != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("__net_nfc_replace_inner_message failed [%d]", error);

		return error;
	}

	/* set record id to record that will be appended to ndef message */
	error = net_nfc_util_set_record_id((ndef_record_s *)record, (uint8_t *)(buffer + 2), payload.length - 2);
	if (error != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_set_record_id failed [%d]", error);

		return error;
	}

	error = net_nfc_util_append_record(message, (ndef_record_s *)record);
	if (error != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_append_record failed [%d]", error);

		return error;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_carrier_config_record(ndef_message_s *message, ndef_record_s *record)
{
	ndef_message_s *inner_msg = NULL;
	int idx = 0;
	int saved_idx = 0;
	net_nfc_error_e error;
	ndef_record_s *current = NULL;
	ndef_record_s *record_priv = (ndef_record_s *)record;

	if (message == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	current = message->records;

	for (idx = 0; idx < message->recordCount; idx++)
	{
		if (current == record)
		{
			break;
		}
		current = current->next;
	}

	if (current == NULL || idx == message->recordCount)
	{
		DEBUG_MSG("The reference is not found in config records");

		return NET_NFC_NO_DATA_FOUND;
	}
	saved_idx = idx;

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		current = inner_msg->records;

		for (idx = 0; idx < inner_msg->recordCount; idx++, current = current->next)
		{
			if (strncmp((char *)current->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)current->type_s.length) == 0)
			{
				if ((uint32_t)(current->payload_s.buffer[1]) == record_priv->id_s.length &&
					strncmp((char *)(current->payload_s.buffer + 2), (char*)(record_priv->id_s.buffer), (size_t)current->payload_s.buffer[1]) == 0)
				{
					// comparing the instance
					break;
				}
			}
		}

		if (current == NULL || idx == message->recordCount)
		{
			DEBUG_MSG("The reference is not found in inner message");

			error = NET_NFC_NO_DATA_FOUND;
		}
		else
		{
			net_nfc_util_remove_record_by_index(inner_msg, idx);
			__net_nfc_replace_inner_message(message, inner_msg);

			// remove the record only if the inner record is found.
			net_nfc_util_remove_record_by_index(message, saved_idx);
		}
	}

	net_nfc_util_free_ndef_message(inner_msg);

	return error;
}

net_nfc_error_e net_nfc_util_get_carrier_config_record(ndef_message_s *message, int index, ndef_record_s** record)
{
	ndef_message_s *inner_msg = NULL;
	data_s id;
	net_nfc_error_e error;
	ndef_record_s *current = NULL;
	int idx = 0;
	int current_idx = 0;

	if (message == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		current = inner_msg->records;
		for (idx = 0; idx < inner_msg->recordCount; idx++)
		{
			if (strncmp((char*)current->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)current->type_s.length) == 0)
			{
				if (current_idx == index)
					break;
				current_idx++;
			}
			current = current->next;
		}

		if (current == NULL || idx == message->recordCount)
		{
			DEBUG_MSG("The reference is not found in inner message");

			error = NET_NFC_NO_DATA_FOUND;
		}
		else
		{
			id.buffer = (current->payload_s.buffer) + 2;
			id.length = current->payload_s.buffer[1];

			error = net_nfc_util_search_record_by_id(message, &id, record);
		}
	}

	net_nfc_util_free_ndef_message(inner_msg);

	return error;
}

net_nfc_error_e net_nfc_util_get_handover_random_number(ndef_message_s *message, unsigned short *random_number)
{
	net_nfc_error_e error;
	ndef_message_s *inner_msg = NULL;
	ndef_record_s *cr_record = NULL;

	if (message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		cr_record = inner_msg->records;
		if (strncmp((char*)cr_record->type_s.buffer, COLLISION_DETECT_RECORD_TYPE, (size_t)cr_record->type_s.length) != 0
			|| cr_record->payload_s.length < 2)
		{
			DEBUG_MSG("There is no Collision resolution record");

			error = NET_NFC_INVALID_FORMAT;
		}
		else
		{
			*random_number = ((unsigned short)cr_record->payload_s.buffer[0] << 8) | (unsigned short)(cr_record->payload_s.buffer[1]);
		}
	}

	net_nfc_util_free_ndef_message(inner_msg);

	return error;
}

net_nfc_error_e net_nfc_util_get_alternative_carrier_record_count(ndef_message_s *message, unsigned int *count)
{
	net_nfc_error_e error;
	ndef_message_s *inner_msg = NULL;
	ndef_record_s *current = NULL;
	int idx;

	if (message == NULL || count == 0)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	*count = 0;

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		current = inner_msg->records;
		for (idx = 0; idx < inner_msg->recordCount; idx++)
		{
			if (strncmp((char *)current->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)current->type_s.length) == 0)
			{
				(*count)++;
			}
			current = current->next;
		}
	}

	net_nfc_util_free_ndef_message(inner_msg);

	return error;
}

net_nfc_error_e net_nfc_util_get_alternative_carrier_power_status(ndef_message_s *message, int index, net_nfc_conn_handover_carrier_state_e *power_state)
{
	net_nfc_error_e error;
	ndef_message_s *inner_msg = NULL;
	ndef_record_s *current = NULL;
	int idx;
	int idx_count = 0;

	if (message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (index < 0)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		error = NET_NFC_OUT_OF_BOUND;
		current = inner_msg->records;
		for (idx = 0; idx < inner_msg->recordCount; idx++)
		{
			if (strncmp((char *)current->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)current->type_s.length) == 0)
			{
				if (idx_count == index)
				{
					*power_state = current->payload_s.buffer[0] & 0x3;
					error = NET_NFC_OK;
					break;
				}
				idx_count++;
			}
			current = current->next;
		}
	}

	net_nfc_util_free_ndef_message(inner_msg);

	return error;
}

net_nfc_error_e net_nfc_util_set_alternative_carrier_power_status(ndef_message_s *message, int index, net_nfc_conn_handover_carrier_state_e power_status)
{
	net_nfc_error_e error;
	ndef_message_s *inner_msg = NULL;

	if (message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	if (index < 0)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) != NET_NFC_OK)
	{
		DEBUG_MSG("net_nfc_util_create_ndef_message failed [%d]", error);

		return error;
	}

	if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
	{
		int idx;
		int idx_count = 0;
		ndef_record_s *current = inner_msg->records;

		error = NET_NFC_OUT_OF_BOUND;
		for (idx = 0; idx < inner_msg->recordCount; idx++, current = current->next)
		{
			if (strncmp((char *)current->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)current->type_s.length) == 0)
			{
				if (idx_count == index)
				{
					current->payload_s.buffer[0] = (power_status & 0x3) | (current->payload_s.buffer[0] & 0xFC);

					__net_nfc_replace_inner_message(message, inner_msg);
					error = NET_NFC_OK;
					break;
				}
				idx_count++;
			}
		}
	}

	net_nfc_util_free_ndef_message(inner_msg);

	return error;
}

net_nfc_error_e net_nfc_util_get_alternative_carrier_type_from_record(ndef_record_s *record, net_nfc_conn_handover_carrier_type_e *type)
{
	if (strncmp((char *)record->type_s.buffer, CONN_HANDOVER_BT_CARRIER_MIME_NAME, (size_t)record->type_s.length) == 0)
	{
		*type = NET_NFC_CONN_HANDOVER_CARRIER_BT;
	}
	else if (strncmp((char *)record->type_s.buffer, CONN_HANDOVER_WIFI_BSS_CARRIER_MIME_NAME, (size_t)record->type_s.length) == 0)
	{
		*type = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS;
	}
	else if (strncmp((char *)record->type_s.buffer, CONN_HANDOVER_WIFI_IBSS_CARRIER_MIME_NAME, (size_t)record->type_s.length) == 0)
	{
		*type = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS;
	}
	else
	{
		*type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_get_alternative_carrier_type(ndef_message_s *message, int index, net_nfc_conn_handover_carrier_type_e *type)
{
	ndef_record_s *record = NULL;
	net_nfc_error_e error;

	error = net_nfc_util_get_carrier_config_record(message, index, (ndef_record_s **)&record);
	if (error != NET_NFC_OK)
	{
		return error;
	}

	return net_nfc_util_get_alternative_carrier_type_from_record(record, type);
}

net_nfc_error_e net_nfc_util_get_selector_power_status(ndef_message_s *message, net_nfc_conn_handover_carrier_state_e *power_state)
{
	net_nfc_error_e error;
	ndef_message_s *inner_msg = NULL;
	ndef_record_s *current = NULL;
	int idx;
	net_nfc_conn_handover_carrier_state_e selector_state = NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE;

	if (message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if ((error = net_nfc_util_create_ndef_message(&inner_msg)) == NET_NFC_OK)
	{
		if ((error = __net_nfc_get_inner_message(message, inner_msg)) == NET_NFC_OK)
		{
			if (inner_msg->recordCount > 1)
			{
				current = inner_msg->records;
				for (idx = 0; idx < inner_msg->recordCount; idx++)
				{
					if (strncmp((char *)current->type_s.buffer, ALTERNATIVE_RECORD_TYPE, (size_t)current->type_s.length) == 0)
					{
						if (((current->payload_s.buffer[0] & 0x3) == NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE) || ((current->payload_s.buffer[0] & 0x3) == NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING))
						{
							selector_state = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;
							break;
						}
					}
					current = current->next;
				}
			}
			else
			{
				/* always activate when ac is only one */
				selector_state = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;
			}

			*power_state = selector_state;
		}
		else
		{
			DEBUG_ERR_MSG("_net_nfc_util_create_ndef_message failed [%d]", error);
		}

		net_nfc_util_free_ndef_message(inner_msg);
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_util_create_ndef_message failed [%d]", error);
		error = NET_NFC_ALLOC_FAIL;
	}

	return error;
}

