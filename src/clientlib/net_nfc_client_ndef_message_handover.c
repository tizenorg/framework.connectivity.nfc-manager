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

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_handover.h"
#include "net_nfc_ndef_message_handover.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_carrier_config(net_nfc_carrier_config_h *config,
	net_nfc_conn_handover_carrier_type_e type)
{
	return net_nfc_util_create_carrier_config(
		(net_nfc_carrier_config_s **)config, type);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_add_carrier_config_property(
	net_nfc_carrier_config_h config, uint16_t attribute, uint16_t size,
	uint8_t * data)
{
	return net_nfc_util_add_carrier_config_property(
		(net_nfc_carrier_config_s *)config, attribute, size, data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_remove_carrier_config_property(
	net_nfc_carrier_config_h config, uint16_t attribute)
{
	return net_nfc_util_remove_carrier_config_property(
		(net_nfc_carrier_config_s *)config, attribute);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_carrier_config_property(
	net_nfc_carrier_config_h config, uint16_t attribute,
	uint16_t *size, uint8_t **data)
{
	return net_nfc_util_get_carrier_config_property(
		(net_nfc_carrier_config_s *)config, attribute, size, data);
}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_append_carrier_config_group(
	net_nfc_carrier_config_h config, net_nfc_property_group_h group)
{
	return net_nfc_util_append_carrier_config_group(
		(net_nfc_carrier_config_s *)config,
		(net_nfc_carrier_property_s *)group);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_remove_carrier_config_group(
	net_nfc_carrier_config_h config, net_nfc_property_group_h group)
{
	return net_nfc_util_remove_carrier_config_group(
		(net_nfc_carrier_config_s *)config,
		(net_nfc_carrier_property_s *)group);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_carrier_config_group(
	net_nfc_carrier_config_h config, uint16_t attribute,
	net_nfc_property_group_h *group)
{
	return net_nfc_util_get_carrier_config_group(
		(net_nfc_carrier_config_s *)config, attribute,
		(net_nfc_carrier_property_s **)group);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_free_carrier_config(net_nfc_carrier_config_h config)
{
	return net_nfc_util_free_carrier_config(
		(net_nfc_carrier_config_s *)config);
}



NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_carrier_config_group(
	net_nfc_property_group_h *group, uint16_t attribute)
{
	return net_nfc_util_create_carrier_config_group(
		(net_nfc_carrier_property_s **)group, attribute);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_add_carrier_config_group_property(
	net_nfc_property_group_h group, uint16_t attribute, uint16_t size,
	uint8_t *data)
{
	return net_nfc_util_add_carrier_config_group_property(
		(net_nfc_carrier_property_s *)group, attribute, size, data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_carrier_config_group_property(
	net_nfc_property_group_h group, uint16_t attribute, uint16_t *size,
	uint8_t **data)
{
	return net_nfc_util_get_carrier_config_group_property(
		(net_nfc_carrier_property_s *)group, attribute, size, data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_remove_carrier_config_group_property(
	net_nfc_property_group_h group, uint16_t attribute)
{
	return net_nfc_util_remove_carrier_config_group_property(
		(net_nfc_carrier_property_s *)group, attribute);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_free_carrier_group(net_nfc_property_group_h group)
{
	return net_nfc_util_free_carrier_group(
		(net_nfc_carrier_property_s *)group);
}



NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_ndef_record_with_carrier_config(
	ndef_record_h *record, net_nfc_carrier_config_h config)
{
	return net_nfc_util_create_ndef_record_with_carrier_config(
		(ndef_record_s**)record, (net_nfc_carrier_config_s *)config);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_carrier_config_from_config_record(
	net_nfc_carrier_config_h *config, ndef_record_h record)
{
	return net_nfc_util_create_carrier_config_from_config_record(
		(net_nfc_carrier_config_s **)config, (ndef_record_s *)record);

}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_carrier_config_from_carrier(
	net_nfc_carrier_config_h *config, net_nfc_ch_carrier_h carrier)
{
	return net_nfc_util_create_carrier_config_from_carrier(
		(net_nfc_carrier_config_s **)config, (net_nfc_ch_carrier_s *)carrier);

}


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_handover_carrier(net_nfc_ch_carrier_h *carrier,
	net_nfc_conn_handover_carrier_state_e cps)
{
	return net_nfc_util_create_handover_carrier(
		(net_nfc_ch_carrier_s **)carrier, cps);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_duplicate_handover_carrier(net_nfc_ch_carrier_h *dest,
	net_nfc_ch_carrier_h src)
{
	return net_nfc_util_duplicate_handover_carrier(
		(net_nfc_ch_carrier_s **)dest,
		(net_nfc_ch_carrier_s *)src);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_free_handover_carrier(net_nfc_ch_carrier_h carrier)
{
	return net_nfc_util_free_handover_carrier(
		(net_nfc_ch_carrier_s *)carrier);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_set_handover_carrier_cps(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_state_e cps)
{
	return net_nfc_util_set_handover_carrier_cps(
		(net_nfc_ch_carrier_s *)carrier, cps);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_carrier_cps(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_state_e *cps)
{
	return net_nfc_util_get_handover_carrier_cps(
		(net_nfc_ch_carrier_s *)carrier, cps);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_set_handover_carrier_type(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_type_e type)
{
	return net_nfc_util_set_handover_carrier_type(
		(net_nfc_ch_carrier_s *)carrier, type);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_carrier_type(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_type_e *type)
{
	return net_nfc_util_get_handover_carrier_type(
		(net_nfc_ch_carrier_s *)carrier, type);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_append_handover_carrier_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h record)
{
	return net_nfc_util_append_handover_carrier_record(
		(net_nfc_ch_carrier_s *)carrier, (ndef_record_s *)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_carrier_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h *record)
{
	return net_nfc_util_get_handover_carrier_record(
		(net_nfc_ch_carrier_s *)carrier, (ndef_record_s **)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_remove_handover_carrier_record(
	net_nfc_ch_carrier_h carrier)
{
	return net_nfc_util_remove_handover_carrier_record(
		(net_nfc_ch_carrier_s *)carrier);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_append_handover_auxiliary_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h record)
{
	return net_nfc_util_append_handover_auxiliary_record(
		(net_nfc_ch_carrier_s *)carrier, (ndef_record_s *)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_auxiliary_record_count(
	net_nfc_ch_carrier_h carrier, uint32_t *count)
{
	return net_nfc_util_get_handover_auxiliary_record_count(
		(net_nfc_ch_carrier_s *)carrier, count);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_auxiliary_record(
	net_nfc_ch_carrier_h carrier, int index, ndef_record_h *record)
{
	return net_nfc_util_get_handover_auxiliary_record(
		(net_nfc_ch_carrier_s *)carrier, index, (ndef_record_s **)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_remove_handover_auxiliary_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h record)
{
	return net_nfc_util_remove_handover_auxiliary_record(
		(net_nfc_ch_carrier_s *)carrier, (ndef_record_s *)record);
}



NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_handover_message(
	net_nfc_ch_message_h *message)
{
	return net_nfc_util_create_handover_message(
		(net_nfc_ch_message_s **)message);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_free_handover_message(
	net_nfc_ch_message_h message)
{
	return net_nfc_util_free_handover_message(
		(net_nfc_ch_message_s *)message);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_random_number(
	net_nfc_ch_message_h message, uint16_t *random_number)
{
	return net_nfc_util_get_handover_random_number(
		(net_nfc_ch_message_s *)message, random_number);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_append_handover_carrier(
	net_nfc_ch_message_h message, net_nfc_ch_carrier_h carrier)
{
	return net_nfc_util_append_handover_carrier(
		(net_nfc_ch_message_s *)message,
		(net_nfc_ch_carrier_s *)carrier);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_carrier_count(
	net_nfc_ch_message_h message, uint32_t *count)
{
	return net_nfc_util_get_handover_carrier_count(
		(net_nfc_ch_message_s *)message, count);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_carrier(
	net_nfc_ch_message_h message, int index,
	net_nfc_ch_carrier_h *carrier)
{
	return net_nfc_util_get_handover_carrier(
		(net_nfc_ch_message_s *)message, index,
		(net_nfc_ch_carrier_s **)carrier);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_handover_carrier_by_type(
	net_nfc_ch_message_h message,
	net_nfc_conn_handover_carrier_type_e type,
	net_nfc_ch_carrier_h *carrier)
{
	return net_nfc_util_get_handover_carrier_by_type(
		(net_nfc_ch_message_s *)message, type,
		(net_nfc_ch_carrier_s **)carrier);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_export_handover_to_ndef_message(
	net_nfc_ch_message_h message, ndef_message_h *result)
{
	return net_nfc_util_export_handover_to_ndef_message(
		(net_nfc_ch_message_s *)message, (ndef_message_s **)result);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_import_handover_from_ndef_message(
	ndef_message_h msg, net_nfc_ch_message_h *result)
{
	return net_nfc_util_import_handover_from_ndef_message(
		(ndef_message_s *)msg, (net_nfc_ch_message_s **)result);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_handover_error_record(ndef_record_h *record, uint8_t reason, uint32_t data)
{
	return net_nfc_util_create_handover_error_record((ndef_record_s **)record, reason, data);
}
