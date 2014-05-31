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


#ifndef __NET_NFC_UTIL_HANDOVER__
#define __NET_NFC_UTIL_HANDOVER__

#include "net_nfc_typedef_private.h"

#ifdef __cplusplus
extern "C"
{
#endif

net_nfc_error_e net_nfc_util_create_carrier_config(net_nfc_carrier_config_s **config, net_nfc_conn_handover_carrier_type_e type);

net_nfc_error_e net_nfc_util_add_carrier_config_property(net_nfc_carrier_config_s *config, uint16_t attribute, uint16_t size, uint8_t *data);

net_nfc_error_e net_nfc_util_remove_carrier_config_property(net_nfc_carrier_config_s *config, uint16_t attribute);

net_nfc_error_e net_nfc_util_get_carrier_config_property(net_nfc_carrier_config_s *config, uint16_t attribute, uint16_t *size, uint8_t **data);

net_nfc_error_e net_nfc_util_append_carrier_config_group(net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group);

net_nfc_error_e net_nfc_util_remove_carrier_config_group(net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group);

net_nfc_error_e net_nfc_util_get_carrier_config_group(net_nfc_carrier_config_s *config, int index, net_nfc_carrier_property_s **group);

net_nfc_error_e net_nfc_util_free_carrier_config(net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_util_create_carrier_config_group(net_nfc_carrier_property_s **group, uint16_t attribute);

net_nfc_error_e net_nfc_util_add_carrier_config_group_property(net_nfc_carrier_property_s *group, uint16_t attribute, uint16_t size, uint8_t *data);

net_nfc_error_e net_nfc_util_get_carrier_config_group_property(net_nfc_carrier_property_s *group, uint16_t attribute, uint16_t *size, uint8_t **data);

net_nfc_error_e net_nfc_util_remove_carrier_config_group_property(net_nfc_carrier_property_s *group, uint16_t attribute);

net_nfc_error_e net_nfc_util_free_carrier_group(net_nfc_carrier_property_s *group);

net_nfc_error_e net_nfc_util_create_ndef_record_with_carrier_config(ndef_record_s **record, net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_util_create_carrier_config_from_config_record(net_nfc_carrier_config_s **config, ndef_record_s *record);

net_nfc_error_e net_nfc_util_append_carrier_config_record(ndef_message_s *message, ndef_record_s *record, net_nfc_conn_handover_carrier_state_e power_status);

net_nfc_error_e net_nfc_util_remove_carrier_config_record(ndef_message_s *message, ndef_record_s *record);

net_nfc_error_e net_nfc_util_get_carrier_config_record(ndef_message_s *message, int index, ndef_record_s **record);

net_nfc_error_e net_nfc_util_get_handover_random_number(ndef_message_s *message, unsigned short *random_number);

net_nfc_error_e net_nfc_util_get_alternative_carrier_record_count(ndef_message_s *message, unsigned int *count);

net_nfc_error_e net_nfc_util_get_alternative_carrier_power_status(ndef_message_s *message, int index, net_nfc_conn_handover_carrier_state_e *power_state);

net_nfc_error_e net_nfc_util_set_alternative_carrier_power_status(ndef_message_s *message, int index, net_nfc_conn_handover_carrier_state_e power_status);

net_nfc_error_e net_nfc_util_get_alternative_carrier_type_from_record(ndef_record_s *record, net_nfc_conn_handover_carrier_type_e *type);

/**
 this function will get carrier type.

 @param[in] 	carrier_info 			connection handover carrier info handler
 @param[in] 	carrier_type 			record type. it can be a NET_NFC_CONN_HANDOVER_CARRIER_BT or NET_NFC_CONN_HANDOVER_CARRIER_WIFI or NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN.

 @return		return the result of the calling the function

 @exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
 */
net_nfc_error_e net_nfc_util_get_alternative_carrier_type(ndef_message_s *message, int index, net_nfc_conn_handover_carrier_type_e *power_state);

net_nfc_error_e net_nfc_util_create_handover_request_message(ndef_message_s **message);

net_nfc_error_e net_nfc_util_create_handover_select_message(ndef_message_s **message);

net_nfc_error_e net_nfc_util_create_handover_error_record(ndef_record_s **record, uint8_t reason, uint32_t data);

net_nfc_error_e net_nfc_util_get_selector_power_status(ndef_message_s *message, net_nfc_conn_handover_carrier_state_e *power_state);

#ifdef __cplusplus
}
#endif

#endif
