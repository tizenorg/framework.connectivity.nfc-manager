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
#ifndef __NET_NFC_NDEF_MESSAGE_HANDOVER_H__
#define __NET_NFC_NDEF_MESSAGE_HANDOVER_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
	This function create carrier configure handler instance.

	@param[out] 	config 			instance handler
	@param[in] 	type 			Carrier types. It would be BT or WPS or etc.

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_OUT_OF_BOUND			type value is not enum value
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
*/
net_nfc_error_e net_nfc_create_carrier_config(net_nfc_carrier_config_h *config, net_nfc_conn_handover_carrier_type_e type);

/**
	Add property key and value for configuration.
	the data will be copied to config handle, you should free used data array.

	@param[in]	config			instance handler
	@param[in]	attribute		attribute key for value.
	@param[in]	size			size of value
	@param[in]	data			value array (binary type)

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
*/
net_nfc_error_e net_nfc_add_carrier_config_property(net_nfc_carrier_config_h config, uint16_t attribute, uint16_t size, uint8_t *data);

/**
	Remove the key and value from configuration, you can also remove the group with CREDENTIAL key.
	The the attribute is exist then it will be removed and also freed automatically.

	@param[in]	config			instance handler
	@param[in]	attribute		attribute key for value.

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_NO_DATA_FOUND		the given key is not found
	@exception NET_NFC_ALREADY_REGISTERED		the given attribute is already registered
*/
net_nfc_error_e net_nfc_remove_carrier_config_property(net_nfc_carrier_config_h config, uint16_t attribute);

/**
	Get the property value by attribute.

	@param[in]	config			instance handler
	@param[in]	attribute		attribute key for value.
	@param[out]	size			size of value
	@param[out]	data			value array (binary type)

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_NO_DATA_FOUND		The given key is not found
*/
net_nfc_error_e net_nfc_get_carrier_config_property(net_nfc_carrier_config_h config, uint16_t attribute, uint16_t *size, uint8_t **data);

/**
	The group will be joined into the configure

	@param[in]	config			instance handler
	@param[in]	group			group handle

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALREADY_REGISTERED		The given group is already registered
*/
net_nfc_error_e net_nfc_append_carrier_config_group(net_nfc_carrier_config_h config, net_nfc_property_group_h group);

/**
	Remove the group from configure handle

	@param[in]	config			instance handler
	@param[in]	group			group handle

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_NO_DATA_FOUND		given handle pointer is not exist in the configure handle
*/
net_nfc_error_e net_nfc_remove_carrier_config_group(net_nfc_carrier_config_h config, net_nfc_property_group_h group);

/**
	Get the group from configure handle by index

	@param[in]	config			instance handler
	@param[in]	attribute		group attribute
	@param[out]	group			group handle

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_OUT_OF_BOUND			the index number is not bound of the max count
	@exception NET_NFC_NO_DATA_FOUND		this is should be happened if the configure handle is damaged
*/
net_nfc_error_e net_nfc_get_carrier_config_group(net_nfc_carrier_config_h config, uint16_t attribute, net_nfc_property_group_h *group);

/**
	free the configure handle

	@param[in] 	config 			instance handler

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
*/
net_nfc_error_e net_nfc_free_carrier_config(net_nfc_carrier_config_h config);

/**
	create the group handle

	@param[out]	group			instance group handler
	@param[in]	attribute		attribute of the property

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
*/
net_nfc_error_e net_nfc_create_carrier_config_group(net_nfc_property_group_h *group, uint16_t attribute);

/**
	add property into the group

	@param[in]	group			instance group handler
	@param[in]	attribute		attribute of the property
	@param[in]	size			size of data (value)
	@param[in]	data			data of the property

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
	@exception NET_NFC_ALREADY_REGISTERED		the given key is already registered
*/
net_nfc_error_e net_nfc_add_carrier_config_group_property(net_nfc_property_group_h group, uint16_t attribute, uint16_t size, uint8_t *data);

/**
	get property from group handle

	@param[in]	group		instance group handler
	@param[in]	attribute	attribute of the property
	@param[out]	size		size of data (value)
	@param[out]	data		data of the property

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
  	@exception NET_NFC_NO_DATA_FOUND		the attribute does not exist in the group
*/
net_nfc_error_e net_nfc_get_carrier_config_group_property(net_nfc_property_group_h group, uint16_t attribute, uint16_t *size, uint8_t **data);

/**
	remove the property from the group

	@param[in]	group		instance group handler
	@param[in]	attribute	attribute of the property

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
  	@exception NET_NFC_NO_DATA_FOUND		the attribute does not exist in the group
*/
net_nfc_error_e net_nfc_remove_carrier_config_group_property(net_nfc_property_group_h group, uint16_t attribute);


/**
	free the group

	@param[in]	group		instance group handler

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
*/
net_nfc_error_e net_nfc_free_carrier_group(net_nfc_property_group_h group);

/**
	Create record handler with config.

	@param[out]	record		record handler
	@param[in]	config		the carrier configure handle

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
*/
net_nfc_error_e net_nfc_create_ndef_record_with_carrier_config(ndef_record_h *record, net_nfc_carrier_config_h config);


/**
	create configure from the ndef record. the record must contained the configuration.
	config should be freed after using

	@param[out]	config		the configure handle
	@param[in]	record		record handler

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
	@exception NET_NFC_INVALID_FORMAT		if the record does not contained the valid format.
*/
net_nfc_error_e net_nfc_create_carrier_config_from_config_record(net_nfc_carrier_config_h *config, ndef_record_h record);

net_nfc_error_e net_nfc_create_carrier_config_from_carrier(
	net_nfc_carrier_config_h *config, net_nfc_ch_carrier_h carrier);

net_nfc_error_e net_nfc_create_handover_carrier(net_nfc_ch_carrier_h *carrier,
	net_nfc_conn_handover_carrier_state_e cps);

net_nfc_error_e net_nfc_duplicate_handover_carrier(net_nfc_ch_carrier_h *dest,
	net_nfc_ch_carrier_h src);

net_nfc_error_e net_nfc_free_handover_carrier(net_nfc_ch_carrier_h carrier);

net_nfc_error_e net_nfc_set_handover_carrier_cps(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_state_e cps);

net_nfc_error_e net_nfc_get_handover_carrier_cps(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_state_e *cps);

net_nfc_error_e net_nfc_set_handover_carrier_type(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_type_e type);

net_nfc_error_e net_nfc_get_handover_carrier_type(
	net_nfc_ch_carrier_h carrier,
	net_nfc_conn_handover_carrier_type_e *type);

net_nfc_error_e net_nfc_append_handover_carrier_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h record);

net_nfc_error_e net_nfc_get_handover_carrier_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h *record);

net_nfc_error_e net_nfc_remove_handover_carrier_record(
	net_nfc_ch_carrier_h carrier);

net_nfc_error_e net_nfc_append_handover_auxiliary_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h record);

net_nfc_error_e net_nfc_get_handover_auxiliary_record_count(
	net_nfc_ch_carrier_h carrier, uint32_t *count);

net_nfc_error_e net_nfc_get_handover_auxiliary_record(
	net_nfc_ch_carrier_h carrier, int index, ndef_record_h *record);

net_nfc_error_e net_nfc_remove_handover_auxiliary_record(
	net_nfc_ch_carrier_h carrier, ndef_record_h record);


net_nfc_error_e net_nfc_create_handover_message(net_nfc_ch_message_h *message);

net_nfc_error_e net_nfc_free_handover_message(net_nfc_ch_message_h message);

net_nfc_error_e net_nfc_get_handover_random_number(net_nfc_ch_message_h message,
	uint16_t *random_number);

net_nfc_error_e net_nfc_append_handover_carrier(net_nfc_ch_message_h message,
	net_nfc_ch_carrier_h carrier);

net_nfc_error_e net_nfc_get_handover_carrier_count(net_nfc_ch_message_h message,
	uint32_t *count);

net_nfc_error_e net_nfc_get_handover_carrier(net_nfc_ch_message_h message,
	int index, net_nfc_ch_carrier_h *carrier);

net_nfc_error_e net_nfc_get_handover_carrier_by_type(
	net_nfc_ch_message_h message,
	net_nfc_conn_handover_carrier_type_e type,
	net_nfc_ch_carrier_h *carrier);

net_nfc_error_e net_nfc_export_handover_to_ndef_message(
	net_nfc_ch_message_h message, ndef_message_h *result);

net_nfc_error_e net_nfc_import_handover_from_ndef_message(
	ndef_message_h msg, net_nfc_ch_message_h *result);

/**
	create the connection handover error record message

	@param[out]	record			connection handover carrier info handler
	@param[in]	reason			error codes (reason)
	@param[in]	data			extra data for each error codes

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			allocation is failed
*/
net_nfc_error_e net_nfc_create_handover_error_record(ndef_record_h * record, uint8_t reason, uint32_t data);


#ifdef __cplusplus
}
#endif


#endif //__NET_NFC_NDEF_MESSAGE_HANDOVER_H__
