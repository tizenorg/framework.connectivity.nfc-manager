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


#ifndef __SLP_NET_NFC_EXCHANGER_H__
#define __SLP_NET_NFC_EXCHANGER_H__


#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
@addtogroup NET_NFC_MANAGER_EXCHANGE
@{

*/


/**
	create net_nfc_exchagner raw type data handler with given values

	@param[out]	ex_data 		exchangner handler
	@param[in]	payload		the data will be deliver (NDEF message)

	@return 		result of this function call

	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
*/
net_nfc_error_e net_nfc_create_exchanger_data(net_nfc_exchanger_data_h *ex_data, data_h payload);

/**
	this makes free exchagner data handler

	@param[in]	ex_data 		exchagner handler

	@return 		result of this function call

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/

net_nfc_error_e net_nfc_free_exchanger_data (net_nfc_exchanger_data_h ex_data);


net_nfc_error_e net_nfc_send_exchanger_data (net_nfc_exchanger_data_h ex_handle, net_nfc_target_handle_h target_handle, void* trans_param);

/**
	request connection handover with discovered P2P device

	@param[in]	target_handle 		target device handle
	@param[in]	type 		specific alternative carrier type (if type is NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN, it will be selected available type of this target)
	@param[in] 	trans_param	user data

	@return 		result of this function call

	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_exchanger_request_connection_handover(net_nfc_target_handle_h target_handle, net_nfc_conn_handover_carrier_type_e type);

/**
	get alternative carrier type from connection handover information handle.

	@param[in] 	info_handle		connection handover information handle
	@param[out] 	type	alternative carrier type

	@return 	return the result of this operation

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_exchanger_get_alternative_carrier_type(net_nfc_connection_handover_info_h info_handle, net_nfc_conn_handover_carrier_type_e *type);

/**
	get alternative carrier dependant data from connection handover information handle.
	Bluetooth : target device address
	Wifi : target device ip address

	@param[in] 	info_handle		connection handover information handle
	@param[out] 	data	alternative carrier data

	@return 	return the result of this operation

	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_exchanger_get_alternative_carrier_data(net_nfc_connection_handover_info_h info_handle, data_h *data);

/**
	this makes free alternative carrier data handler

	@param[in]	info_handle 		alternative carrier data handler

	@return 		result of this function call

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_exchanger_free_alternative_carrier_data(net_nfc_connection_handover_info_h  info_handle);


/**
@}

*/


#ifdef __cplusplus
}
#endif


#endif
