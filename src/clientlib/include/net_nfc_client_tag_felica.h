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
#ifndef __NET_NFC_CLIENT_TAG_FELICA_H__
#define __NET_NFC_CLIENT_TAG_FELICA_H__

#include "net_nfc_typedef.h"
#include "net_nfc_client_transceive.h"

#ifdef __cplusplus
extern "C" {
#endif

/**

@addtogroup NET_NFC_MANAGER_TAG
@{

	send poll request to felica tag.
	Use this command to acquire and identify a card. Acqusition of IDm and PMm is possible with this command.
	By specifying a request code , you can acquire system code or communication performance of the system.
	By specifying a time slot, you can designate the maximum number of time slots possible to return response.

	NET_NFC_FELICA_POLL_NO_REQUEST = 0x00
	NET_NFC_FELICA_POLL_SYSTEM_CODE_REQUEST = 0x01
	NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST= 0x02

	time slot

	Time slot		Max number of slots
	0x00,		1
	0x01,		2
	0x03,		4
	0x07,		8
	0x0f,		16

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	req_code		request code with this command
	@param[in] 	time_slot		time slot value

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (SYSTEM_CODE, etc) is not founded

*/

net_nfc_error_e net_nfc_client_felica_poll(net_nfc_target_handle_h handle,
					net_nfc_felica_poll_request_code_e req_code,
					uint8_t time_slote,
					nfc_transceive_data_callback callback,
					void *user_data);

/**
	Use this command to check for the existence of Area / Service specified by Area Code / Service Code
	If the specified Area / Service exists, the card returns version information of the key known as "Key Version" (2 Bytes)
	If the specified Area / Service does not exist, the card returns 0xffff as it s Key Version

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle						target handle of detected tag
	@param[in] 	number_of_area_service		the number of specified Area / Service list
	@param[in] 	area_service_list				specified Area / Service list

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (IDm, etc) is not founded
	@exception NET_NFC_OUT_OF_BOUND		the length of IDm is not correct. number of services exceed max value

*/

net_nfc_error_e net_nfc_client_felica_request_service(
					net_nfc_target_handle_h handle,
					uint8_t number_of_area_service,
					uint16_t area_service_list[],
					uint8_t number_of_services,
					nfc_transceive_data_callback callback,
					void *user_data);

/**
	Use this command to check whether a card exist
	the Current mode of the card is returned.

	Mode

	0x00	Mode0
	0x01	Mode1
	0x02	Mode2
	0x03	Mode3

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle						target handle of detected tag

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (IDm, etc) is not founded
	@exception NET_NFC_OUT_OF_BOUND		the length of IDm is not correct

*/

net_nfc_error_e net_nfc_client_felica_request_response(
					net_nfc_target_handle_h handle,
					nfc_transceive_data_callback callback,
					void *user_data);

/**
	Use this command to read block data from a Service that requires no authentification

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle					target handle of detected tag
	@param[in] 	number_of_service			the number of service list to read
	@param[in] 	service_list				specified Service list to read
	@param[in] 	number_of_blocks			the number of blocks to read
	@param[in] 	block_list					the blocks to read

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (IDm, etc) is not founded
	@exception NET_NFC_OUT_OF_BOUND		the length of IDm is not correct

*/

net_nfc_error_e net_nfc_client_felica_read_without_encryption(
					net_nfc_target_handle_h handle,
					uint8_t number_of_services,
					uint16_t service_list[],
					uint8_t number_of_blocks,
					uint8_t block_list[],
					nfc_transceive_data_callback callback,
					void *user_data);

/**
	Use this command to write block data to a Service that requires no authentification

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle					target handle of detected tag
	@param[in] 	number_of_service			the number of service list to write
	@param[in] 	service_list				specified Service list to write
	@param[in] 	number_of_blocks			the number of blocks to write
	@param[in] 	block_list					the blocks to write
	@param[in] 	data						the data to write

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (IDm, etc) is not founded
	@exception NET_NFC_OUT_OF_BOUND		the length of IDm is not correct. number of services exceed max value, the data length to write is exceed the limitation. It should be less than number_of_blocks * 16 bytes

*/

net_nfc_error_e net_nfc_client_felica_write_without_encryption(
					net_nfc_target_handle_h handle,
					uint8_t number_of_services,
					uint16_t service_list[],
					uint8_t number_of_blocks,
					uint8_t block_list[],
					data_h data,
					nfc_transceive_data_callback callback,
					void *user_data);

/**
	Use this command to acquire system code of the system located on a card
	If a card is divided into mutiple system, this command acquires system code of all the system existing in the card

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle					target handle of detected tag

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (IDm, etc) is not founded
	@exception NET_NFC_OUT_OF_BOUND		the length of IDm is not correct.

*/

net_nfc_error_e net_nfc_client_felica_request_system_code(
					net_nfc_target_handle_h handle,
					nfc_transceive_data_callback callback,
					void* trans_param);

/**
@}
*/


#ifdef __cplusplus
}
#endif


#endif //__NET_NFC_CLIENT_TAG_FELICA_H__
