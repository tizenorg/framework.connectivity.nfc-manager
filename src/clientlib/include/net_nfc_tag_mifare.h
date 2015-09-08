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
#ifndef __NET_NFC_TAG_MIFARE_H__
#define __NET_NFC_TAG_MIFARE_H__

#include "net_nfc_typedef.h"


#ifdef __cplusplus
extern "C" {
#endif

/**

@addtogroup NET_NFC_MANAGER_TAG
@{
	Authenticate a sector with key A. I/O operation. e.g. read / write /
	increment / decrement will be available after successful authentication.
	This API is only available for MIFARE classic

	MIFARE CLASSIC MINI
		=> 0 ~ 4 : 5 sector and 4 block with 16 bytes

	MIFARE CLASSIC 1K
		=> 0 ~ 15 : 16 sector and 4 block with 16 bytes

	MIFARE CLASSIC 4K
		=> 0 ~ 31 : 32 sector and 4 block with 16 bytes
		=> 32 ~ 39 : 8 sector and 16 block with 16 bytes

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	sector		sector to authenticate with key A
	@param[in] 	auth_key	6 byte key to authenticate the sector

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (UID, etc) is not
						founded

*/

net_nfc_error_e net_nfc_client_mifare_authenticate_with_keyA(
						net_nfc_target_handle_h handle,
						uint8_t sector,
						data_h auth_key,
						void *callback,
						void *user_data);

/**
	Authenticate a sector with key B. I/O operation. e.g. read / write /
	increment / decrement will be available after successful authentication.
	This API is only available for MIFARE classic

	MIFARE CLASSIC MINI
		=> 0 ~ 4 : 5 sector and 4 block with 16 bytes

	MIFARE CLASSIC 1K
		=> 0 ~ 15 : 16 sector and 4 block with 16 bytes

	MIFARE CLASSIC 4K
		=> 0 ~ 31 : 32 sector and 4 block with 16 bytes
		=> 32 ~ 39 : 8 sector and 16 block with 16 bytes

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	sector		sector to authenticate with key B
	@param[in] 	auth_key	6 byte key to authenticate the sector

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_NO_DATA_FOUND	mendantory tag info (UID, etc) is not
						founded

*/


net_nfc_error_e net_nfc_client_mifare_authenticate_with_keyB(
						net_nfc_target_handle_h handle,
						uint8_t sector,
						data_h auth_key,
						void *callback,
						void *user_data);

/**
	read block or read page. If detected card is MIFARE classic, then It will
	read a block (16 byte). If detected card is Ultra light, then It will read
	4 page (16 block)

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block or starting page number

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied
						(damaged data is recieved) or error ack
						is recieved

*/

net_nfc_error_e net_nfc_client_mifare_read(net_nfc_target_handle_h handle,
					uint8_t addr,
					void *callback,
					void *user_data);

/**
	write block (16 byte) to addr. Only 4 bytes will be written when tag is
	ultra light

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block or starting page number
	@param[in] 	data		data to write

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received
						from tag

*/


net_nfc_error_e net_nfc_client_mifare_write_block(
						net_nfc_target_handle_h handle,
						uint8_t addr,
						data_h data,
						void *callback,
						void *user_data);

/**
	write page (4 byte) to addr. Only 4 bytes will be written when tag is
	MIFARE classic

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block or starting page number
	@param[in] 	data		data to write

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is
						received from tag

*/

net_nfc_error_e net_nfc_client_mifare_write_page(
						net_nfc_target_handle_h handle,
						uint8_t addr,
						data_h data,
						void *callback,
						void *user_data);


/**
	Increase a value block, storing the result in the temporary block on the
	tag
	This API is only available for MIFARE classic

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block
	@param[in] 	value		index of block to increase, starting from 0

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received
						from tag

*/

net_nfc_error_e net_nfc_client_mifare_increment(net_nfc_target_handle_h handle,
						uint8_t addr,
						int value,
						void *callback,
						void *user_data);

/**
	Decrease a value block, storing the result in the temporary block on the
	tag
	This API is only available for MIFARE classic

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block
	@param[in] 	value		index of block to decrease, starting from 0

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received
						from tag

*/

net_nfc_error_e net_nfc_client_mifare_decrement(net_nfc_target_handle_h handle,
						uint8_t addr,
						int value,
						void *callback,
						void *user_data);

/**
	Copy from the temporary block to a value block.
	This API is only available for MIFARE classic

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block
	@param[in] 	value		index of block to decrease, starting from 0

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received
						from tag

*/

net_nfc_error_e net_nfc_client_mifare_transfer(net_nfc_target_handle_h handle,
					uint8_t addr,
					void *callback,
					void *user_data);

/**
	Copy from a value block to the temporary block.
	This API is only available for MIFARE classic

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle		target handle of detected tag
	@param[in] 	addr		block
	@param[in] 	value		index of block to decrease, starting from 0

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter has illigal NULL pointer
	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the
						internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you
						request not supported command
	@exception NET_NFC_INVALID_HANDLE	target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received
						from tag

*/

net_nfc_error_e net_nfc_client_mifare_restore(net_nfc_target_handle_h handle,
					uint8_t addr,
					void *callback,
					void *user_data);

/**
	create default factory key. The key is 0xff, 0xff, 0xff, 0xff, 0xff, 0xff

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	key			the handle to create key

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

*/

net_nfc_error_e net_nfc_client_mifare_create_default_key(data_h* key);

/**
	create mifare application directory key. The key is 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	key			the handle to create key

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

*/

net_nfc_error_e net_nfc_client_mifare_create_application_directory_key(
								data_h* key);

/**
	create nfc forum key. The key is 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	key			the handle to create key

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

*/

net_nfc_error_e net_nfc_client_mifare_create_net_nfc_forum_key(data_h* key);

/**
@} */

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_TAG_MIFARE_H__
