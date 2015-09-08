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

#ifndef __NET_NFC_NDEF_MESSAGE_H__
#define __NET_NFC_NDEF_MESSAGE_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif


/**

@addtogroup NET_NFC_MANAGER_NDEF
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <nfc-manager-def.h>

        @li @c #net_nfc_initialize                  Initialize the nfc device.

*/

/**
	create ndef message handler. this function allocate the ndef message handler and initialize.

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[out]	ndef_message		instance of the ndef_message is retuened

	@return 	return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code

	net_nfc_error_e result = NET_NFC_OK;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;

	result = net_nfc_create_ndef_message (&msg);
	if (result != NET_NFC_OK) return result;

	result = net_nfc_create_uri_type_record (&record , "http://www.samsung.com" ,NET_NFC_SCHEMA_FULL_URI);
	if (result != NET_NFC_OK) return result;

	result = net_nfc_append_record_to_ndef_message (msg ,record);
	if (result != NET_NFC_OK) return result;

	net_nfc_write_ndef(id, msg, &user_context);

	net_nfc_free_ndef_message (msg);

	@endcode
*/


net_nfc_error_e net_nfc_create_ndef_message(ndef_message_h *ndef_message);

/**
	this APIs is the getter of  record counts

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message 	output structure to get the record
	@param[out]	count			number of record count


	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

	@code

	static void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		switch (message)
		{
			case NET_NFC_MESSAGE_READ_NDEF:
				{
					if(data != NULL)
					{
						int count = 0;
						ndef_message_h ndef = (ndef_message_h)(data);
						net_nfc_get_ndef_message_record_count (ndef, &count);
						printf ("record count = %d\n", count);
					}
				}
			break;
		}
	}
	@endcode
*/
net_nfc_error_e net_nfc_get_ndef_message_record_count(ndef_message_h ndef_message, int *count);

/**
	This function converts the NDEF Message structure to serial bytes of ndef message.

	it gets copy of the rawdata bytes from ndef_message. ndef_message has no effect after free rawdata
	Application should free rawdata.

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message 	output structure to get the record
	@param[out]	rawdata			this is the raw data that will be formed into the

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_NDEF_BUF_END_WITHOUT_ME	Wrong formatted NDEF message

	@code

	net_nfc_error_e result = NET_NFC_OK;
	data_h rawdata;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;
	int idx;
	uint8_t * buffer = NULL;

	result = net_nfc_create_ndef_message (&msg);
	if (result != NET_NFC_OK) return result;

	result = net_nfc_create_uri_type_record (&record , "http://www.samsung.com" ,NET_NFC_SCHEMA_FULL_URI);
	if (result != NET_NFC_OK) return result;

	result = net_nfc_append_record_to_ndef_message (msg ,record);
	if (result != NET_NFC_OK) return result;

	net_nfc_create_rawdata_from_ndef_message (msg, &rawdata);

	buffer = net_nfc_get_data_buffer (rawdata) ;

	for (idx = 0; idx < net_nfc_get_data_length (rawdata) ; idx++)
	{
		printf (" %02X", buffer[idx]);
		if (idx % 16 == 0) printf ("\n");
	}

	net_nfc_free_ndef_message (msg);

	@endcode


*/

net_nfc_error_e net_nfc_create_rawdata_from_ndef_message(ndef_message_h ndef_message, data_h *rawdata);

/**
	This function return the structure of ndef_message from serial format of ndef message.
	You may say create ndef handler from raw serial bytes
	it cunsumes the bytes array until get the (ME==1). it retunrs error if the bytes array does not have ME flag.
	if the array has two NDEF Message serially (not recursive case - like smart poster). the first NDEF message
	will be converted to ndef_message handler, and other messages will be ignored.

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[out]	ndef_message		ndef message handler that will be returned
	@param[in]	rawdata 			ndef message that formed in bytes array

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_NDEF_BUF_END_WITHOUT_ME	Wrong formatted NDEF message

	@code

	static void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		switch (message)
		{
			case NET_NFC_MESSAGE_READ_NDEF:
				{
					if(data != NULL)
					{
						record_h record;
						ndef_message_h url;
						data_h ndef_type;
						data_h payload;

						ndef_message_h ndef = (ndef_message_h)(data);
						net_nfc_get_record_by_index (ndef, 0, &record);
						net_nfc_get_record_type (record, &ndef_type);
						if (strncmp (ndef_type.buffer, "Sp", ndef_type.length)){
							net_nfc_get_record_payload (record, &payload);
							net_nfc_create_ndef_message_from_rawdata (&url, payload);
							printf_ndef_massage (url);
						}
					}
				}
			break;
		}
	}
	@endcode

*/


net_nfc_error_e net_nfc_create_ndef_message_from_rawdata(ndef_message_h *ndef_message, data_h rawdata);

/**
	it returns the total size of ndef message bytes. parse the structure data and count the bytes
	to know the length of bytes required to store the NDEF message.

	it calculates the length every time application calls this function. it does not cache inside.
	TODO: do we need to cache the value inside of ndef_message_h

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message		this is the raw data that will be formed into the
	@param[out]	length			number of bytes required to create ndef message serial format

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_get_ndef_message_byte_length(ndef_message_h ndef_message, uint32_t *length);
/**
	Append a record to ndef message structure.
	This API help to create NDEF message and it control Record flags to follow the NDEF forum specification

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message		NDEF message structure
	@param[in]	record 			a record will be added into the ndef message

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

	@code

	net_nfc_error_e result = NET_NFC_OK;
	data_h rawdata;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;
	int idx;
	uint8_t * buffer = NULL;

	result = net_nfc_create_ndef_message (&msg);
	if (result != NET_NFC_OK) return result;

	result = net_nfc_create_uri_type_record (&record , "http://www.samsung.com" ,NET_NFC_SCHEMA_FULL_URI);
	if (result != NET_NFC_OK) return result;

	result = net_nfc_append_record_to_ndef_message (msg ,record);
	if (result != NET_NFC_OK) return result;

	net_nfc_create_rawdata_from_ndef_message (msg, &rawdata);

	buffer = net_nfc_get_data_buffer (rawdata) ;

	for (idx = 0; idx < net_nfc_get_data_length (rawdata) ; idx++)
	{
		printf (" %02X", buffer[idx]);
		if (idx % 16 == 0) printf ("\n");
	}

	net_nfc_free_ndef_message (msg);

	@endcode


*/
net_nfc_error_e net_nfc_append_record_to_ndef_message(ndef_message_h ndef_message, ndef_record_h record);

/**
	remove the record that indicated by index number.
	and this deleted record will be freed.

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message 	the message wil be freed
	@param[in]	index			index of record

	@return 	return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OUT_OF_BOUND			index is out of bound
	@exception NET_NFC_INVALID_FORMAT		Wrong formatted ndef message

*/

net_nfc_error_e net_nfc_remove_record_by_index(ndef_message_h ndef_message, int index);

/**
	get record by index. this function just return the pointer of record.
	if you change the record value it directly affected to NDEF message

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message		the message wil be freed
	@param[in]	index			index of record
	@param[in]	record			record pointer

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OUT_OF_BOUND			index is out of bound

*/
net_nfc_error_e net_nfc_get_record_by_index(ndef_message_h ndef_message, int index, ndef_record_h *record);

/**
	Add a record by index. This API help to add record by index. MB or ME bits will automatically assained.

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message		the message wil be freed
	@param[in]	index			index of record
	@param[in]	record			record pointer

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OUT_OF_BOUND			index is out of bound
	@exception NET_NFC_INVALID_FORMAT		Wrong formatted ndef message
*/

net_nfc_error_e net_nfc_append_record_by_index(ndef_message_h ndef_message, int index, ndef_record_h record);


/**
	search the specific type in the NDEF message. this function return the first record that holds the type.
	if the type has "urn:nfc:wkt:" or "urn:nfc:ext:", these prefix will be removed automatically.

	@param[in]		ndef_message		NDEF message handler
	@param[in]		tnf				TNF value
	@param[in]		type				Record type , include type length
	@param[out]		record			record handle

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_NO_DATA_FOUND			search is failed
	@exception NET_NFC_INVALID_FORMAT		Wrong formatted ndef message

	@code

	static void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		switch (message)
		{
			case NET_NFC_MESSAGE_READ_NDEF:
				{
					if(data != NULL)
					{
						date_h type;
						int count = 0;
						ndef_message_h ndef = (ndef_message_h)(data);
						ndef_record_h record;
						net_nfc_create_data (&type, "Sp", 2);
						net_nfc_search_record_by_type (ndef, NET_NFC_RECORD_WELL_KNOWN_TYPE, type, &record);
					}
				}
			break;
		}
	}

	@endcode

*/
net_nfc_error_e net_nfc_search_record_by_type(ndef_message_h ndef_message, net_nfc_record_tnf_e tnf, data_h type, ndef_record_h *record);


/**
	this function helps to free the ndef_message_s type structure.
	it has multiple ndef_record_s with linked list form and each record has own pointer.
	this function free these memory in one shot!
	don't worry about the record handler. these handlers also freed.

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message		the message wil be freed

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_free_ndef_message(ndef_message_h ndef_message);


/**
	retreive ndef message which is read by nfc-manager .
	after reading message, it will be removed from nfc-manager storage

	\par Sync (or) Async: sync
	This is a Synchronous API

	@param[in]	ndef_message		the message wil be retrieved

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_NO_NDEF_MESSAGE		No ndef message is found
	@exception NET_NFC_INVALID_FORMAT		Wrong formatted ndef message
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

*/

net_nfc_error_e net_nfc_retrieve_current_ndef_message(ndef_message_h *ndef_message);


/**
@} */


#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_NDEF_MESSAGE_H__
