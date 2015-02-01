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

#ifndef __NET_NFC_NDEF_RECORD_H__
#define __NET_NFC_NDEF_RECORD_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif


/**

@addtogroup NET_NFC_MANAGER_RECORD
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <nfc-typedef.h>

*/


/**
	This define gives you Message Begin from the flag byte

	@param[in] 	flag		flag that comes from "net_nfc_get_record_flags" function
	@return 		the mb flag

	@exception NONE
*/
uint8_t net_nfc_get_record_mb(uint8_t flag);
/**
	This define gives you Message end from the flag byte

	@param[in] 	flag		flag that comes from "net_nfc_get_record_flags" function
	@return 		the me flag

	@exception NONE
*/
uint8_t net_nfc_get_record_me(uint8_t flag);
/**
	This define gives you Chun Flag  that indicate that either the first record chunk or a middle record chunk of a chunked payload

	@param[in] 	flag		flag that comes from "net_nfc_get_record_flags" function
	@return 		the chunk flag

	@exception NONE
*/
uint8_t net_nfc_get_record_cf(uint8_t flag);
/**
	This define gives you ID length present flag

	@param[in] 	flag		flag that comes from "net_nfc_get_record_flags" function
	@return 		the  il (id length flag) flag

	@exception NONE

*/
uint8_t net_nfc_get_record_il(uint8_t flag);
/**
	This define gives you short record flag. This flag indicates that the payload length filed is a single octet

	@param[in]	flag		flag that comes from "net_nfc_get_record_flags" function
	@return 		the short record flag

	@exception NONE
*/
uint8_t net_nfc_get_record_sr(uint8_t flag);



/**
	creat a record with given parameter value. this function automatically set the NDEF record flags

	@param[out]	record			Record handler
	@param[in]	tnf				record type (TNF value) empty, well known, mime type, URI, external, or unchanged
	@param[in]	typeName 		specify type name ex) Sp, U, or Hr ...
	@param[in]	id 				record id
	@param[in]	payload 			payload of this record

	@return		return the result of the calling the function

	@exception NET_NFC_OUT_OF_BOUND			tnf value is out of range
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code
		char uri[] = " yahoo.com";
		ndef_record_s uriRecord;

		data_h payload;

		net_nfc_create_data (&payload, uri, strlen (uri));
		uri[0] = 0x01;

		if((result = net_nfc_create_record( &uriRecord, NET_NFC_RECORD_WELL_KNOWN_TYPE, "U" , NULL, payload, )) != NET_NFC_OK)
		{
			printf("U record is failed [%d]\n", result);
		}
	@endcode
*/
net_nfc_error_e net_nfc_create_record(ndef_record_h *record, net_nfc_record_tnf_e tnf, data_h typeName, data_h id, data_h payload);


/**
	this function helps to create text type payload
	please, refer the NDEF forum specification "Text Record Type Definition"
	it creates byte array payload can be used in text type record

	this function does not encode the text. The paramter "text" will be asuumed as that it is already encoded with encode type.
	this function  just helps to create text records.

	@param[out]	record				Record handler
	@param[in]	text					encoded text (this should be text not binary)
	@param[in]	language_code_str		language_code_str ex) en-US
	@param[in]	encode				text concoding type such as "utf8"

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed


	@code
		net_nfc_error_e result = NET_NFC_OK;
		ndef_message_h msg = NULL;
		ndef_record_h record = NULL;

		char* message = "Hello, NFC World";

		net_nfc_create_ndef_message (&msg);
		net_nfc_create_text_type_record (&record , message, "en-US", NET_NFC_ENCODE_UTF_8);
		net_nfc_append_record_to_ndef_message (msg ,record);

	@endcode

*/
net_nfc_error_e net_nfc_create_text_type_record(ndef_record_h *record, const char *text, const char *language_code_str, net_nfc_encode_type_e encode);

/**
	this function helps to create URI type payload
	please refer the NFC forum specification "URI Record type Definition"
	it creates byte array payload.

	@param[out]	record				Record handler
	@param[in]	uri					string uri that will be stored in the payload
	@param[in]	protocol_schema		protocol schema that is specified in NFC Forum


	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code
		net_nfc_error_e result = NET_NFC_OK;
		ndef_message_h msg = NULL;
		ndef_record_h record = NULL;

		net_nfc_create_ndef_message (&msg);
		net_nfc_create_uri_type_record (&record ,"http://www.samsung.com" ,NET_NFC_SCHEMA_FULL_URI);
		net_nfc_append_record_to_ndef_message (msg ,record);
	@endcode
*/

net_nfc_error_e net_nfc_create_uri_type_record(ndef_record_h *record, const char *uri, net_nfc_schema_type_e protocol_schema);

/**
	this function is getter of record payload.
	this function gives you  the pointer of pyaload that is contained by record.
	Do not free the payload. it will be freed when the record is freed

	@param[in] 	record 		Record handler
	@param[out] 	payload		data_h type payload pointer (it gives you the pointer of payload; not copied)

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/
net_nfc_error_e net_nfc_get_record_payload(ndef_record_h record, data_h *payload);

/**
	this function is getter of record type.
	this function gives you  the pointer of record type that is contained by record.
	Do not free the type. it will be freed when the record is freed

	@param[in] 	record 		Record handler
	@param[out] 	type			dat_h type pointer (it gives you the pointer of type; not copied)

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/
net_nfc_error_e net_nfc_get_record_type(ndef_record_h record, data_h *type);

/**
	this function is getter of record ID.
	this function gives you  the pointer of ID that is contained by record.
	it may return NULL pointer if the ID is not exist
	Do not free the type. it will be freed when the record is freed.

	@param[in] 	record 		Record handler
	@param[out] 	id			dat_h type ID pointer (it gives you the pointer of payload not copied)

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_get_record_id(ndef_record_h record, data_h *id);

/**
	this function is getter of record TNF value.

	@param[in] 	record 		Record handler
	@param[out] 	tnf			TNF value

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)


*/
net_nfc_error_e net_nfc_get_record_tnf(ndef_record_h record, net_nfc_record_tnf_e *tnf);

/**
	this function is getter of record flags.
	you can get the each flag value by using defines "RECORD_GET_XX"

	@param[in] 	record 		Record handler
	@param[out] 	flag			flag value (it gives you the pointer of payload not copied)

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

	@code

		ndef_record_h	 record;
		uint8_t flag;

		net_nfc_get_record_by_index (msg, 0, &record);
		if (record != NULL){
			net_nfc_get_record_flags (record, &flag);
			printf ("MB:%d, ME:%d, CF:%d, IL:%d, SR:%d\n",
				net_nfc_get_record_mb(flag),
				net_nfc_get_record_me(flag),
				net_nfc_get_record_cf(flag),
				net_nfc_get_record_il(flag),
				net_nfc_get_record_sr(flag));
		}

	@endcode

*/
net_nfc_error_e net_nfc_get_record_flags(ndef_record_h record, uint8_t *flag);


/**
	you can set record ID with this function

	@param[in] 	record 		Record handler
	@param[in]	id			Record ID

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/
net_nfc_error_e net_nfc_set_record_id(ndef_record_h record, data_h id);

/**
	this function free the record handler. do not use this function after appending the ndef message

	@param[in] 	record 		Record handler

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/
net_nfc_error_e net_nfc_free_record(ndef_record_h record);


/**
	this function get text from text record. it allocate buffer char and store the text string. you should free this string.

	@param[in] 	record 		Record handler
	@param[out] 	buffer 		text string

	@return		return the result of the calling the function

	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE		record is not text record
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_create_text_string_from_text_record(ndef_record_h record, char **buffer);

/**
	this function get language code from text record. (ex: US-en)

	@param[in] 	record 			Record handler
	@param[out] 	lang_code_str 	lang code string value followed by IANA

	@return		return the result of the calling the function

	@exception NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE		record is not text record
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_get_languange_code_string_from_text_record(ndef_record_h record, char **lang_code_str);


/**
	this function get encoding type from text record (ex: UTF-8)

	@param[in] 	record 		Record handler
	@param[out] 	encoding 	encoding type

	@return		return the result of the calling the function

	@exception NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE		record is not text record
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_get_encoding_type_from_text_record(ndef_record_h record, net_nfc_encode_type_e *encoding);


/**
	this function get URI from uri record. you should free the uri string.

	@param[in] 	record 		Record handler
	@param[out] 	uri 			uri text string

	@return		return the result of the calling the function

	@exception NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE		record is not uri record
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_create_uri_string_from_uri_record(ndef_record_h record, char **uri);

#ifdef __cplusplus
}
#endif


#endif //__NET_NFC_NDEF_RECORD_H__
