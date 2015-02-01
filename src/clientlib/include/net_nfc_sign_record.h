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
#ifndef __NET_NFC_SIGN_RECORD_H__
#define __NET_NFC_SIGN_RECORD_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C"
{
#endif


/**

@addtogroup NET_NFC_MANAGER_RECORD
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <nfc-typedef.h>

*/

/**
	this function make the signature of some continuous records
	please refer the NFC forum specification "Signature Record type Definition"

	@param[in/out]	msg					NDEF message handler. After executing this function, a signature record will be added.
	@param[in]		begin_index			the index of beginning record that will be signed.
	@param[in]		end_index			the last index of record that will be signed.
	@param[in]		cert_file			PKCS #12 type certificate file (.p12). And the file should be encoded in DER type. (NOT PEM type)
	@param[in]		passowrd			the password of cert_file

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code
		ndef_message_h msg = NULL;

		// create a ndef message and add some records
		// ...

		net_nfc_sign_records(msg, 0, 1, "/tmp/cert.p12", "abcdef");
	@endcode
*/
net_nfc_error_e net_nfc_sign_records(ndef_message_h msg, int begin_index, int end_index, char *cert_file, char *password);

/**
	this function make the signature of whole records in NDEF message

	@param[in/out]	msg					NDEF message handler. After executing this function, a signature record will be added.
	@param[in]		cert_file			PKCS #12 type certificate file (.p12). And the file should be encoded in DER type. (NOT PEM type)
	@param[in]		passowrd			the password of cert_file

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code
		ndef_message_h msg = NULL;

		// create a ndef message and add some records
		// ...

		net_nfc_sign_ndef_message(msg, "/tmp/cert.p12", "abcdef");
	@endcode
*/
net_nfc_error_e net_nfc_sign_ndef_message(ndef_message_h msg, char *cert_file, char *password);

/**
	This function does verify signature of records
	record MUST be continuous.

	@param[in]	begin_record				the handle of beginning record that will be verified
	@param[in]	sign_record					the handle of signature record

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code
		net_nfc_error_e error = NET_NFC_OK;
		ndef_message_h msg = NULL;
		ndef_record_h begin_record = NULL;
		ndef_record_h sign_record = NULL;

		// import NDEF message including the signature record.
		// ...

		net_nfc_get_record_by_index(msg, 0, &begin_record);
		net_nfc_get_record_by_index(msg, 2, &sign_record);

		error = net_nfc_verify_signature_records(begin_record, sign_record);

		return (error == NET_NFC_OK);
	@endcode
*/
net_nfc_error_e net_nfc_verify_signature_records(ndef_record_h begin_record, ndef_record_h sign_record);

/**
	This function does verify signature in NDEF message
	If message has 2 or more signature record, it should do verify every signatures and return result.
	(Despite of failing only one signature record, this function will return error.)

	@param[in]	msg				NDEF message that will be verified.

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illegal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed

	@code
		net_nfc_error_e error = NET_NFC_OK;
		ndef_message_h msg = NULL;

		// import NDEF message including the signature record.
		// ...

		error = net_nfc_verify_signature_ndef_message(msg);

		return (error == NET_NFC_OK);
	@endcode
*/
net_nfc_error_e net_nfc_verify_signature_ndef_message(ndef_message_h msg);

#ifdef __cplusplus
}
#endif


#endif //__NET_NFC_SIGN_RECORD_H__
