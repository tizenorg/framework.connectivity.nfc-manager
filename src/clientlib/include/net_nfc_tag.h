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


#ifndef __NET_NFC_TAG_H__
#define __NET_NFC_TAG_H__

#include "net_nfc_typedef.h"


#ifdef __cplusplus
 extern "C" {
#endif

/**

@addtogroup NET_NFC_MANAGER_TAG
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <net_nfc_typedef.h>

        @li @c #net_nfc_transceive					provide low level tag access
        @li @c #net_nfc_format_ndef					format to NDEF tag type
        @li @c #net_nfc_read_tag						read ndef message
        @li @c #net_nfc_write_ndef					write ndef message
        @li @c #net_nfc_set_tag_filter					set detection filter .
        @li @c #net_nfc_get_tag_filter					get detection filter
        @li @c #net_nfc_create_transceive_info_only		allocate the transceive info.
        @li @c #net_nfc_create_transceive_info			allocate the transeeive info and set given values
        @li @c #net_nfc_set_transceive_info_command	command setter from transceive info.
        @li @c #net_nfc_set_transceive_info_data		data setter from transceive info.
        @li @c #net_nfc_set_transceive_info_address		address setter from transceive info.
        @li @c #net_nfc_free_transceive_info			free transceive info handler

*/

/**
	transceive function is the only wayt to access the raw format card (not formated),
	each tag type requres own command to access tags,
	this API provide low level access of tag operation and you require the knowlege of each tag technology. <BR>
	To use this API you should create transceive info with "net_nfc_create_transceive_info" API

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle		target ID that has been delivered from callback
	@param[in]	info			trnasceive infomation that has created by "net_nfc_create_transceive_info" API
	@param[in]	trans_param	user data that will be delivered to callback

	@return return the result of the calling this function

	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY				Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_NOT_SUPPORTED	you may recieve this error if you request not supported command
	@exception NET_NFC_INVALID_HANDLE		target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received from tag

	@code

	void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		net_nfc_target_handle_h id;
		bool is_ndef;
		net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

		net_nfc_get_tag_ndef_support (target_info, &is_ndef);
		net_nfc_get_tag_handle (target_info, &id);

		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{
			net_nfc_transceive_info_h trans;
			net_nfc_create_transceive_info (&trans, NET_NFC_EMIFAREREAD, 0x00, NULL);
			net_nfc_transceive (id ,trans , &user_context);
			net_nfc_free_transceive_info (trans);
		}
		break;

		case NET_NFC_MESSAGE_TRANSCEIVE:
			if(result == NET_NFC_OK){
				printf("NET_NFC_MESSAGE_TRANSCEIVE is OK \n");
				if (data != NULL){
					data_h read_data = (data_h) * data;
					int idx;
					uint8_t * buf = net_nfc_get_data_buffer (data_read);
					for (idx = 0; idx < net_nfc_get_data_length (read_data); idx ++){
						printf (" %02X", buf[idx]);
					}
				}
			}
			else{
				printf("NET_NFC_MESSAGE_TRANSCEIVE is failed %d\n", result);
			}
		break;
	}

	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		sleep (100);

		return 0;
	}
	@endcode

*/

net_nfc_error_e net_nfc_transceive (net_nfc_target_handle_h handle, data_h rawdata, void* trans_param);

/**
	This API formats the detected tag that can store NDEF message.
	some tags are required authentication. if the detected target does need authentication, set NULL.

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle		target ID that has been delivered from callback
	@param[in]	key			key value that may need to format the tag
	@param[in]	trans_param	user data that will be delivered to callback

	@return return the result of the calling this function

	@exception NET_NFC_ALLOC_FAIL 	memory allocation is failed
	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_BUSY				Device is too busy to handle your request
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_INVALID_HANDLE		target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received from tag
	@exception NET_NFC_TAG_IS_ALREADY_FORMATTED	requested target is already famatted

	@code

	void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:

		if(data != NULL){
			net_nfc_target_handle_h id;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			net_nfc_get_tag_handle (target_info, &id);

			if (!is_ndef){
				net_nfc_format_ndef (id, NULL, NULL);
			}
		}
		break;

		case NET_NFC_MESSAGE_FORMAT_NDEF:
			printf ("ndef format is completed with %d\n", result);
		break;
	}
	@endcode

*/

net_nfc_error_e net_nfc_format_ndef(net_nfc_target_handle_h handle, data_h key, void* trans_param);



/**
	net_nfc_Ndef_read do read operation with NDEF format
	In the callback function, return value is byte array of the NDEF message.
	it need to convert to NDEF structure

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle		the target ID the connection is already made
	@param[in] 	trans_param	user data

	@return 	return the result of the calling this function

	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_NO_NDEF_SUPPORT	Tag is not support NDEF message
	@exception NET_NFC_ALLOC_FAIL	memory allocation is failed
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_INVALID_HANDLE		target handle is not valid
	@exception NET_NFC_TAG_READ_FAILED	received chunked data is not valied (damaged data is recieved) or error ack is recieved

	@code
	void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		// ......
		switch (message)
		{
			case NET_NFC_MESSAGE_TAG_DISCOVERED:
			{
				if(data != NULL){
					net_nfc_target_handle_h id;
					bool is_ndef;
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

					net_nfc_get_tag_ndef_support (target_info, &is_ndef);
					net_nfc_get_tag_handle (target_info, &id);

					if (is_ndef){
						net_nfc_read_tag (id, &user_context);
					}
				}
			}
			break;

			case NET_NFC_MESSAGE_READ_NDEF:
			{
				if (result != NET_NFC_OK)
				{
					// FAILED read NDEF message
				}
				ndef_message_h ndef_message = (ndef_message_h ) data;
			}
			break;
		}
		return;
	}

	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		sleep (100);

		return 0;
	}
	@endcode

*/


net_nfc_error_e net_nfc_read_tag (net_nfc_target_handle_h handle, void* trans_param);

/**
	net_nfc_Ndef_write do write operation with NDEF format message

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in]	handle		the target Id the connection is already made
	@param[in]	msg			the message will be write to the target
	@param[in] 	trans_param	user data

	@return		return the result of the calling the function

	@exception NET_NFC_NOT_INITIALIZED	Try to operate without initialization
	@exception NET_NFC_NO_NDEF_SUPPORT	Tag is not support NDEF message
	@exception NET_NFC_ALLOC_FAIL	memory allocation is failed
	@exception NET_NFC_BUSY		Device is too busy to handle your request
	@exception NET_NFC_INSUFFICIENT_STORAGE	 Tag does not enough storage to store NDEF message
	@exception NET_NFC_RF_TIMEOUT	Timeout is raised while communicate with tag
	@exception NET_NFC_INVALID_HANDLE		target handle is not valid
	@exception NET_NFC_TAG_WRITE_FAILED	read only tag, or error ack is received from tag


	@code
	void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		// ......
		switch (message)
		{
			case NET_NFC_MESSAGE_TAG_DISCOVERED:
			{
				if(data != NULL){
					net_nfc_target_handle_h id;
					bool is_ndef;
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

					net_nfc_get_tag_ndef_support (target_info, &is_ndef);
					net_nfc_get_tag_handle (target_info, &id);

					if (is_ndef){
						net_nfc_error_e result = NET_NFC_OK;
						ndef_message_h bt_msg = NULL;
						ndef_record_h record = NULL;

						net_nfc_create_ndef_message (&msg);
						net_nfc_create_text_type_record (&record , "Hello NFC World", NET_NFC_LANG_EN_US ,NET_NFC_ENCODE_UTF_8);
						net_nfc_append_record_to_ndef_message (msg ,record);

						net_nfc_write_ndef(id, msg, &user_context);
					}
				}
			}
			break;

			case NET_NFC_MESSAGE_WRITE_NDEF:
			{
				if (result != NET_NFC_OK)
				{
					// FAILED write NDEF message
				}
			}
			break;
		}
		return;
	}

	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		sleep (100);

		return 0;
	}
	@endcode

*/

net_nfc_error_e net_nfc_write_ndef (net_nfc_target_handle_h handle, ndef_message_h msg, void* trans_param);

/**
	this API make a ndef tag read only.

	\par Sync (or) Async: Async
	This is a synchronous API

	@param[in]	handle		the target Id the connection is already made
	@param[in] 	trans_param	user data

	@return		return the result of the calling the function

	@exception NONE

	@code

	@code
	void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		// ......
		switch (message)
		{
			case NET_NFC_MESSAGE_TAG_DISCOVERED:
			{
				if(data != NULL){
					net_nfc_target_handle_h id;
					bool is_ndef;
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

					net_nfc_get_tag_ndef_support (target_info, &is_ndef);
					net_nfc_get_tag_handle (target_info, &id);

					if (is_ndef){

						net_nfc_error_e result = NET_NFC_OK;
						net_nfc_make_read_only_ndef_tag(id, &user_context);
					}
				}
			}
			break;

			case NET_NFC_MESSAGE_MAKE_READ_ONLY_NDEF:
			{
				if (result != NET_NFC_OK)
				{
					// FAILED to make read only ndef tag
				}
			}
			break;
		}
		return;
	}

	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		sleep (100);

		return 0;
	}
	@endcode

*/


net_nfc_error_e net_nfc_make_read_only_ndef_tag(net_nfc_target_handle_h handle, void* trans_param);

/**
	this API help to set filter of target types.
	bit opertor or can be used in the config parameter (like  NET_NFC_ISO14443A_ENABLE | NET_NFC_ISO14443B_ENABLE)
	or you may choose "NET_NFC_ALL_ENABLE" enum value to get all result
	it prevent getting tag types from RF level.
	if the client api does call this function, default is always NET_NFC_ALL_ENABLE.

	\par Sync (or) Async: Sync
	This is a synchronous API

	@param[in]	config		filter value with bits operation

	@return		return the result of the calling the function

	@exception NONE

	@code

	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		net_nfc_event_filter_e filter = NET_NFC_ALL_ENABLE;
		net_nfc_error_e net_nfc_set_tag_filter(filter);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		sleep (100);

		return 0;
	}

	@endcode
*/

net_nfc_error_e net_nfc_set_tag_filter(net_nfc_event_filter_e config);

/**
	get current filter status. The current filter value will return filter you can call this API any time anywhere

	\par Sync (or) Async: Async
	This is a asynchronous API

	@return		return the filter which is set

	@exception NONE

	@code

	net_nfc_event_filter_e config = net_nfc_get_tag_filter();

	@endcode

*/
net_nfc_error_e net_nfc_is_tag_connected(void *trans_param);

/**
	Check a target connected already. (Synchronous function)

	\par Sync (or) Async: Sync
	This is a synchronous API

	@param[out]	dev_type	currently connected device type
	@return					return the filter which is set

	@exception NONE

	@code

	int dev_type = 0;
	net_nfc_error_e result = net_nfc_is_tag_connected_sync(&dev_type);

	@endcode
*/
net_nfc_error_e net_nfc_is_tag_connected_sync(int *dev_type);

net_nfc_event_filter_e net_nfc_get_tag_filter(void);

net_nfc_error_e net_nfc_get_current_tag_info(void* trans_param);
net_nfc_error_e net_nfc_get_current_tag_info_sync(net_nfc_target_info_h *info);

#ifdef __cplusplus
}
#endif


#endif

