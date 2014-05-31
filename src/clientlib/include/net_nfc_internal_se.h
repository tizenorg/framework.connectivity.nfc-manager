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

#ifndef __NET_NFC_INTERNAL_SE_H__
#define __NET_NFC_INTERNAL_SE_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**

@addtogroup NET_NFC_MANAGER_SECURE_ELEMENT
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <net_nfc_typedef.h>

        @li @c #net_nfc_set_secure_element_type			set secure element type
        @li @c #net_nfc_get_secure_element_type			get current selected secure element
        @li @c #net_nfc_open_internal_secure_element		open selected secure element
        @li @c #net_nfc_open_internal_secure_element_sync	open selected secure element (synchronous)
        @li @c #net_nfc_close_internal_secure_element		close selected secure element
        @li @c #net_nfc_close_internal_secure_element_sync	close selected secure element (synchronous)
        @li @c #net_nfc_send_apdu				send apdu to opened secure element
        @li @c #net_nfc_send_apdu_sync				send apdu to opened secure element (synchronous)
        @li @c #net_nfc_get_atr					request atr of secure element
        @li @c #net_nfc_get_atr_sync				request atr of secure element (synchronous)
*/

/**
	set secure element type. secure element will be a UICC or ESE.
	only one secure element is selected in a time.
	external reader can communicate with secure element by emitting RF

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	se_type			secure element type
	@param[in]	trans_param		user data that will be delivered to callback

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	not supported se_type
*/
net_nfc_error_e net_nfc_set_secure_element_type(net_nfc_se_type_e se_type, void *trans_param);

/**
	get current select se type.

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in]	trans_param		user data that will be delivered to callback

	@return		return the result of the calling the function
*/
net_nfc_error_e net_nfc_get_secure_element_type(void *trans_param);

/**
	open and initialize the type of secure element.
	if the type of secure element is selected, then change mode as MODE OFF
	to prevent to be detected by external reader

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	se_type			secure element type
	@param[in]	trans_param		user data that will be delivered to callback

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	not supported se_type
*/
net_nfc_error_e net_nfc_open_internal_secure_element(net_nfc_se_type_e se_type, void *trans_param);

/**
	open and initialize the type of secure element.
	if the type of secure element is selected, then change mode as MODE OFF
	to prevent to be detected by external reader

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	se_type			secure element type
	@param[out]	handle			the handle of opened secure element

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	not supported se_type
*/
net_nfc_error_e net_nfc_open_internal_secure_element_sync(net_nfc_se_type_e se_type, net_nfc_target_handle_h *handle);

/**
	close opened secure element and change back to previous setting

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle			the handle of opened secure element
	@param[in]	trans_param		user data that will be delivered to callback

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid secure element handle
*/
net_nfc_error_e net_nfc_close_internal_secure_element(net_nfc_target_handle_h handle, void *trans_param);

/**
	close opened secure element and change back to previous setting

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle			the handle of opened secure element

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid secure element handle
*/
net_nfc_error_e net_nfc_close_internal_secure_element_sync(net_nfc_target_handle_h handle);

/**
	send apdu to opened secure element

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle			the handle of opened secure element
	@param[in] 	apdu			apdu command to send
	@param[in]	trans_param		user data that will be delivered to callback

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid secure element handle
	@exception NET_NFC_NULL_PARAM 		data is null or empty
*/
net_nfc_error_e net_nfc_send_apdu(net_nfc_target_handle_h handle, data_h apdu, void *trans_param);

/**
	send apdu to opened secure element

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle			the handle of opened secure element
	@param[in] 	apdu			apdu command to send
	@param[out]	response		result of apdu

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid secure element handle or parameter
	@exception NET_NFC_NULL_PARAM 		data is null or empty
*/
net_nfc_error_e net_nfc_send_apdu_sync(net_nfc_target_handle_h handle, data_h apdu, data_h *response);

/**
	request atr of secure element

	\par Sync (or) Async: Async
	This is a Asynchronous API

	@param[in] 	handle			the handle of opened secure element
	@param[in]	trans_param		user data that will be delivered to callback

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid

*/
net_nfc_error_e net_nfc_get_atr(net_nfc_target_handle_h handle, void *trans_param);

/**
	request atr of secure element

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@param[in] 	handle			the handle of opened secure element
	@param[out]	atr			Answer to reset of secure element

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid

*/
net_nfc_error_e net_nfc_get_atr_sync(net_nfc_target_handle_h handle, data_h *atr);

/**
	set card emulation mode of secure element

	\par Sync (or) Async: Sync
	This is a Synchronous API

	@param[in]   se_mode		the mode of card emulation

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid

*/
net_nfc_error_e net_nfc_set_card_emulation_mode_sync(net_nfc_card_emulation_mode_t se_mode);


/**
	set type of secure element

	\par Sync (or) Async: Sync
	This is a Synchronous API

	@param[in]   se_type		the type of secure element

	@return		return the result of the calling the function

	@exception NET_NFC_INVALID_PARAM 	invalid

*/
net_nfc_error_e net_nfc_set_secure_element_type_sync(net_nfc_se_type_e se_type);

#ifdef __cplusplus
}
#endif


#endif

