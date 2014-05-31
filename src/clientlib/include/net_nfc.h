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


/**
  NFC Manager
  NFC Manager controls the nfc device with high level APIs such as SmartPoster and Connection handover.
  It also support the JSR257 push handling.
  this file is provide the APIs of NFC Manager

  @file		net_nfc.h
  modified by:
                        Sechang Sohn (sc.sohn@samsung.com)
			Sangsoo Lee (constant.lee@samsung.com)
			Sungjae Lim (neueziel.lim@samsung.com)
                        Junyong Sim (junyong.sim@samsung.com)
                        Wonkyu Kwon (wonkyu.kwon@samsung.com)
  @version		0.1
  @brief  	This file provide the APIs of the NFC Manager
 */


#ifndef __NET_NFC_INTERFACE_H__
#define __NET_NFC_INTERFACE_H__

#include <net_nfc_typedef.h>
#include <net_nfc_tag.h>
#include <net_nfc_tag_jewel.h>
#include <net_nfc_tag_mifare.h>
#include <net_nfc_tag_felica.h>
#include <net_nfc_llcp.h>
#include <net_nfc_target_info.h>
#include <net_nfc_ndef_message.h>
#include <net_nfc_ndef_record.h>
#include <net_nfc_data.h>
#include <net_nfc_ndef_message_handover.h>
#include <net_nfc_internal_se.h>
#include <net_nfc_test.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NET_NFC_SERVICE_EMPTY_TYPE      "http://tizen.org/appcontrol/operation/nfc/empty"
#define NET_NFC_SERVICE_WELL_KNOWN_TYPE "http://tizen.org/appcontrol/operation/nfc/wellknown"
#define NET_NFC_SERVICE_EXTERNAL_TYPE   "http://tizen.org/appcontrol/operation/nfc/external"
#define NET_NFC_SERVICE_MIME_TYPE       "http://tizen.org/appcontrol/operation/nfc/mime"
#define NET_NFC_SERVICE_URI_TYPE        "http://tizen.org/appcontrol/operation/nfc/uri"

/**

@addtogroup NET_NFC_MANAGER_API
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <net_nfc_typedef.h>

        @li @c #net_nfc_initialize					Initialize the nfc-manager
        @li @c #net_nfc_deinitialize				deinitialize the nfc-manager
        @li @c #net_nfc_set_response_callback		register callback function for async response and detection events
        @li @c #net_nfc_unset_response_callback	unregister callback

*/

/**
	"net_nfc_intialize" initializes NFC Manager.
	This function must be called before proceed any function of NFC Manager excepting net_nfc_set_exchanger_cb.
	Internally it make socket connection to NFC-Manager.
	When the client process crashed or exit without the deinit. nfc-manager
	auto matically process deinit itself.

	In running time, application can have a only one functionality of nfc client and nfc exchanger listener
	Both can not be co-existed. So, If application want to be a exchanger listener, then do not call net_nfc_initialize. if net_nfc_initialize is called before,
	net_nfc_deintialize SHOULD be called  first, and then net_nfc_set_exchange_cb will be available.

	\par Sync (or) Async: Sync
	This is a Synchronous API

	@return		return the result of calling this functions

	@exception 	NET_NFC_ALREADY_INITIALIZED	already initialized
	@exception	NET_NFC_IPC_FAIL		communication to server is failed
	@exception 	NET_NFC_ALLOC_FAIL	memory allocation failed
	@exception	NET_NFC_THREAD_CREATE_FAIL	failed to create thread for main event delivery
	@exception	NET_NFC_NOT_ALLOWED_OPERATION exchanger_cb is already register.

	<br>

	example codes
	@code
	int main ()
	{
		net_nfc_error_e result;
		result = net_nfc_initialize();
		if (result != NET_NFC_OK) {
			printf ("initialize error: %d\n", result);
		}

		return 0;
	}
	@endcode

*/
net_nfc_error_e net_nfc_initialize(void);

/**
	the net_nfc_deinitialize function free the all the resource of the NFC Manager and
	disconnect session of connection from application to the Manager.

	\par Sync (or) Async: Sync
	This is a Asynchronous API

	@return 	return the result of the calling this function

	sample codes
	@code

	@exception NONE

	int main (void)
	{
		if(NET_NFC_OK != net_nfc_initialize()){
			// intialize is failed
			return 1;
		}

        if(net_nfc_deinitialize() == NET_NFC_OK){
			// deinitialize is success
		}

		return 0;
	}

	@endcode

*/
net_nfc_error_e net_nfc_deinitialize(void);

/**
	You should register callback before calling the asyn functions.
	All of result comes from callback function, such as data of read operation,
	Target infomation and the event of async operation completions.
	you can replace callback or user_parameter any time by calling this function.
	callback resgister's user_parameter is used only if the event does not have owner.
	most of event gerenrated by calling async APIs, but detection event, detatch
	event, and etc does not have event owner. These events return the user_param
	in the callback function
	if you call this function when the callback function is already registered, it replaces
	the new callback and user_param.

	@param[in]	cb			callback function
	@param[in]	user_param	userdata that will be delivered when the event does not have owner

	@return 	return the result of the calling this function

	@code
	void net_nfc_cb(net_nfc_message_e message, net_nfc_error_e result, void* data , void* userContext)
	{
		switch(message)
		{
			......
			default:
				break;
		}
	}

	@exception 	NET_NFC_NULL_PARAMETER 	Null parameter is received

	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		return 0;
	}

	@endcode

*/
net_nfc_error_e net_nfc_set_response_callback(net_nfc_response_cb cb, void *user_param);

/**
	this function unregsiters the callback function.

	@return 	return the result of the calling this function

	@exception NET_NFC_NOT_REGISTERED	unset is requested but the callback was not registered before

	@code
	int main()
	{

		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		result = net_nfc_set_response_callback (net_nfc_cb, &user_context2);
		check_result(result);

		net_nfc_unset_response_callback ();
		return 0;
	}
	@endcode
*/
net_nfc_error_e net_nfc_unset_response_callback(void);

/**
	this function enables/disables the app select popup.
	If you use this function to block popup, you should allow that when your app is closed.

	@param[in]	enable			enable or disable

	@return 	return the result of the calling this function

	@code
	int main()
	{
		net_nfc_error_e result;
		result = net_nfc_initialize();
		check_result(result);

		// block app launch popup
		result = net_nfc_set_launch_popup_state(FALSE);
		check_result(result);

		// allow app launch popup
		result = net_nfc_set_launch_popup_state(TRUE);
		check_result(result);

		return 0;
	}
	@endcode
*/
net_nfc_error_e net_nfc_set_launch_popup_state(int enable);

/**
	this function get state of the app select popup.
	If you use this function to block popup, you should allow that when your app is closed.

	@return true on enabled, otherwise false.

	@code
	int main()
	{
		return net_nfc_get_launch_popup_state();
	}
	@endcode
*/
net_nfc_error_e net_nfc_get_launch_popup_state(int *state);


/**
	this function on/off the nfc module.

	@param[in]	state			nfc on or off

	@return 	return the result of the calling this function

	@code
	int main()
	{
		net_nfc_error_e result;

		// nfc module on
		result = net_nfc_set_state(TRUE);
		check_result(result);

		result = net_nfc_initialize();
		check_result(result);

		// do something

		result = net_nfc_deinitialize();
		check_result(result);

		// nfc module off
		result = net_nfc_set_state(FALSE);
		check_result(result);

		return 0;
	}
	@endcode
*/
net_nfc_error_e net_nfc_set_state(int state, net_nfc_set_activation_completed_cb callback);

/**
	this function returns the nfc module state.

	@param[out]	state			nfc on or off

	@return 	return the result of the calling this function

	@code
	int main()
	{
		net_nfc_error_e result;
		int state;

		result = net_nfc_get_state(&state);
		check_result(result);

		if (state == FALSE)
		{
			// nfc module on
			result = net_nfc_set_state(TRUE);
			check_result(result);
		}

		result = net_nfc_initialize();
		check_result(result);

		return 0;
	}
	@endcode
*/
net_nfc_error_e net_nfc_get_state(int *state);

/**
	this function returns the nfc supported or not.

	@param[out]	state			nfc on or off

	@return 	return the result of the calling this function

	@code
	int main()
	{
		net_nfc_error_e result;
		int state;

		result = net_nfc_is_supported(&state);
		check_result(result);

		if (state == FALSE)
		{
			// nfc module on
			result = net_nfc_is_supported(TRUE);
			check_result(result);
		}


		return 0;
	}
	@endcode
*/
net_nfc_error_e net_nfc_is_supported(int *state);


/* THIS API is temp for multiple client */

net_nfc_error_e net_nfc_state_activate(void);
net_nfc_error_e net_nfc_state_deactivate(void);

/**
@} */

#ifdef __cplusplus
}
#endif


#endif

