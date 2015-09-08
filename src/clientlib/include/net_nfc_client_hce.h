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

#ifndef __NET_NFC_CLIENT_HCE_H__
#define __NET_NFC_CLIENT_HCE_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*************Hce Callbacks*********/

typedef void (*net_nfc_client_hce_event_cb)(
	net_nfc_target_handle_h handle,
	net_nfc_hce_event_t event,
	data_h apdu,
	void *user_data);

/************* Hce API's*************/

net_nfc_error_e net_nfc_client_hce_set_event_received_cb(
	net_nfc_client_hce_event_cb callback, void *user_data);
net_nfc_error_e net_nfc_client_hce_unset_event_received_cb(void);

net_nfc_error_e net_nfc_client_hce_response_apdu_sync(
	net_nfc_target_handle_h handle, data_h resp_apdu_data);


/* internal */
net_nfc_error_e net_nfc_client_hce_init(void);
void net_nfc_client_hce_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_HCE_H__
