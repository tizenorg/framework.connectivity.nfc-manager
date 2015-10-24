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

#ifndef __NET_NFC_CLIENT_SE_H__
#define __NET_NFC_CLIENT_SE_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/*************Secure Element Callbacks*********/
typedef void (*net_nfc_se_set_se_cb)(
	net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_se_get_se_cb)(
	net_nfc_error_e result,
	net_nfc_se_type_e se_type,
	void *user_data);

typedef void (*net_nfc_se_set_card_emulation_cb)(
	net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_se_open_se_cb)(
	net_nfc_error_e result,
	net_nfc_target_handle_h handle,
	void *user_data);

typedef void (*net_nfc_se_close_se_cb)(
	net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_se_get_atr_cb)(
	net_nfc_error_e result,
	data_h data,
	void *user_data);

typedef void (*net_nfc_se_send_apdu_cb)(
	net_nfc_error_e result,
	data_h data,
	void *user_data);

typedef void (*net_nfc_client_se_event)(
	net_nfc_message_e event,
	void *user_data);

typedef void (*net_nfc_client_se_transaction_event)(
					net_nfc_se_type_e se_type,
					data_h aid,
					data_h param,
					void *user_data);

typedef void (*net_nfc_client_se_ese_detected_event)(
					net_nfc_target_handle_h handle,
					int dev_type,
					data_h data,
					void *user_data);

typedef bool (*net_nfc_client_se_registered_aid_cb)(net_nfc_se_type_e se_type,
	const char *aid, bool readonly, void *user_data);

typedef bool (*net_nfc_client_se_registered_handler_cb)(const char *package,
	void *user_data);

/************* Secure Element API's*************/

net_nfc_error_e net_nfc_client_se_set_secure_element_type(
					net_nfc_se_type_e se_type,
					net_nfc_se_set_se_cb callback,
					void *user_data);


net_nfc_error_e net_nfc_client_se_set_secure_element_type_sync(
					net_nfc_se_type_e se_type);

net_nfc_error_e net_nfc_client_se_get_secure_element_type_sync(
	net_nfc_se_type_e *se_type);

net_nfc_error_e net_nfc_set_card_emulation_mode_sync(
	net_nfc_card_emulation_mode_t mode);

net_nfc_error_e net_nfc_get_card_emulation_mode_sync(
	net_nfc_card_emulation_mode_t *se_type);

net_nfc_error_e net_nfc_client_se_open_internal_secure_element(
					net_nfc_se_type_e se_type,
					net_nfc_se_open_se_cb callback,
					void *user_data);


net_nfc_error_e net_nfc_client_se_open_internal_secure_element_sync(
					net_nfc_se_type_e se_type,
					net_nfc_target_handle_h *handle);


net_nfc_error_e net_nfc_client_se_close_internal_secure_element(
					net_nfc_target_handle_h handle,
					net_nfc_se_close_se_cb callback,
					void *user_data);


net_nfc_error_e net_nfc_client_se_close_internal_secure_element_sync(
					net_nfc_target_handle_h handle);


net_nfc_error_e net_nfc_client_se_get_atr(
				net_nfc_target_handle_h handle,
				net_nfc_se_get_atr_cb callback,
				void *user_data);


net_nfc_error_e net_nfc_client_se_get_atr_sync(
				net_nfc_target_handle_h handle,
				data_h *atr);


net_nfc_error_e net_nfc_client_se_send_apdu(
				net_nfc_target_handle_h handle,
				data_h apdu_data,
				net_nfc_se_send_apdu_cb callback,
				void *user_data);


net_nfc_error_e net_nfc_client_se_send_apdu_sync(
				net_nfc_target_handle_h handle,
				data_h apdu_data,
				data_h *response);


/************* Secure Element CallBack Register/Deregister functions*************/

void net_nfc_client_se_set_ese_detection_cb(
			net_nfc_client_se_ese_detected_event callback,
			void *user_data);

void net_nfc_client_se_unset_ese_detection_cb(void);

void net_nfc_client_se_set_transaction_event_cb(
			net_nfc_se_type_e se_type,
			net_nfc_client_se_transaction_event callback,
			void *user_data);

void net_nfc_client_se_unset_transaction_event_cb(net_nfc_se_type_e type);

void net_nfc_client_se_set_event_cb(net_nfc_client_se_event callback,
				void *user_data);

void net_nfc_client_se_unset_event_cb(void);

net_nfc_error_e net_nfc_client_se_set_transaction_fg_dispatch(int mode);


/* new card emulation */
net_nfc_error_e net_nfc_client_se_is_activated_aid_handler_sync(
	net_nfc_se_type_e se_type, const char *aid, bool *activated);

net_nfc_error_e net_nfc_client_se_is_activated_category_handler_sync(
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, bool *activated);

net_nfc_error_e net_nfc_client_se_get_registered_aids_count_sync(
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	size_t *count);

net_nfc_error_e net_nfc_client_se_foreach_registered_aids_sync(
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	net_nfc_client_se_registered_aid_cb callback,
	void *user_data);

net_nfc_error_e net_nfc_client_se_register_aids_sync(net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid, ...);
net_nfc_error_e net_nfc_client_se_unregister_aid_sync(net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid);
net_nfc_error_e net_nfc_client_se_unregister_aids_sync(net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category);


net_nfc_error_e net_nfc_client_se_set_default_route_sync(
	net_nfc_se_type_e switch_on, net_nfc_se_type_e switch_off,
	net_nfc_se_type_e battery_off);

/* internal */
net_nfc_error_e net_nfc_client_se_add_route_aid_sync(
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid,
	bool unlock_required, int power);

net_nfc_error_e net_nfc_client_se_remove_route_aid_sync(
	const char *package, const char *aid);

net_nfc_error_e net_nfc_client_se_remove_package_aids_sync(
	const char *package);

net_nfc_error_e net_nfc_client_se_foreach_registered_handlers_sync(
	net_nfc_card_emulation_category_t category,
	net_nfc_client_se_registered_handler_cb callback,
	void *user_data);

//net_nfc_error_e net_nfc_client_hce_get_route_table_sync(data_h arg_aid);


/* TODO : move to internal header */
/************* Secure Element Init/Deint*************/

net_nfc_error_e net_nfc_client_se_init(void);

void net_nfc_client_se_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_SE_H__
