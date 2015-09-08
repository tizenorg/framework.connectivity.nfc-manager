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

#ifndef __NET_NFC_CLIENT_TAG_H__
#define __NET_NFC_CLIENT_TAG_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#if 0
typedef void (*net_nfc_client_tag_is_tag_connected_completed)(
						net_nfc_error_e result,
						net_nfc_target_type_e dev_type,
						void *user_data);

typedef void (*net_nfc_client_tag_get_current_tag_info_completed)(
						net_nfc_error_e result,
						net_nfc_target_info_h info,
						void *user_data);

typedef void (*net_nfc_client_tag_get_current_target_handle_completed)(
					net_nfc_error_e result,
					net_nfc_target_handle_h handle,
					void *user_data);
#endif
typedef void (*net_nfc_client_tag_tag_discovered)(net_nfc_target_info_h info,
						void *user_data);

typedef void (*net_nfc_client_tag_tag_detached)(void *user_data);

#if 0
net_nfc_error_e net_nfc_client_tag_is_tag_connected(
			net_nfc_client_tag_is_tag_connected_completed callback,
			void *user_data);

net_nfc_error_e net_nfc_client_tag_get_current_tag_info(
		net_nfc_client_tag_get_current_tag_info_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_tag_get_current_target_handle(
	net_nfc_client_tag_get_current_target_handle_completed callback,
	void *user_data);
#endif
net_nfc_error_e net_nfc_client_tag_is_tag_connected_sync(
					net_nfc_target_type_e *dev_type);

net_nfc_error_e net_nfc_client_tag_get_current_tag_info_sync(
						net_nfc_target_info_h *info);

net_nfc_error_e net_nfc_client_barcode_get_barcode_sync(
						unsigned char **barcode, int* barcode_len);

net_nfc_error_e net_nfc_client_tag_get_current_target_handle_sync(
					net_nfc_target_handle_h *handle);

void net_nfc_client_tag_set_tag_discovered(
			net_nfc_client_tag_tag_discovered callback,
			void *user_data);

void net_nfc_client_tag_unset_tag_discovered(void);

void net_nfc_client_tag_set_tag_detached(
			net_nfc_client_tag_tag_detached callback,
			void *user_data);

void net_nfc_client_tag_unset_tag_detached(void);


/* internal function */
void net_nfc_client_tag_set_filter(net_nfc_event_filter_e filter);

net_nfc_event_filter_e net_nfc_client_tag_get_filter(void);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_tag_init(void);

void net_nfc_client_tag_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_TAG_H__
