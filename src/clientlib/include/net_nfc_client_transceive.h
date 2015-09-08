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

#ifndef __NET_NFC_CLIENT_TRANSCEIVE_H__
#define __NET_NFC_CLIENT_TRANSCEIVE_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*nfc_transceive_callback)(net_nfc_error_e result,
					void *user_data);

typedef void (*nfc_transceive_data_callback)(net_nfc_error_e result,
					data_h data,
					void *user_data);

net_nfc_error_e net_nfc_client_transceive(net_nfc_target_handle_h handle,
					data_h rawdata,
					nfc_transceive_callback callback,
					void *user_data);

net_nfc_error_e net_nfc_client_transceive_data(net_nfc_target_handle_h handle,
					data_h rawdata,
					nfc_transceive_data_callback callback,
					void *user_data);

net_nfc_error_e net_nfc_client_transceive_sync(net_nfc_target_handle_h handle,
					data_h rawdata);

net_nfc_error_e net_nfc_client_transceive_data_sync(
						net_nfc_target_handle_h handle,
						data_h rawdata,
						data_h *response);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_transceive_init(void);

void net_nfc_client_transceive_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_TRANSCEIVE_H__
