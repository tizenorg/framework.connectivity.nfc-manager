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

#ifndef NET_NFC_SERVICE_SE_PRIVATE_H
#define NET_NFC_SERVICE_SE_PRIVATE_H

#include "net_nfc_typedef_private.h"

typedef struct _se_setting_t
{
	net_nfc_target_handle_s *current_ese_handle;
	void *open_request_trans_param;
	uint8_t type;
	uint8_t return_type;
	uint8_t mode;
}
net_nfc_se_setting_t;

net_nfc_se_setting_t *net_nfc_service_se_get_se_setting();
net_nfc_target_handle_s *net_nfc_service_se_get_current_ese_handle();
void net_nfc_service_se_set_current_ese_handle(net_nfc_target_handle_s *handle);
uint8_t net_nfc_service_se_get_se_type();
void net_nfc_service_se_set_se_type(uint8_t type);
uint8_t net_nfc_service_se_get_se_mode();
void net_nfc_service_se_set_se_mode(uint8_t mode);

net_nfc_error_e net_nfc_service_se_change_se(uint8_t type);

void net_nfc_service_se_detected(net_nfc_request_msg_t *req_msg);
net_nfc_error_e net_nfc_service_se_close_ese();

/* TAPI SIM API */

bool net_nfc_service_tapi_init(void);
void net_nfc_service_tapi_deinit(void);
bool net_nfc_service_transfer_apdu(int client_fd, data_s *apdu, void *trans_param);
bool net_nfc_service_request_atr(int client_fd, void *trans_param);
bool net_nfc_service_se_transaction_receive(net_nfc_request_msg_t* msg);
void net_nfc_service_se_send_apdu(net_nfc_request_msg_t *msg);
void net_nfc_service_se_get_atr(net_nfc_request_msg_t *msg);
void net_nfc_service_se_close_se(net_nfc_request_msg_t *msg);
void net_nfc_service_se_open_se(net_nfc_request_msg_t *msg);
void net_nfc_service_se_set_se(net_nfc_request_msg_t *msg);
void net_nfc_service_se_get_se(net_nfc_request_msg_t *msg);
void net_nfc_service_se_cleanup();
void net_nfc_service_se_change_card_emulation_mode(net_nfc_request_msg_t *req_msg);

#endif
