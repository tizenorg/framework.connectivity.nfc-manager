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
#ifndef __NET_NFC_CLIENT_LLCP_H__
#define __NET_NFC_CLIENT_LLCP_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*net_nfc_client_llcp_config_completed)(net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_client_llcp_listen_completed)(net_nfc_error_e result,
	net_nfc_llcp_socket_t client_socket,
	void *user_data);

typedef void (*net_nfc_client_llcp_accept_completed)(net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_client_llcp_reject_completed)(net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_client_llcp_connect_completed)(net_nfc_error_e result,
	net_nfc_llcp_socket_t client_socket,
	void *user_data);

typedef void (*net_nfc_client_llcp_connect_sap_completed)(
	net_nfc_error_e result,
	net_nfc_llcp_socket_t client_socket,
	void *user_data);

typedef void (*net_nfc_client_llcp_send_completed)(net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_client_llcp_send_to_completed)(net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_client_llcp_receive_completed)(net_nfc_error_e result,
	data_h data,
	void *user_data);

typedef void (*net_nfc_client_llcp_receive_from_completed)(
	net_nfc_error_e result,
	sap_t sap,
	data_h data,
	void *user_data);

typedef void (*net_nfc_client_llcp_close_completed)(net_nfc_error_e result,
	void *user_data);

typedef void (*net_nfc_client_llcp_disconnect_completed)(
	net_nfc_error_e result,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_config(net_nfc_llcp_config_info_h config,
	net_nfc_client_llcp_config_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_config_sync
					(net_nfc_llcp_config_info_h config);

net_nfc_error_e net_nfc_client_llcp_get_config
					(net_nfc_llcp_config_info_h *config);

net_nfc_error_e net_nfc_client_llcp_listen(net_nfc_llcp_socket_t socket,
		const char *service_name,
		sap_t sap,
		net_nfc_client_llcp_listen_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_llcp_listen_sync(net_nfc_llcp_socket_t socket,
		const char *service_name,
		sap_t sap,
		net_nfc_llcp_socket_t *out_socket);

net_nfc_error_e net_nfc_client_llcp_accept(net_nfc_llcp_socket_t socket,
		net_nfc_client_llcp_accept_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_llcp_accept_sync(net_nfc_llcp_socket_t socket);

net_nfc_error_e net_nfc_client_llcp_reject(net_nfc_llcp_socket_t socket,
		net_nfc_client_llcp_reject_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_llcp_reject_sync(net_nfc_llcp_socket_t socket);

net_nfc_error_e net_nfc_client_llcp_connect(net_nfc_llcp_socket_t socket,
		const char *service_name,
		net_nfc_client_llcp_connect_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_llcp_connect_sync(net_nfc_llcp_socket_t socket,
		const char *service_name,
		net_nfc_llcp_socket_t *out_socket);

net_nfc_error_e net_nfc_client_llcp_send(net_nfc_llcp_socket_t socket,
	data_h data,
	net_nfc_client_llcp_send_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_send_sync(net_nfc_llcp_socket_t socket,
	data_h data);

net_nfc_error_e net_nfc_client_llcp_send_to(net_nfc_llcp_socket_t socket,
	sap_t sap,
	data_h data,
	net_nfc_client_llcp_send_to_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_send_to_sync(net_nfc_llcp_socket_t socket,
	sap_t sap,
	data_h data);

net_nfc_error_e net_nfc_client_llcp_receive(net_nfc_llcp_socket_t socket,
	size_t request_length,
	net_nfc_client_llcp_receive_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_receive_sync(net_nfc_llcp_socket_t socket,
	size_t request_length,
	data_h *out_data);

net_nfc_error_e net_nfc_client_llcp_receive_from(net_nfc_llcp_socket_t socket,
	size_t request_length,
	net_nfc_client_llcp_receive_from_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_receive_from_sync(
	net_nfc_llcp_socket_t socket,
	size_t request_length,
	sap_t *out_sap,
	data_h *out_data);

net_nfc_error_e net_nfc_client_llcp_close(net_nfc_llcp_socket_t socket,
	net_nfc_client_llcp_close_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_close_sync(net_nfc_llcp_socket_t socket);

net_nfc_error_e net_nfc_client_llcp_disconnect(net_nfc_llcp_socket_t socket,
	net_nfc_client_llcp_disconnect_completed callback,
	void *user_data);

net_nfc_error_e net_nfc_client_llcp_disconnect_sync(
	net_nfc_llcp_socket_t socket);

void net_nfc_client_llcp_create_socket(net_nfc_llcp_socket_t *socket,
		net_nfc_llcp_socket_option_h option);

net_nfc_error_e net_nfc_client_llcp_get_local_config(
		net_nfc_llcp_config_info_h *config);

net_nfc_error_e net_nfc_client_llcp_get_local_socket_option(
		net_nfc_llcp_socket_t socket,
		net_nfc_llcp_socket_option_h *option);

net_nfc_error_e net_nfc_client_llcp_create_socket_option(
		net_nfc_llcp_socket_option_h *option,
		uint16_t miu,
		uint8_t rw,
		net_nfc_socket_type_e type);

net_nfc_error_e net_nfc_client_llcp_socket_option_default(
	net_nfc_llcp_socket_option_h *option);

net_nfc_error_e net_nfc_client_llcp_get_socket_option_miu(
	net_nfc_llcp_socket_option_h option,
	uint16_t *miu);

net_nfc_error_e net_nfc_client_llcp_set_socket_option_miu(
	net_nfc_llcp_socket_option_h option,
	uint16_t miu);

net_nfc_error_e net_nfc_client_llcp_get_socket_option_rw(
	net_nfc_llcp_socket_option_h option,
	uint8_t *rt);

net_nfc_error_e net_nfc_client_llcp_set_socket_option_rw(
	net_nfc_llcp_socket_option_h option,
	uint8_t rt);

net_nfc_error_e net_nfc_client_llcp_get_socket_option_type(
	net_nfc_llcp_socket_option_h option,
	net_nfc_socket_type_e *type);

net_nfc_error_e net_nfc_client_llcp_set_socket_option_type(
	net_nfc_llcp_socket_option_h option,
	net_nfc_socket_type_e type);

net_nfc_error_e net_nfc_client_llcp_free_socket_option(
	net_nfc_llcp_socket_option_h option);

net_nfc_error_e net_nfc_client_llcp_create_config(
	net_nfc_llcp_config_info_h *config,
	uint16_t miu,
	uint16_t wks,
	uint8_t lto,
	uint8_t option);

net_nfc_error_e net_nfc_client_llcp_create_config_default(
	net_nfc_llcp_config_info_h *config);

net_nfc_error_e net_nfc_client_llcp_get_config_miu(
	net_nfc_llcp_config_info_h config,
	uint16_t *miu);

net_nfc_error_e net_nfc_client_llcp_get_config_wks(
	net_nfc_llcp_config_info_h config,
	uint16_t *wks);

net_nfc_error_e net_nfc_client_llcp_get_config_lto(
	net_nfc_llcp_config_info_h config,
	uint8_t *lto);

net_nfc_error_e net_nfc_client_llcp_get_config_option(
	net_nfc_llcp_config_info_h config,
	uint8_t *option);

net_nfc_error_e net_nfc_client_llcp_set_config_miu(
	net_nfc_llcp_config_info_h config,
	uint16_t miu);

net_nfc_error_e net_nfc_client_llcp_set_config_wks(
	net_nfc_llcp_config_info_h config,
	uint16_t wks);

net_nfc_error_e net_nfc_client_llcp_set_config_lto(
	net_nfc_llcp_config_info_h config,
	uint8_t lto);

net_nfc_error_e net_nfc_client_llcp_set_config_option(
	net_nfc_llcp_config_info_h config,
	uint8_t option);

net_nfc_error_e net_nfc_client_llcp_free_config(
	net_nfc_llcp_config_info_h config);

net_nfc_error_e net_nfc_client_llcp_create_socket_option_default(
					net_nfc_llcp_socket_option_h *option);

net_nfc_error_e net_nfc_client_llcp_connect_sap(net_nfc_llcp_socket_t socket,
					sap_t sap,
					net_nfc_client_llcp_connect_sap_completed callback,
					void *user_data);

net_nfc_error_e net_nfc_client_llcp_connect_sap_sync(
					net_nfc_llcp_socket_t socket,
					sap_t sap,
					net_nfc_llcp_socket_t *out_socket);


net_nfc_error_e net_nfc_client_llcp_init(void);

void net_nfc_client_llcp_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_LLCP_H__
