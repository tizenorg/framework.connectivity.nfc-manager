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
#ifndef __NET_NFC_SERVER_LLCP_H__
#define __NET_NFC_SERVER_LLCP_H__

#include <gio/gio.h>

#include "net_nfc_typedef_internal.h"

/* define */
/* Service Name should be followed naming rule. */
// service access name
#define SDP_SAN			"urn:nfc:sn:sdp"
#define IP_SAN			"urn:nfc:sn:ip"
#define OBEX_SAN 		"urn:nfc:sn:obex"

#define SDP_SAP			1  /* service discovery protocol service access point */
#define IP_SAP			2  /* Internet protocol service access point */
#define OBEX_SAP		3  /* object exchange service access point */

#define GET_MAJOR_VER(__x)	(((__x) >> 4) & 0x0F)
#define GET_MINOR_VER(__x)	((__x) & 0x0F)

/* default llcp configurations */
#define NET_NFC_LLCP_MIU	128
#define NET_NFC_LLCP_WKS	1
#define NET_NFC_LLCP_LTO	10
#define NET_NFC_LLCP_OPT	0

typedef enum
{
	NET_NFC_LLCP_IDLE = 0,
	NET_NFC_LLCP_STEP_01 = 0xFFFF,
	NET_NFC_LLCP_STEP_02,
	NET_NFC_LLCP_STEP_03,
	NET_NFC_LLCP_STEP_04,
	NET_NFC_LLCP_STEP_05,
	NET_NFC_LLCP_STEP_06,
	NET_NFC_LLCP_STEP_07,
	NET_NFC_LLCP_STEP_08,
	NET_NFC_LLCP_STEP_09,
	NET_NFC_LLCP_STEP_10,
	NET_NFC_LLCP_STEP_11,
	NET_NFC_LLCP_STEP_12,
	NET_NFC_LLCP_STEP_13,
	NET_NFC_LLCP_STEP_14,
	NET_NFC_LLCP_STEP_15,
	NET_NFC_LLCP_STEP_16,
	NET_NFC_LLCP_STEP_17,
	NET_NFC_LLCP_STEP_18,
	NET_NFC_LLCP_STEP_19,
	NET_NFC_LLCP_STEP_20,
	NET_NFC_LLCP_STEP_RETURN,
	NET_NFC_STATE_SOCKET_ERROR,
	NET_NFC_STATE_ERROR,
} net_nfc_state_e;

typedef void (*net_nfc_server_llcp_callback) (net_nfc_error_e result,
					net_nfc_target_handle_s *handle,
					net_nfc_llcp_socket_t socket,
					data_s *data,
					gpointer user_data);

typedef void (*net_nfc_server_llcp_activate_cb)(
	int event,
	net_nfc_target_handle_s *handle,
	uint32_t sap,
	const char *san,
	void *user_param);

gboolean net_nfc_server_llcp_init(GDBusConnection *connection);

void net_nfc_server_llcp_deinit(void);

/* server side */
void net_nfc_server_llcp_deactivated(gpointer user_data);

net_nfc_error_e net_nfc_server_llcp_set_config(
					net_nfc_llcp_config_info_s *config);

guint16 net_nfc_server_llcp_get_miu(void);

guint16 net_nfc_server_llcp_get_wks(void);

guint8 net_nfc_server_llcp_get_lto(void);

guint8 net_nfc_server_llcp_get_option(void);

bool net_nfc_server_llcp_target_detected(void *info);

net_nfc_error_e net_nfc_server_llcp_simple_server(
				net_nfc_target_handle_s *handle,
				const char *san,
				sap_t sap,
				net_nfc_server_llcp_callback callback,
				net_nfc_server_llcp_callback error_callback,
				gpointer user_data);

net_nfc_error_e net_nfc_server_llcp_simple_client(
				net_nfc_target_handle_s *handle,
				const char *san,
				sap_t sap,
				net_nfc_server_llcp_callback callback,
				net_nfc_server_llcp_callback error_callback,
				gpointer user_data);

net_nfc_error_e net_nfc_server_llcp_simple_accept(
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				net_nfc_server_llcp_callback error_callback,
				gpointer user_data);

net_nfc_error_e net_nfc_server_llcp_simple_send(
					net_nfc_target_handle_s *handle,
					net_nfc_llcp_socket_t socket,
					data_s *data,
					net_nfc_server_llcp_callback callback,
					gpointer user_data);

net_nfc_error_e net_nfc_server_llcp_simple_receive(
					net_nfc_target_handle_s *handle,
					net_nfc_llcp_socket_t socket,
					net_nfc_server_llcp_callback callback,
					gpointer user_data);

net_nfc_error_e net_nfc_server_llcp_register_service(const char *id,
	sap_t sap, const char *san, net_nfc_server_llcp_activate_cb cb,
	void *user_param);

net_nfc_error_e net_nfc_server_llcp_unregister_service(const char *id,
	sap_t sap, const char *san);

net_nfc_error_e net_nfc_server_llcp_unregister_services(const char *id);

net_nfc_error_e net_nfc_server_llcp_unregister_all();

net_nfc_error_e net_nfc_server_llcp_start_registered_services(
	net_nfc_target_handle_s *handle);

#endif //__NET_NFC_SERVER_LLCP_H__
