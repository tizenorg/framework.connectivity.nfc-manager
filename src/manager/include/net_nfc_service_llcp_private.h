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

#ifndef NET_NFC_SERVICE_LLCP_PRIVATE_H
#define NET_NFC_SERVICE_LLCP_PRIVATE_H

#include "net_nfc_typedef_private.h"

/* define */
/* Service Name should be followed naming rule. */
// service access name

#define SDP_SAN			"urn:nfc:sn:sdp"
#define IP_SAN			"urn:nfc:sn:ip"
#define SNEP_SAN 		"urn:nfc:sn:snep"
#define OBEX_SAN 		"urn:nfc:sn:obex"

#define CONN_HANDOVER_SAN 	"urn:nfc:sn:handover"

#define NPP_SAN			"com.android.npp"
#define NPP_SAP			0x10

#define SDP_SAP			1    /* service discovery protocol service access point */
#define IP_SAP			2       /* Internet protocol service access point */
#define OBEX_SAP		3  /* ojbect exchange service access point */
#define SNEP_SAP		4  /* simple ndef exchange protocol service access point */

#define CONN_HANDOVER_SAP	5 /* connection handover service access point */

#define SNEP_MAJOR_VER		1
#define SNEP_MINOR_VER		0

#define NPP_MAJOR_VER		0
#define NPP_MINOR_VER		1

#define NPP_NDEF_ENTRY		0x00000001

#define NPP_ACTION_CODE		0x01

#define SNEP_MAX_BUFFER		128 /* simple NDEF exchange protocol */
#define CH_MAX_BUFFER		128     /* connection handover */

typedef enum{
	NPP_REQ_CONTINUE = 0x00,
	NPP_REQ_REJECT,
	NPP_RESP_CONT,
	NPP_RESP_SUCCESS,
	NPP_RESP_NOT_FOUND,
	NPP_RESP_EXCESS_DATA,
	NPP_RESP_BAD_REQ,
	NPP_RESP_NOT_IMPLEMEN,
	NPP_RESP_UNSUPPORTED_VER,
	NPP_RESP_REJECT,
}npp_command_field_e;

typedef enum{
	SNEP_REQ_CONTINUE = 0x00,
	SNEP_REQ_GET = 0x01,
	SNEP_REQ_PUT = 0x02,
	SNEP_REQ_REJECT = 0x7F,
	SNEP_RESP_CONT = 0x80,
	SNEP_RESP_SUCCESS = 0x81,
	SNEP_RESP_NOT_FOUND = 0xC0,
	SNEP_RESP_EXCESS_DATA = 0xC1,
	SNEP_RESP_BAD_REQ = 0xC2,
	SNEP_RESP_NOT_IMPLEMENT = 0xE0,
	SNEP_RESP_UNSUPPORTED_VER = 0xE1,
	SNEP_RESP_REJECT = 0xFF,
}snep_command_field_e;

/* static variable */

typedef enum {
	NET_NFC_STATE_EXCHANGER_SERVER = 0x00,
	NET_NFC_STATE_EXCHANGER_SERVER_NPP,

	NET_NFC_STATE_EXCHANGER_CLIENT,
	NET_NFC_STATE_CONN_HANDOVER_REQUEST,
	NET_NFC_STATE_CONN_HANDOVER_SELECT,
} llcp_state_e;

typedef enum {
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

typedef struct _net_nfc_llcp_state_t{
	int client_fd;
	unsigned int step;
	unsigned int fragment_offset;
	llcp_state_e state;
	net_nfc_llcp_socket_t socket;
	uint16_t max_capability;
	net_nfc_target_handle_s * handle;
	net_nfc_error_e prev_result;
	net_nfc_llcp_socket_t incomming_socket;
	ndef_message_s *requester;
	ndef_message_s *selector;
	bool low_power;
	void * user_data;
	void * payload;

	llcp_app_protocol_e type_app_protocol;
	net_nfc_conn_handover_carrier_type_e type;

} net_nfc_llcp_state_t;


typedef struct _net_nfc_llcp_npp_t{
	uint8_t npp_version;
	uint32_t npp_ndef_entry;
	uint8_t npp_action_code;
	uint32_t npp_ndef_length;
} __attribute__((packed))net_nfc_llcp_npp_t;

#define NET_NFC_COMMON_HANDOVER_CONTEXT unsigned int step;\
					net_nfc_llcp_state_t *llcp_state;\
					void *user_data;\
					net_nfc_error_e result;\
					net_nfc_conn_handover_carrier_type_e request_type;\
					void *data;\
					bool is_requester;

typedef struct _net_nfc_handover_context_t
{
	NET_NFC_COMMON_HANDOVER_CONTEXT;
}
net_nfc_handover_context_t;

typedef struct _net_nfc_handover_create_config_context_t
{
	NET_NFC_COMMON_HANDOVER_CONTEXT;

	net_nfc_conn_handover_carrier_type_e current_type;
	ndef_message_s *ndef_message;
	ndef_message_s *requester; /* for low power selector */
	bool is_low_power;
}
net_nfc_handover_create_config_context_t;

typedef struct _net_nfc_handover_process_config_context_t
{
	NET_NFC_COMMON_HANDOVER_CONTEXT;

	net_nfc_carrier_config_s *config;
}
net_nfc_handover_process_config_context_t;

bool net_nfc_service_llcp_process_accept(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_terminate_connection(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_disconnect_target(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_socket_error(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_accepted_socket_error(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_send_to_socket(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_send_socket(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_receive_socket(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_receive_from_socket(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_connect_socket(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_connect_sap_socket(net_nfc_request_msg_t* msg);
bool net_nfc_service_llcp_process_disconnect_socket(net_nfc_request_msg_t* msg);
net_nfc_error_e net_nfc_service_send_exchanger_msg(net_nfc_request_p2p_send_t* msg);
bool net_nfc_service_llcp_process(net_nfc_target_handle_s* handle, int devType, net_nfc_error_e* result);

void net_nfc_service_llcp_remove_state (net_nfc_llcp_state_t * state);
void net_nfc_service_llcp_add_state (net_nfc_llcp_state_t * state);

#endif
