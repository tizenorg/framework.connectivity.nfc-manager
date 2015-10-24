 /*
 * Copyright   2012, 2013 Samsung Electronics Co., Ltd.
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
#ifndef __NET_NFC_TYPEDEF_INTERNAL_H__
#define __NET_NFC_TYPEDEF_INTERNAL_H__

#include "net_nfc_typedef.h"

typedef enum
{
	NET_NFC_POLL_START = 0x01,
	NET_NFC_POLL_STOP,
} net_nfc_detect_mode_e;

/**
 This structure is just data, to express bytes array
 */
typedef struct _data_s
{
	uint8_t *buffer;
	uint32_t length;
} data_s;

typedef struct _net_nfc_data_t
{
	uint32_t length;
	uint8_t buffer[0];
} net_nfc_data_s;

typedef enum _net_nfc_connection_type_e
{
	NET_NFC_TAG_CONNECTION = 0x00,
	NET_NFC_P2P_CONNECTION_TARGET,
	NET_NFC_P2P_CONNECTION_INITIATOR,
	NET_NFC_SE_CONNECTION
} net_nfc_connection_type_e;

typedef struct _net_nfc_target_handle_s
{
	uint32_t connection_id;
	net_nfc_connection_type_e connection_type;
	net_nfc_target_type_e target_type;
	/*++npp++*/
	llcp_app_protocol_e app_type;
	/*--npp--*/
} net_nfc_target_handle_s;

typedef struct _net_nfc_current_target_info_s
{
	net_nfc_target_handle_s *handle;
	uint32_t devType;
	int number_of_keys;
	net_nfc_data_s target_info_values;
}net_nfc_current_target_info_s;

typedef struct _net_nfc_llcp_config_info_s
{
	uint16_t miu; /** The remote Maximum Information Unit (NOTE: this is MIU, not MIUX !)*/
	uint16_t wks; /** The remote Well-Known Services*/
	uint8_t lto; /** The remote Link TimeOut (in 1/100s)*/
	uint8_t option; /** The remote options*/
} net_nfc_llcp_config_info_s;

typedef struct _net_nfc_llcp_socket_option_s
{
	uint16_t miu; /** The remote Maximum Information Unit */
	uint8_t rw; /** The Receive Window size (4 bits)*/
	net_nfc_socket_type_e type;
} net_nfc_llcp_socket_option_s;

typedef struct _net_nfc_llcp_internal_socket_s
{
	uint16_t miu; /** The remote Maximum Information Unit */
	uint8_t rw; /** The Receive Window size (4 bits)*/
	net_nfc_socket_type_e type;
	net_nfc_llcp_socket_t oal_socket;
	net_nfc_llcp_socket_t client_socket;
	sap_t sap;
	uint8_t *service_name;
	net_nfc_target_handle_s *device_id;
	net_nfc_llcp_socket_cb cb;
	bool close_requested;
	void *register_param; /* void param that has been registered in callback register time */
} net_nfc_llcp_internal_socket_s;

/**
 ndef_record_s structure has the NDEF record data. it is only a record not a message
 */
typedef struct _record_s
{
	uint8_t MB :1;
	uint8_t ME :1;
	uint8_t CF :1;
	uint8_t SR :1;
	uint8_t IL :1;
	uint8_t TNF :3;
	data_s type_s;
	data_s id_s;
	data_s payload_s;
	struct _record_s *next;
} ndef_record_s;

/**
 NDEF message it has record counts and records (linked listed form)
 */
typedef struct _ndef_message_s
{
	uint32_t recordCount;
	ndef_record_s *records; // linked list
} ndef_message_s;

/**
 Enum value to stop or start the discovery mode
 */

#define NET_NFC_MAX_UID_LENGTH            0x0AU       /**< Maximum UID length expected */
#define NET_NFC_MAX_ATR_LENGTH            0x30U       /**< Maximum ATR_RES (General Bytes) */
#define NET_NFC_ATQA_LENGTH               0x02U       /**< ATQA length */
#define NET_NFC_ATQB_LENGTH               0x0BU       /**< ATQB length */

#define NET_NFC_PUPI_LENGTH               0x04U       /**< PUPI length */
#define NET_NFC_APP_DATA_B_LENGTH         0x04U       /**< Application Data length for Type B */
#define NET_NFC_PROT_INFO_B_LENGTH        0x03U       /**< Protocol info length for Type B  */

#define NET_NFC_MAX_ATR_LENGTH            0x30U       /**< Maximum ATR_RES (General Bytes)  */
#define NET_NFC_MAX_UID_LENGTH            0x0AU       /**< Maximum UID length expected */
#define NET_NFC_FEL_ID_LEN                0x08U       /**< Felica current ID Length */
#define NET_NFC_FEL_PM_LEN                0x08U       /**< Felica current PM Length */
#define NET_NFC_FEL_SYS_CODE_LEN          0x02U       /**< Felica System Code Length */

#define NET_NFC_15693_UID_LENGTH          0x08U       /**< Length of the Inventory bytes for  */

typedef struct _net_nfc_tag_info_s
{
	char *key;
	data_h value;
} net_nfc_tag_info_s;

typedef struct _net_nfc_target_info_s
{
	net_nfc_target_handle_s *handle;
	net_nfc_target_type_e devType;
	uint8_t is_ndef_supported;
	uint8_t ndefCardState;
	uint32_t maxDataSize;
	uint32_t actualDataSize;
	int number_of_keys;
	net_nfc_tag_info_s *tag_info_list;
	char **keylist;
	data_s raw_data;
} net_nfc_target_info_s;

typedef struct _net_nfc_se_event_info_s
{
	data_s aid;
	data_s param;
} net_nfc_se_event_info_s;

typedef struct _net_nfc_transceive_info_s
{
	uint32_t dev_type;
	data_s trans_data;
} net_nfc_transceive_info_s;

typedef struct _net_nfc_connection_handover_info_s
{
	net_nfc_conn_handover_carrier_type_e type;
	data_s data;
}
net_nfc_connection_handover_info_s;

typedef enum _client_state_e
{
	NET_NFC_CLIENT_INACTIVE_STATE = 0x00,
	NET_NFC_CLIENT_ACTIVE_STATE,
} client_state_e;

typedef enum _net_nfc_launch_popup_check_e
{
	CHECK_FOREGROUND = 0x00,
	NO_CHECK_FOREGROUND,
} net_nfc_launch_popup_check_e;

typedef enum _net_nfc_launch_popup_state_e
{
	NET_NFC_LAUNCH_APP_SELECT = 0x00,
	NET_NFC_NO_LAUNCH_APP_SELECT,
} net_nfc_launch_popup_state_e;

/* server state */
#define NET_NFC_SERVER_IDLE		0
#define NET_NFC_SERVER_DISCOVERY	(1 << 1)
#define NET_NFC_TAG_CONNECTED		(1 << 2)
#define NET_NFC_SE_CONNECTED		(1 << 3)
#define NET_NFC_SNEP_CLIENT_CONNECTED	(1 << 4)
#define NET_NFC_NPP_CLIENT_CONNECTED	(1 << 5)
#define NET_NFC_SNEP_SERVER_CONNECTED	(1 << 6)
#define NET_NFC_NPP_SERVER_CONNECTED	(1 << 7)

// these are messages for request
#define NET_NFC_REQUEST_MSG_HEADER \
	/* DON'T MODIFY THIS CODE - BEGIN */ \
	uint32_t length; \
	uint32_t request_type; \
	uint32_t client_fd; \
	uint32_t flags; \
	uint32_t user_param; \
	/* DON'T MODIFY THIS CODE - END */

typedef struct _net_nfc_request_msg_t
{
	NET_NFC_REQUEST_MSG_HEADER
} net_nfc_request_msg_t;

typedef struct _net_nfc_request_target_detected_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint32_t devType;
	int number_of_keys;
	net_nfc_data_s target_info_values;
} net_nfc_request_target_detected_t;

typedef struct _net_nfc_request_se_event_t
{
	NET_NFC_REQUEST_MSG_HEADER

	data_s aid;
	data_s param;
} net_nfc_request_se_event_t;

typedef struct _net_nfc_request_llcp_msg_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_llcp_socket_t llcp_socket;
} net_nfc_request_llcp_msg_t;

typedef struct _net_nfc_request_hce_apdu_t
{
	NET_NFC_REQUEST_MSG_HEADER

	data_s apdu;
} net_nfc_request_hce_apdu_t;

typedef struct _net_nfc_request_listen_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	uint16_t miu; /** The remote Maximum Information Unit */
	uint8_t rw; /** The Receive Window size (4 bits)*/
	net_nfc_socket_type_e type;
	net_nfc_llcp_socket_t oal_socket;
	sap_t sap;
	void *trans_param;
	net_nfc_data_s service_name;
} net_nfc_request_listen_socket_t;

typedef struct _net_nfc_request_receive_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	size_t req_length;
	void *trans_param;
	net_nfc_data_s data;
} net_nfc_request_receive_socket_t;

typedef struct _net_nfc_request_receive_from_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	size_t req_length;
	sap_t sap;
	void *trans_param;
	net_nfc_data_s data;
} net_nfc_request_receive_from_socket_t;

// these are messages for response

typedef void (*target_detection_listener_cb)(void *data, void *user_param);
typedef void (*se_transaction_listener_cb)(void *data, void *user_param);
typedef void (*llcp_event_listener_cb)(void *data, void *user_param);


/*HCE CB*/
typedef void (*hce_active_listener_cb)(void *user_param);
typedef void (*hce_deactive_listener_cb)(void *user_param);
typedef void (*hce_apdu_listener_cb)(void *data, void *user_param);


typedef enum _llcp_event_e
{
	LLCP_EVENT_SOCKET_ACCEPTED = 0x1,
	LLCP_EVENT_SOCKET_ERROR,
	LLCP_EVENT_DEACTIVATED,
} llcp_event_e;

typedef struct _net_nfc_stack_information_s
{
	uint32_t net_nfc_supported_tagetType;
	uint32_t net_nfc_fw_version;
} net_nfc_stack_information_s;

typedef enum _net_nfc_discovery_mode_e
{
	NET_NFC_DISCOVERY_MODE_CONFIG = 0x00U,
	NET_NFC_DISCOVERY_MODE_START,
	NET_NFC_DISCOVERY_MODE_STOP,
	NET_NFC_DISCOVERY_MODE_RESUME,
} net_nfc_discovery_mode_e;

typedef enum _net_nfc_secure_element_policy_e
{
	SECURE_ELEMENT_POLICY_INVALID = 0x00,
	SECURE_ELEMENT_POLICY_UICC_ON = 0x01,
	SECURE_ELEMENT_POLICY_UICC_OFF = 0x02,
	SECURE_ELEMENT_POLICY_ESE_ON = 0x03,
	SECURE_ELEMENT_POLICY_ESE_OFF = 0x04,
	SECURE_ELEMENT_POLICY_HCE_ON = 0x05,
	SECURE_ELEMENT_POLICY_HCE_OFF = 0x06
} net_nfc_secure_element_policy_e;

 typedef enum _net_nfc_secure_element_type_e
 {
	SECURE_ELEMENT_TYPE_INVALID = 0x00, /**< Indicates SE type is Invalid */
	SECURE_ELEMENT_TYPE_ESE = 0x01, /**< Indicates SE type is SmartMX */
	SECURE_ELEMENT_TYPE_UICC = 0x02, /**<Indicates SE type is   UICC */
	SECURE_ELEMENT_TYPE_HCE = 0x03, /**<Indicates SE type is   HCE */
	SECURE_ELEMENT_TYPE_UNKNOWN = 0x04 /**< Indicates SE type is Unknown */
} net_nfc_secure_element_type_e;

typedef enum _net_nfc_secure_element_state_e
{
	SECURE_ELEMENT_INACTIVE_STATE = 0x00, /**< state of the SE is In active*/
	SECURE_ELEMENT_ACTIVE_STATE = 0x01, /**< state of the SE is active  */
} net_nfc_secure_element_state_e;

typedef enum _net_nfc_wallet_mode_e
{
	NET_NFC_WALLET_MODE_MANUAL = 0x00,
	NET_NFC_WALLET_MODE_AUTOMATIC = 0x01,
	NET_NFC_WALLET_MODE_UICC = 0x02,
	NET_NFC_WALLET_MODE_ESE = 0x03,
	NET_NFC_WALLET_MODE_HCE = 0x04,
} net_nfc_wallet_mode_e;

typedef struct _secure_element_info_s
{
	net_nfc_target_handle_s *handle;
	net_nfc_secure_element_type_e secure_element_type;
	net_nfc_secure_element_state_e secure_element_state;

} net_nfc_secure_element_info_s;

typedef enum _net_nfc_secure_element_mode_e
{
	SECURE_ELEMENT_WIRED_MODE = 0x00, /**< Enables Wired Mode communication.This mode shall be applied to */
	SECURE_ELEMENT_VIRTUAL_MODE, /**< Enables Virtual Mode communication.This can be applied to UICC as well as SmartMX*/
	SECURE_ELEMENT_OFF_MODE /**< Inactivate SE.This means,put SE in in-active state */
} net_nfc_secure_element_mode_e;

typedef enum _net_nfc_message_service_e
{
	NET_NFC_MESSAGE_SERVICE_RESET = 2000,
	NET_NFC_MESSAGE_SERVICE_INIT,
	NET_NFC_MESSAGE_SERVICE_ACTIVATE,
	NET_NFC_MESSAGE_SERVICE_DEACTIVATE,
	NET_NFC_MESSAGE_SERVICE_DEINIT,
	NET_NFC_MESSAGE_SERVICE_STANDALONE_TARGET_DETECTED,
	NET_NFC_MESSAGE_SERVICE_SE,
	NET_NFC_MESSAGE_SERVICE_TERMINATION,
	NET_NFC_MESSAGE_SERVICE_SLAVE_TARGET_DETECTED,
	NET_NFC_MESSAGE_SERVICE_SLAVE_ESE_DETECTED,
	NET_NFC_MESSAGE_SERVICE_RESTART_POLLING_LOOP,
	NET_NFC_MESSAGE_SERVICE_LLCP_LISTEN,
	NET_NFC_MESSAGE_SERVICE_LLCP_INCOMING,
	NET_NFC_MESSAGE_SERVICE_LLCP_ACCEPT,
	NET_NFC_MESSAGE_SERVICE_LLCP_REJECT,
	NET_NFC_MESSAGE_SERVICE_LLCP_SEND,
	NET_NFC_MESSAGE_SERVICE_LLCP_SEND_TO,
	NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE,
	NET_NFC_MESSAGE_SERVICE_LLCP_RECEIVE_FROM,
	NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT,
	NET_NFC_MESSAGE_SERVICE_LLCP_CONNECT_SAP,
	NET_NFC_MESSAGE_SERVICE_LLCP_DISCONNECT,
	NET_NFC_MESSAGE_SERVICE_LLCP_DEACTIVATED,
	NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ERROR,
	NET_NFC_MESSAGE_SERVICE_LLCP_SOCKET_ACCEPTED_ERROR,
	NET_NFC_MESSAGE_SERVICE_CHANGE_CLIENT_STATE,
	NET_NFC_MESSAGE_SERVICE_WATCH_DOG,
	NET_NFC_MESSAGE_SERVICE_CLEANER,
	NET_NFC_MESSAGE_SERVICE_SET_LAUNCH_STATE,
} net_nfc_message_service_e;

typedef enum _net_nfc_se_command_e
{
	NET_NFC_SE_CMD_UICC_ON = 0,
	NET_NFC_SE_CMD_ESE_ON,
	NET_NFC_SE_CMD_ALL_OFF,
	NET_NFC_SE_CMD_ALL_ON,
} net_nfc_se_command_e;

/* connection handover info */

typedef enum
{
	NET_NFC_CONN_HANDOVER_ERR_REASON_RESERVED = 0x00,
	NET_NFC_CONN_HANDOVER_ERR_REASON_TEMP_MEM_CONSTRAINT,
	NET_NFC_CONN_HANDOVER_ERR_REASON_PERM_MEM_CONSTRAINT,
	NET_NFC_CONN_HANDOVER_ERR_REASON_CARRIER_SPECIFIC_CONSTRAINT,
} net_nfc_conn_handover_error_reason_e;

#define SMART_POSTER_RECORD_TYPE	"Sp"
#define URI_RECORD_TYPE			"U"
#define TEXT_RECORD_TYPE		"T"
#define GC_RECORD_TYPE			"Gc"

#define URI_SCHEM_FILE "file://"

typedef void (*net_nfc_service_llcp_cb)(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, data_s *data, void *extra, void *user_param);

typedef struct _net_nfc_llcp_param_t
{
	net_nfc_llcp_socket_t socket;
	net_nfc_service_llcp_cb cb;
	data_s data;
	void *user_param;
}
net_nfc_llcp_param_t;

typedef enum
{
	NET_NFC_INVALID = 0x00,
	NET_NFC_SCREEN_OFF = 0x01,
	NET_NFC_SCREEN_ON_LOCK = 0x02,
	NET_NFC_SCREEN_ON_UNLOCK = 0x03,
} net_nfc_screen_state_type_e;

#endif //__NET_NFC_TYPEDEF_INTERNAL_H__
