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
#ifndef __NET_NFC_TYPEDEF_H__
#define __NET_NFC_TYPEDEF_H__

/**
 NFC Manager
 NFC Manager controls the nfc device with high level APIs such as SmartPoster and Connection handover.
 It also support the JSR257 push handling.
 This file describe the structure and defines of the NFC manager

 @version		0.1

 */

/**
 @defgroup NET_NFC_MANAGER The description of NFC Manager
 @defgroup NET_NFC_TYPEDEF Defines and structures
 @defgroup NET_NFC_MANAGER_API NFC Manager
 @defgroup NET_NFC_MANAGER_INFO Tag Information and data APIs
 @defgroup NET_NFC_MANAGER_TAG Tag Read/Write APIs
 @defgroup NET_NFC_MANAGER_NDEF NDEF Message APIs
 @defgroup NET_NFC_MANAGER_RECORD NDEF Record APIs
 @defgroup NET_NFC_MANAGER_LLCP NFC LLCP APIs
 @defgroup NET_NFC_MANAGER_APDU Internal APDU APIs
 @defgroup NET_NFC_MANAGER_EXCHANGE App Exchanger APIs


 @addtogroup NET_NFC_MANAGER
 @{
 <P> "NFC Manager" is the framework that provide NFC APIs,
 and it also provide high level services such as Smart Poster, Connection Handover,
 and JSR257 push registry.  </P>

 NFC Manager APIs are defined in <net_nfc.h>, <net_nfc_typedef.h>

 <P>
 Memory management rules <br>
 depends on the the verb of each function it describe memory management roles

 1. set: copy the parameters and used inside of nfc-manager, you should free the parameter you have used
 2. append: it is similar to "set" but, it does not make copy, you SHOULD NOT free the parameter after use it belongs to nfc-manager and it will be freed later
 (example "net_nfc_append_record_to_ndef_message") the appended record will be free the at the ndef message free time.
 3. get, search : it gives original pointer to you, DO NOT free the pointer get from nfc-manager API
 4. remove: automatically free inside of the this function do not free again.
 5. create: it allocate handle, therefore, you should consider free after using (for example "net_nfc_create_rawdata_from_ndef_message(ndef_message_h ndef_message, data_h *rawdata)"
 this function allocate the data_h, you should free data with the function net_nfc_free_data())
 </p>

 @}
 */

/**
 @addtogroup NET_NFC_TYPEDEF
 @{
 This documents provide the NFC defines

 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 net_nfc_error_e is enum type that returned from each functions
 it mostly contains the error codes and it may contains status codes.
 */
typedef enum
{
/*000*/NET_NFC_OK = 0, /**< Status is OK	*/
/*999*/NET_NFC_UNKNOWN_ERROR = -999, /**< Unknown error */
/*998*/NET_NFC_ALLOC_FAIL, /**< Memory allocation is failed */
/*997*/NET_NFC_THREAD_CREATE_FAIL, /**< Thread creation is failed */
/*996*/NET_NFC_INVALID_STATE, /**< State of NFC-Manager or nfc-stack is not normal */
/*995*/NET_NFC_IPC_FAIL, /**< Communication with ipc is failed. (from client to server)*/
/*994*/NET_NFC_OUT_OF_BOUND, /**< Index is out of bound */
/*993*/NET_NFC_NULL_PARAMETER, /**< Unexpected NULL parameter is received */
/*992*/NET_NFC_BUFFER_TOO_SMALL, /**< Requested buffer is too small to store data, this error should be received */
/*991*/NET_NFC_ALREADY_INITIALIZED, /**< You tried to initialized again without de-init */
/*990*/NET_NFC_COMMUNICATE_WITH_CONTROLLER_FAILED, /**< Communication with Controller Chipset is failed this is Fatal Error */
/*989*/NET_NFC_RF_TIMEOUT, /**< Timeout is raised while communicate with a tag */
/*988*/NET_NFC_RF_ERROR, /**< Unexpected package is received from target, you may receive this error comes by the low level RF communication fault*/
/*987*/NET_NFC_NOT_INITIALIZED, /**< Application tries to request without initialization */
/*986*/NET_NFC_NOT_SUPPORTED, /**< Request information or command is not supported in current connected target */
/*985*/NET_NFC_ALREADY_REGISTERED, /**< Requested SAP number is already used by other socket or data is already appended or registered */
/*984*/NET_NFC_NOT_ALLOWED_OPERATION, /**< Requested Operation is not allowed in the situation in critical time (such as write data on target)*/
/*983*/NET_NFC_BUSY, /**< Previous operation is not finished. don't worry to get this message, most of request will be executed in the serial queue */
/*982*/NET_NFC_INVALID_HANDLE, /**< Requested Device in not valid device */
/*981*/NET_NFC_TAG_READ_FAILED, /**< Tag reading is failed because of unexpected chunk data is received or error ack is received */
/*980*/NET_NFC_TAG_WRITE_FAILED, /**< When you try to write on read only tag or error ack is received */
/*979*/NET_NFC_NO_NDEF_SUPPORT, /**< Tag is not supported NDEF format for tag is not formatted for NDEF */
/*978*/NET_NFC_NO_NDEF_MESSAGE, /**< No data is received after NDEF reading */
/*977*/NET_NFC_INVALID_FORMAT, /**< Received data is not readable or it has illegal values or format */
/*976*/NET_NFC_INSUFFICIENT_STORAGE, /**< The connected tag does not have enough information */
/*975*/NET_NFC_OPERATION_FAIL, /**< The remote target returned error while doing a operation*/
/*974*/NET_NFC_NOT_CONNECTED, /**< remote is not connected correctly. This can be happened when the RF does not have enough strength */
/*973*/NET_NFC_NO_DATA_FOUND, /**< Requested data is not found in the list or properties */
/*972*/NET_NFC_SECURITY_FAIL, /**< Authentication is failed while communication with nfc-manager server */
/*971*/NET_NFC_TARGET_IS_MOVED_AWAY, /**< Target is lost while doing a operation */
/*970*/NET_NFC_TAG_IS_ALREADY_FORMATTED, /** Target is already formatted */
/*969*/NET_NFC_NOT_REGISTERED, /**< removal is requested but requested data is not registered */
/*968*/NET_NFC_INVALID_PARAM, /**< removal is requested but requested data is not registered */
/*967*/NET_NFC_PERMISSION_DENIED, /**< privilege check is failed */
/*966*/NET_NFC_NOT_ACTIVATED, /**< Application tries to request without activation */
/*499*/NET_NFC_NDEF_TYPE_LENGTH_IS_NOT_OK = -499, /**< Illegal ndef record type length */
/*498*/NET_NFC_NDEF_PAYLOAD_LENGTH_IS_NOT_OK, /**< Illegal ndef record payload length */
/*497*/NET_NFC_NDEF_ID_LENGTH_IS_NOT_OK, /**< Illegal ndef record id length */
/*496*/NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE, /**< Parameter record is not expected record. for example, try to URI from text record */
/*495*/NET_NFC_NDEF_BUF_END_WITHOUT_ME, /**< NDEF messages is terminated without ME flag */
/*494*/NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC, /**< Current device does not support NFC feature or this manager does not found plugin library */

/*399*/NET_NFC_LLCP_INVALID_SOCKET = -399, /**< socket is not valid socket */
/*398*/NET_NFC_LLCP_SOCKET_DISCONNECTED, /**< socket is disconnected */
/*397*/NET_NFC_LLCP_SOCKET_FRAME_REJECTED, /**< send data is rejected from remote side */

/*299*/NET_NFC_P2P_SEND_FAIL = -299, /**< P2P data send fail */
} net_nfc_error_e;

/**
 Enum value of the record type  ( TNF value )
 */
typedef enum
{
	NET_NFC_RECORD_EMPTY = 0x0,
	NET_NFC_RECORD_WELL_KNOWN_TYPE,
	NET_NFC_RECORD_MIME_TYPE, // Media type
	NET_NFC_RECORD_URI,
	NET_NFC_RECORD_EXTERNAL_RTD,
	NET_NFC_RECORD_UNKNOWN,
	NET_NFC_RECORD_UNCHAGNED,
} net_nfc_record_tnf_e;

/**
 net_nfc_message_e is identify the events comes from nfc-manager.
 most of the events response event that you requested operations.
 and some of the events are generated by nfc-manager. (example, NET_NFC_MESSAGE_TAG_DISCOVERED, NET_NFC_MESSAGE_TAG_DETACHED,
 NET_NFC_MESSAGE_LLCP_DISCOVERED and NET_NFC_MESSAGE_LLCP_DETACHED)

 All of the events are delivered by the the callback function that registered with "net_nfc_set_response_callback"
 */

typedef enum
{
	NET_NFC_MESSAGE_TRANSCEIVE = 0, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_tranceive"
	 	 	 	 	 	 	 	 	 <br> if the operation is success, the data parameter should cast into data_h or it return NULL*/
	NET_NFC_MESSAGE_READ_NDEF, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_read_tag"
	 	 	 	 	 	 	 	 <br> if the operation is success, the data parameter should cast into ndef_message_h or it return NULL */
	NET_NFC_MESSAGE_WRITE_NDEF, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_write_ndef"
	 	 	 	 	 	 	 	 <br> data pointer always returns NULL */
	NET_NFC_MESSAGE_MAKE_READ_ONLY_NDEF, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_make_read_only_ndef"
	 	 	 	 	 	 	 	 	 	 <br> data pointer always returns NULL */
	NET_NFC_MESSAGE_IS_TAG_CONNECTED, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_is_tag_conneced"
	 	 	 	 	 	 	 	 	 	 <br> data pointer always returns NULL */
	NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_get_current_tag_infof"
	 	 	 	 	 	 	 	 <br> if the operation is success, the data parameter should cast into net_nfc_target_info_h or it return NULL */
	NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE,  /**< Type: Response Event, <br> This events is received after calling the "net_nfc_get_current_target_handle"
	 	 	 	 	 	 	 	 <br> if the operation is success, the data parameter should cast into net_nfc_target_handle_h or it return NULL */
	NET_NFC_MESSAGE_TAG_DISCOVERED, /**< Type: Notify Event, <br> When a tag or SE is detected, you got this event.
	 	 	 	 	 	 	 	 	 <br> The data contains the target info , need to cast to net_nfc_target_info_h*/
	NET_NFC_MESSAGE_NOTIFY, /**< This Notify Event <br> when the unexpected error has occurred, this event is delivered. data pointer always returns NULL  */
	NET_NFC_MESSAGE_TAG_DETACHED, /**< Type: Notify Event, <br> When a tag or SE is disappeared, you got this event.
	 	 	 	 	 	 	 	 	 <br> The data contains the target info , need to cast to net_nfc_target_info_h but it does not have detail target info
	 	 	 	 	 	 	 	 	 <br> please, do not use "net_nfc_get_tag_info_keys" when you got this event*/
/*10*/	NET_NFC_MESSAGE_FORMAT_NDEF, /**< Type: Response Event <br> After complete "net_nfc_format_ndef", this event is delivered */
	NET_NFC_MESSAGE_LLCP_DISCOVERED,/**< Type: Notify Event <br> When LLCP is discovered and remote device is support llcp, you receive this event
	 	 	 	 	 	 	 	 	 <br> data pointer contains the remote llcp configuration info. Cast to net_nfc_llcp_config_info_h*/
	NET_NFC_MESSAGE_P2P_DETACHED, /**< Type: Notify Event <br> When LLCP is de-activated by removing the device, you receive this event*/
	NET_NFC_MESSAGE_LLCP_CONFIG, /**< Type: Response Event. <br> The operation of "net_nfc_set_llcp_local_configure" is completed */

	NET_NFC_MESSAGE_P2P_DISCOVERED, /**< Type: Notify Event <br> The remove device is detected and ready for transferring data to remote side */
	NET_NFC_MESSAGE_P2P_SEND, /**< Type: Response Event, <br> This events is received after calling the "net_nfc_send_exchanger_data" */
	NET_NFC_MESSAGE_P2P_RECEIVE, /**< Type: Notify Event, <br> When llcp server socket receive some data, this event is delivered. */

	NET_NFC_MESSAGE_SE_START_TRANSACTION, /**< Type: Notify Event, indicates external reader start transaction*/
	NET_NFC_MESSAGE_SE_END_TRANSACTION, /**< Type: Notify Event, indicates external reader end transaction*/
	NET_NFC_MESSAGE_SE_TYPE_TRANSACTION, /**< Type: Notify Event, Indicates external reader trying to access secure element */
/*20*/	NET_NFC_MESSAGE_SE_CONNECTIVITY, /**< Type: Notify Event, This event notifies the terminal host that it shall send a connectivity event from UICC */
	NET_NFC_MESSAGE_SE_FIELD_ON, /**< Type: Notify Event, indicates external reader field is on*/
	NET_NFC_MESSAGE_SE_FIELD_OFF, /**< Type: Notify Event, indicates external reader field is off*/
	NET_NFC_MESSAGE_SE_TYPE_CHANGED, /**< Type: Notify Event, indicates secure element type is changed*/
	NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED, /**< Type: Notify Event, indicates card emulation mode is changed*/
	NET_NFC_MESSAGE_CONNECTION_HANDOVER, /**< Type: Response Event. <br> The result of connection handover. If it has been completed successfully, this event will include the information of alternative carrier. */

	NET_NFC_MESSAGE_SET_SE,
	NET_NFC_MESSAGE_GET_SE,
	NET_NFC_MESSAGE_OPEN_INTERNAL_SE,
	NET_NFC_MESSAGE_CLOSE_INTERNAL_SE,
/*30*/	NET_NFC_MESSAGE_SEND_APDU_SE,
	NET_NFC_MESSAGE_GET_ATR_SE,
	NET_NFC_GET_SERVER_STATE,

	NET_NFC_MESSAGE_SIM_TEST,

	NET_NFC_MESSAGE_INIT,
	NET_NFC_MESSAGE_DEINIT,

	NET_NFC_MESSAGE_PRBS_TEST,

	NET_NFC_MESSAGE_GET_FIRMWARE_VERSION,

	NET_NFC_MESSAGE_SET_EEDATA,

	NET_NFC_MESSAGE_SNEP_START_SERVER,
	NET_NFC_MESSAGE_SNEP_START_CLIENT,
/*40*/	NET_NFC_MESSAGE_SNEP_REQUEST,
	NET_NFC_MESSAGE_SNEP_STOP_SERVICE,
	NET_NFC_MESSAGE_SNEP_REGISTER_SERVER,
	NET_NFC_MESSAGE_SNEP_UNREGISTER_SERVER,

	NET_NFC_MESSAGE_CONNECT,
	NET_NFC_MESSAGE_DISCONNECT,
	NET_NFC_MESSAGE_SET_CARD_EMULATION,

/*47*/	NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED,
	NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED,
	NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA,
} net_nfc_message_e;

typedef enum
{
	NET_NFC_UNKNOWN_TARGET = 0x00U,

	/* Specific PICC Devices */

	NET_NFC_GENERIC_PICC,
	NET_NFC_ISO14443_A_PICC,
	NET_NFC_ISO14443_4A_PICC,
	NET_NFC_ISO14443_3A_PICC,
	NET_NFC_MIFARE_MINI_PICC,
	NET_NFC_MIFARE_1K_PICC,
	NET_NFC_MIFARE_4K_PICC,
	NET_NFC_MIFARE_ULTRA_PICC,
	NET_NFC_MIFARE_DESFIRE_PICC,
	NET_NFC_ISO14443_B_PICC,
	NET_NFC_ISO14443_4B_PICC,
	NET_NFC_ISO14443_BPRIME_PICC,
	NET_NFC_FELICA_PICC,
	NET_NFC_JEWEL_PICC,
	NET_NFC_ISO15693_PICC,
	NET_NFC_BARCODE_128_PICC,
	NET_NFC_BARCODE_256_PICC,

	/* NFC-IP1 Device Types */
	NET_NFC_NFCIP1_TARGET,
	NET_NFC_NFCIP1_INITIATOR,

} net_nfc_target_type_e;

/**
 Card states for nfc tag
 */
typedef enum
{
	NET_NFC_NDEF_CARD_INVALID = 0x00, /**<  The card is not NFC forum specified tag. The ndef format will be needed. */
	NET_NFC_NDEF_CARD_INITIALISED, /**< The card is NFC forum specified tag, but It has no actual data. So, the ndef write will be needed. */
	NET_NFC_NDEF_CARD_READ_WRITE, /**<  The card is NFC forum specified tag. The ndef read and write will be allowed. */
	NET_NFC_NDEF_CARD_READ_ONLY /**< The card is NFC forum specified tag, but only the ndef read will be allowed. */
} net_nfc_ndef_card_state_e;

/**
 Encoding type for string message
 */
typedef enum
{
	NET_NFC_ENCODE_UTF_8 = 0x00,
	NET_NFC_ENCODE_UTF_16,
} net_nfc_encode_type_e;

/**
 URI scheme type defined in the NFC forum  "URI Record Type Definition"
 */
typedef enum
{
	NET_NFC_SCHEMA_FULL_URI = 0x00, /**< protocol is specify by payload  	*/
	NET_NFC_SCHEMA_HTTP_WWW, /**< http://www. 				*/
	NET_NFC_SCHEMA_HTTPS_WWW, /**< https://www. 				*/
	NET_NFC_SCHEMA_HTTP, /**< http:// 						*/
	NET_NFC_SCHEMA_HTTPS, /**< https://					*/
	NET_NFC_SCHEMA_TEL, /**< tel: 						*/
	NET_NFC_SCHEMA_MAILTO, /**< mailto:						*/
	NET_NFC_SCHEMA_FTP_ANONYMOUS, /**< ftp://anonymouse:anonymouse@ 	*/
	NET_NFC_SCHEMA_FTP_FTP, /**< ftp://ftp.					*/
	NET_NFC_SCHEMA_FTPS, /**< ftps://						*/
	NET_NFC_SCHEMA_SFTP, /**< sftp://						*/
	NET_NFC_SCHEMA_SMB, /**< smb://						*/
	NET_NFC_SCHEMA_NFS, /**< nfs://						*/
	NET_NFC_SCHEMA_FTP, /**< ftp://						*/
	NET_NFC_SCHEMA_DAV, /**< dav://						*/
	NET_NFC_SCHEMA_NEWS, /**< news://					*/
	NET_NFC_SCHEMA_TELNET, /**< telnet://					*/
	NET_NFC_SCHEMA_IMAP, /**< imap: 						*/
	NET_NFC_SCHEMA_RTSP, /**< rtsp://						*/
	NET_NFC_SCHEMA_URN, /**< urn: 						*/
	NET_NFC_SCHEMA_POP, /**< pop: 						*/
	NET_NFC_SCHEMA_SIP, /**< sip: 						*/
	NET_NFC_SCHEMA_SIPS, /**< sips: 						*/
	NET_NFC_SCHEMA_TFTP, /**< tftp: 						*/
	NET_NFC_SCHEMA_BTSPP, /**< btspp://					*/
	NET_NFC_SCHEMA_BTL2CAP, /**< btl2cap://					*/
	NET_NFC_SCHEMA_BTGOEP, /**< btgoep://					*/
	NET_NFC_SCHEMA_TCPOBEX, /**< tcpobex://					*/
	NET_NFC_SCHEMA_IRDAOBEX, /**< irdaobex://					*/
	NET_NFC_SCHEMA_FILE, /**< file://						*/
	NET_NFC_SCHEMA_URN_EPC_ID, /**< urn:epc:id: 					*/
	NET_NFC_SCHEMA_URN_EPC_TAG, /**< urn:epc:tag:					*/
	NET_NFC_SCHEMA_URN_EPC_PAT, /**< urn:epc:pat:					*/
	NET_NFC_SCHEMA_URN_EPC_RAW, /**< urn:epc:raw:					*/
	NET_NFC_SCHEMA_URN_EPC, /**< urn:epc: 					*/
	NET_NFC_SCHEMA_URN_NFC, /**< urn:epc:nfc:					*/
	NET_NFC_SCHEMA_MAX /**< --  indicating max--			*/
} net_nfc_schema_type_e;

// this is for target detect event filter

typedef enum
{
	NET_NFC_ALL_DISABLE = 0x0000,
	NET_NFC_ISO14443A_ENABLE = 0x0001,
	NET_NFC_ISO14443B_ENABLE = 0x0002,
	NET_NFC_ISO15693_ENABLE = 0x0004,
	NET_NFC_FELICA_ENABLE = 0x0008,
	NET_NFC_JEWEL_ENABLE = 0x0010,
	NET_NFC_IP_ENABLE = 0x0020,
	NET_NFC_ALL_ENABLE = ~0,

} net_nfc_event_filter_e;

/*
 **************************************
 LLCP defines
 **************************************
 */
/**
 These events are delivered to the each socket callback. These events are separated events that comes from "net_nfc_set_response_callback" callback
 */
typedef enum
{
	/* start number should be larger than "net_nfc_message_e"
	 because  to make seperate with net_nfc_message_e event it may conflict in
	 the dispatcher and ipc part */
	NET_NFC_MESSAGE_LLCP_LISTEN = 1000, /**< Type: Response Event <br> this event indicates "net_nfc_listen_llcp" requested is completed*/
	NET_NFC_MESSAGE_LLCP_ACCEPTED, /**< Type: Notify Event. <br>  Remote socket is accepted to listening socket
	 	 	 	 	 	 	 	 	 <br> data pointer contains the remote socket info (Cast to net_nfc_llcp_socket_option_h)*/
	NET_NFC_MESSAGE_LLCP_CONNECT, /**< Type: Response Event. <br> "net_nfc_connect_llcp_with" request is completed and your socket is connected to remote site with url*/
	NET_NFC_MESSAGE_LLCP_CONNECT_SAP, /**< Type: Response Event.<br>  "net_nfc_connect_llcp_with_sap" request is completed and your socket is connected to remote site with sap number*/
	NET_NFC_MESSAGE_LLCP_SEND, /**< Type: Response Event,<br>  "net_nfc_send_llcp" operation is completed (connection mode)*/
	NET_NFC_MESSAGE_LLCP_SEND_TO, /**< Type: Response Event,<br>  "net_nfc_send_llcp_to"operation is completed (connectionless mode)*/
	NET_NFC_MESSAGE_LLCP_RECEIVE, /**< Type: Response Event,<br>  "net_nfc_receive_llcp" operation is completed (connection mode)
	 	 	 	 	 	 	 	 	 <br> data pointer contains received data (Cast to data_h)*/
	NET_NFC_MESSAGE_LLCP_RECEIVE_FROM, /**< Type: Response Event,<br>  "net_nfc_receive_llcp_from" operation is completed (connectionless mode)*/
	NET_NFC_MESSAGE_LLCP_DISCONNECT, /**< Type: Response Event,<br>  "net_nfc_disconnect_llcp" request is completed */
	NET_NFC_MESSAGE_LLCP_ERROR, /**< Type: Notify Event,<br>  when the socket is disconnected, you may receive this event */
	NET_NFC_MESSAGE_LLCP_CONNECT_REQ, /**< Type: Notify Event,<br> when the peer requests connect, you may receive this event */
	NET_NFC_MESSAGE_LLCP_ACCEPT, /**< Type: Response Event <br> this event indicates "net_nfc_accept_llcp" requested is completed*/
	NET_NFC_MESSAGE_LLCP_REJECT, /**< Type: Response Event <br> this event indicates "net_nfc_reject_llcp" requested is completed*/
	NET_NFC_MESSAGE_LLCP_REJECTED, /**< Type: Notify Event,<br> when the socket is rejected, you may receive this event */
	NET_NFC_MESSAGE_LLCP_CLOSE, /**< Type: Response Event,<br>  "net_nfc_close_llcp_socket" request is completed */

} net_nfc_llcp_message_e;

typedef enum
{
	NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED,
	NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONLESS,
} net_nfc_socket_type_e;

typedef enum
{
	NET_NFC_SNEP = 0x00,
	NET_NFC_NPP,
} llcp_app_protocol_e;

typedef struct _data_s *data_h;

typedef struct _ndef_record_s *ndef_record_h;

typedef struct _ndef_message_s *ndef_message_h;

typedef struct _net_nfc_target_info_s *net_nfc_target_info_h;

typedef uint32_t net_nfc_traceive_cmd;

typedef struct _net_nfc_llcp_config_info_s *net_nfc_llcp_config_info_h;

typedef struct _net_nfc_llcp_socket_option_s *net_nfc_llcp_socket_option_h;

typedef struct _net_nfc_target_handle_s *net_nfc_target_handle_h;

typedef struct _net_nfc_connection_handover_info_s *net_nfc_connection_handover_info_h;

typedef uint8_t sap_t;

typedef uint32_t net_nfc_llcp_socket_t;

typedef void *net_nfc_snep_handle_h;

// LLCP Callback
typedef void (*net_nfc_llcp_socket_cb)(net_nfc_llcp_message_e message, net_nfc_error_e result, void *data, void *user_data, void *trans_data);

// Main Callback
typedef void (*net_nfc_response_cb)(net_nfc_message_e message, net_nfc_error_e result, void *data, void *user_param, void *trans_data);

typedef void (*net_nfc_internal_se_response_cb)(net_nfc_message_e message, net_nfc_error_e result, void *data, void *user_param, void *trans_data);

typedef void (* net_nfc_set_activation_completed_cb)(net_nfc_error_e error, void *user_data);

// handover

typedef enum
{
	NET_NFC_CONN_HANDOVER_CARRIER_BT = 0x00,
	NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS, /* Wifi Protected Setup */
#define NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS
	NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P, /* Wifi Peer-to-Peer */
#define NET_NFC_CONN_HANDOVER_CARRIER_WIFI_IBSS NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P
#define NET_NFC_CONN_HANDOVER_CARRIER_WIFI_DIRECT NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P
	NET_NFC_CONN_HANDOVER_CARRIER_BT_LE,
	NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN,
} net_nfc_conn_handover_carrier_type_e;

typedef enum
{
	NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE = 0x00,
	NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE,
	NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING,
	NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN_STATUS,
} net_nfc_conn_handover_carrier_state_e;

typedef struct _net_nfc_conn_handover_carrier_info_s *net_nfc_conn_handover_carrier_info_h;
typedef struct _net_nfc_conn_handover_info_s *net_nfc_conn_handover_info_h;

#define MIFARE_KEY_DEFAULT {(uint8_t)0xFF,(uint8_t)0xFF,(uint8_t)0xFF,(uint8_t)0xFF,(uint8_t)0xFF,(uint8_t)0xFF}
#define MIFARE_KEY_APPLICATION_DIRECTORY {(uint8_t)0xA0,(uint8_t)0xA1,(uint8_t)0xA2,(uint8_t)0xA3,(uint8_t)0xA4,(uint8_t)0xA5}
#define MIFARE_KEY_NET_NFC_FORUM {(uint8_t)0xD3,(uint8_t)0xF7,(uint8_t)0xD3,(uint8_t)0xF7,(uint8_t)0xD3,(uint8_t)0xF7}
#define MIFARE_KEY_LENGTH 6

typedef enum
{
	NET_NFC_FELICA_POLL_NO_REQUEST = 0x00,
	NET_NFC_FELICA_POLL_SYSTEM_CODE_REQUEST,
	NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST,
	NET_NFC_FELICA_POLL_MAX = 0xFF,
} net_nfc_felica_poll_request_code_e;

/**
 WIFI configuration key enums for connection handover.
 */

typedef enum
{
	NET_NFC_WIFI_ATTRIBUTE_VERSION = 0x104A,
	NET_NFC_WIFI_ATTRIBUTE_CREDENTIAL = 0x100E,
	NET_NFC_WIFI_ATTRIBUTE_NET_INDEX = 0x1026,
	NET_NFC_WIFI_ATTRIBUTE_SSID = 0x1045,
	NET_NFC_WIFI_ATTRIBUTE_AUTH_TYPE = 0x1003, /*< WPA2PSK 	0x0020 */
	NET_NFC_WIFI_ATTRIBUTE_ENC_TYPE = 0x100F, /*< AES 			0x0008 */
	NET_NFC_WIFI_ATTRIBUTE_NET_KEY = 0x1027,
	NET_NFC_WIFI_ATTRIBUTE_MAC_ADDR = 0x1020,
	NET_NFC_WIFI_ATTRIBUTE_CHANNEL = 0x1001, /* Channel number - based on IEEE */
	NET_NFC_WIFI_ATTRIBUTE_VEN_EXT = 0x1049,
	NET_NFC_WIFI_ATTRIBUTE_VERSION2 = 0x00,
} net_nfc_carrier_wifi_attribute_e;

typedef enum
{
	NET_NFC_WIFI_P2P_ATTRIBUTE_MANUFACTURER = 0x1021,
	NET_NFC_WIFI_P2P_ATTRIBUTE_MODEL_NAME = 0x1023,
	NET_NFC_WIFI_P2P_ATTRIBUTE_MODEL_NUMBER = 0x1024,
	NET_NFC_WIFI_P2P_ATTRIBUTE_OOB_DEVICE_PASSWORD = 0x102C,
	NET_NFC_WIFI_P2P_ATTRIBUTE_RF_BANDS = 0x103C,
	NET_NFC_WIFI_P2P_ATTRIBUTE_SERIAL_NUMBER = 0x1042,
	NET_NFC_WIFI_P2P_ATTRIBUTE_UUID_E = 0x1047,
	NET_NFC_WIFI_P2P_ATTRIBUTE_VEN_EXT = 0x1049,

	NET_NFC_WIFI_P2P_ATTRIBUTE_CAPABILITY = 0x02,
	NET_NFC_WIFI_P2P_ATTRIBUTE_DEVICE_INFO = 0x0D,
	NET_NFC_WIFI_P2P_ATTRIBUTE_OOB_GROUP_OWNER_NEGO_CHANNEL = 0x13,
	NET_NFC_WIFI_P2P_ATTRIBUTE_CHANNEL_LIST = 0x0B,
	NET_NFC_WIFI_P2P_ATTRIBUTE_GROUP_INFO = 0x0E,
	NET_NFC_WIFI_P2P_ATTRIBUTE_GROUP_ID = 0x0F,
}
net_nfc_carrier_wifi_p2p_attribute_e;

typedef enum
{
	NET_NFC_BT_ATTRIBUTE_UUID16_PART = 0x02, /* More 16-bit UUIDs available */
	NET_NFC_BT_ATTRIBUTE_UUID16 = 0x03, /* Complete list of 16-bit UUIDs */
	NET_NFC_BT_ATTRIBUTE_UUID32_PART = 0x04, /* More 32-bit UUIDs available */
	NET_NFC_BT_ATTRIBUTE_UUID32 = 0x05, /* Complete list of 32-bit UUIDs */
	NET_NFC_BT_ATTRIBUTE_UUID128_PART = 0x06, /* More 128-bit UUIDs available */
	NET_NFC_BT_ATTRIBUTE_UUID128 = 0x07, /* Complete list of 128-bit UUIDs */
	NET_NFC_BT_ATTRIBUTE_NAME_PART = 0x08, /* Shortened local name */
	NET_NFC_BT_ATTRIBUTE_NAME = 0x09, /* Complete local name */
	NET_NFC_BT_ATTRIBUTE_TXPOWER = 0x0a, /* TX Power level */
	NET_NFC_BT_ATTRIBUTE_OOB_COD = 0x0d, /* SSP OOB Class of Device */
	NET_NFC_BT_ATTRIBUTE_OOB_HASH_C = 0x0e, /* SSP OOB Hash C */
	NET_NFC_BT_ATTRIBUTE_OOB_HASH_R = 0x0f, /* SSP OOB Randomizer R */
	NET_NFC_BT_ATTRIBUTE_ID = 0x10, /* Device ID */
	NET_NFC_BT_ATTRIBUTE_MANUFACTURER = 0xFF, /* Manufacturer Specific Data */
	NET_NFC_BT_ATTRIBUTE_ADDRESS = 0xF0, /* Bluetooth device Address */
} net_nfc_handover_bt_attribute_e;

typedef struct _net_nfc_carrier_config_s *net_nfc_carrier_config_h;
typedef struct _net_nfc_carrier_property_s *net_nfc_property_group_h;

typedef struct _net_nfc_ch_message_s *net_nfc_ch_message_h;
typedef struct _net_nfc_ch_carrier_s *net_nfc_ch_carrier_h;

typedef enum
{
	NET_NFC_SE_TYPE_NONE = 0x00,/**< Invalid */
	NET_NFC_SE_TYPE_ESE = 0x01,/**< SmartMX */
	NET_NFC_SE_TYPE_UICC = 0x02,/**< UICC */
	NET_NFC_SE_TYPE_SDCARD = 0x03, /* SDCard type is not currently supported */
	NET_NFC_SE_TYPE_HCE = 0x04, /* SDCard type is not currently supported */
} net_nfc_se_type_e;

 typedef enum
 {
	NET_NFC_SE_INVALID_ENTRY = 0x00, /**< Indicates SE type is Invalid */
	NET_NFC_SE_TECH_ENTRY = 0x01, /*Technology*/
	NET_NFC_SE_PROTOCOL_ENTRY = 0x02, /*Protocol*/
} net_nfc_se_entry_type_e;

typedef enum
{
	NET_NFC_SE_INVALID_TECH_PROTO = 0x00, /**< Indicates SE type is Invalid */
	NET_NFC_SE_TECH_A_ISODEP = 0x01,/*Type A /ISO DEP*/
	NET_NFC_SE_TECH_B_NFCDEP = 0x02,/*Type B / NFC DEP*/
	NET_NFC_SE_TECH_A_B_ISO_NFC_DEP = 0x03,/*Type B / NFC DEP*/
	NET_NFC_SE_TECH_F = 0x04,/*Type F*/
} net_nfc_se_tech_protocol_type_e;

typedef enum
{
	NET_NFC_SE_INVALID = 0x00, /**< Indicates SE type is Invalid */
	NET_NFC_SE_SWITCH_ON = 0x01,/* Target On*/
	NET_NFC_SE_SWITCH_OFF = 0x02,/*Target Off*/
	NET_NFC_SE_SCREEN_OFF = 0x08,
	NET_NFC_SE_SCREEN_ON_LOCK = 0x10,
	NET_NFC_SE_SCREEN_ON_UNLOCK = 0x20,
} net_nfc_se_power_state_type_e;

typedef enum
{
	NET_NFC_SIGN_TYPE_NO_SIGN = 0,
	NET_NFC_SIGN_TYPE_PKCS_1,
	NET_NFC_SIGN_TYPE_PKCS_1_V_1_5,
	NET_NFC_SIGN_TYPE_DSA,
	NET_NFC_SIGN_TYPE_ECDSA,
	NET_NFC_MAX_SIGN_TYPE,
} net_nfc_sign_type_t;

typedef enum
{
	NET_NFC_CERT_FORMAT_X_509 = 0,
	NET_NFC_CERT_FORMAT_X9_86,
	NET_NFC_MAX_CERT_FORMAT,
} net_nfc_cert_format_t;

typedef enum
{
	NET_NFC_SNEP_GET = 1,
	NET_NFC_SNEP_PUT = 2,
} net_nfc_snep_type_t;

typedef enum
{
	NET_NFC_LLCP_REGISTERED = -1,
	NET_NFC_LLCP_UNREGISTERED = -2,
	NET_NFC_LLCP_START  = -3,
	NET_NFC_LLCP_STOP  = -4,
}
net_nfc_llcp_state_t;

typedef enum
{
	NET_NFC_CARD_EMULATION_DISABLE = 0,
	NET_NFC_CARD_EMELATION_ENABLE
}
net_nfc_card_emulation_mode_t;

typedef enum
{
	NET_NFC_HCE_EVENT_DEACTIVATED = 0,
	NET_NFC_HCE_EVENT_ACTIVATED = 1,
	NET_NFC_HCE_EVENT_APDU_RECEIVED = 2,
}
net_nfc_hce_event_t;

typedef enum
{
	NET_NFC_CARD_EMULATION_CATEGORY_UNKNOWN = 0,
	NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT = 1,
	NET_NFC_CARD_EMULATION_CATEGORY_OTHER = 2,
	NET_NFC_CARD_EMULATION_CATEGORY_MAX = 3,
}
net_nfc_card_emulation_category_t;

#ifdef __cplusplus
}
#endif

/**
 @}
 */

#endif //__NET_NFC_TYPEDEF_H__
