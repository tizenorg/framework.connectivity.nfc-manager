/*
 * Copyright (C) 2010 NXP Semiconductors
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __NET_NFC_INTERNAL_TYPEDEF_H__
#define __NET_NFC_INTERNAL_TYPEDEF_H__

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

typedef struct _net_nfc_sIso14443AInfo_t
{
	uint8_t Uid[NET_NFC_MAX_UID_LENGTH]; /**< UID information of the TYPE A Tag Discovered */
	uint8_t UidLength; /**< UID information length, shall not be greater  than NET_NFC_MAX_UID_LENGTH i.e., 10 */
	uint8_t AppData[NET_NFC_MAX_ATR_LENGTH]; /**< Application data information of the tag discovered (= Historical bytes for type A) */
	uint8_t AppDataLength; /**< Application data length */
	uint8_t Sak; /**< SAK informationof the TYPE A Tag Discovered */
	uint8_t AtqA[NET_NFC_ATQA_LENGTH]; /**< ATQA informationof the TYPE A Tag Discovered */
	uint8_t MaxDataRate; /**< Maximum data rate supported by the TYPE A Tag Discovered */
	uint8_t Fwi_Sfgt; /**< Frame waiting time and start up frame guard time as defined in ISO/IEC 14443-4[7] for type A */
} net_nfc_sIso14443AInfo_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief Remote Device Reader B RF Gate Information Container
 *
 *  The <em> Reader B structure </em> includes the available information
 *  related to the discovered ISO14443B remote device. This information
 *  is updated for every device discovery.
 *  \note None.
 *
 */
typedef struct _net_nfc_sIso14443BInfo_t
{
	union net_nfc_uAtqBInfo
	{
		struct net_nfc_sAtqBInfo
		{
			uint8_t Pupi[NET_NFC_PUPI_LENGTH]; /**< PUPI information  of the TYPE B Tag Discovered */
			uint8_t AppData[NET_NFC_APP_DATA_B_LENGTH]; /**< Application Data  of the TYPE B Tag Discovered */
			uint8_t ProtInfo[NET_NFC_PROT_INFO_B_LENGTH]; /**< Protocol Information  of the TYPE B Tag Discovered */
		} AtqResInfo;
		uint8_t AtqRes[NET_NFC_ATQB_LENGTH]; /**< ATQB Response Information of TYPE B Tag Discovered */
	} AtqB;

	uint8_t HiLayerResp[NET_NFC_MAX_ATR_LENGTH]; /**< Higher Layer Response information in answer to ATRRIB Command for Type B */
	uint8_t HiLayerRespLength; /**< Higher Layer Response length */
	uint8_t Afi; /**< Application Family Identifier of TYPE B Tag Discovered */
	uint8_t MaxDataRate; /**< Maximum data rate supported by the TYPE B Tag Discovered */
} net_nfc_sIso14443BInfo_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief Remote Device Reader B prime RF Gate Information Container
 *
 */
typedef struct _net_nfc_sIso14443BPrimeInfo_t
{
	void *BPrimeCtxt;
} net_nfc_sIso14443BPrimeInfo_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief Remote Device Jewel Reader RF Gate Information Container
 *
 *  The <em> Jewel Reader structure </em> includes the available information
 *  related to the discovered Jewel remote device. This information
 *  is updated for every device discovery.
 *  \note None.
 *
 */
typedef struct _net_nfc_sJewelInfo_t
{
	uint8_t Uid[NET_NFC_MAX_UID_LENGTH]; /**< UID information of the TYPE A Tag Discovered */
	uint8_t UidLength; /**< UID information length, shall not be greater than NET_NFC_MAX_UID_LENGTH i.e., 10 */
	uint8_t HeaderRom0; /**< Header Rom byte zero */
	uint8_t HeaderRom1; /**< Header Rom byte one */

} net_nfc_sJewelInfo_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief Remote Device Felica Reader RF Gate Information Container
 *
 *  The <em> Felica Reader structure </em> includes the available information
 *  related to the discovered Felica remote device. This information
 *  is updated for every device discovery.
 *  \note None.
 *
 */
typedef struct _net_nfc_sFelicaInfo_t
{
	uint8_t IDm[(NET_NFC_FEL_ID_LEN + 2)]; /**< Current ID of Felica tag */
	uint8_t IDmLength; /**< IDm length, shall not be greater than NET_NFC_FEL_ID_LEN i.e., 8 */
	uint8_t PMm[NET_NFC_FEL_PM_LEN]; /**< Current PM of Felica tag */
	uint8_t SystemCode[NET_NFC_FEL_SYS_CODE_LEN]; /**< System code of Felica tag */
} net_nfc_sFelicaInfo_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief Remote Device Reader 15693 RF Gate Information Container
 *
 *  The <em> Reader A structure </em> includes the available information
 *  related to the discovered ISO15693 remote device. This information
 *  is updated for every device discovery.
 *  \note None.
 *
 */

typedef struct _net_nfc_sIso15693Info_t
{
	uint8_t Uid[NET_NFC_15693_UID_LENGTH]; /**< UID information of the 15693 Tag Discovered */
	uint8_t UidLength; /**< UID information length, shall not be greater than NET_NFC_15693_UID_LENGTH i.e., 8 */
	uint8_t Dsfid; /**< DSF information of the 15693 Tag Discovered */
	uint8_t Flags; /**< Information about the Flags in the 15693 Tag Discovered */
	uint8_t Afi; /**< Application Family Identifier of 15693 Tag Discovered */
} net_nfc_sIso15693Info_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief NFC Data Rate Supported between the Reader and the Target
 *
 *  The <em> \ref Halnet_nfc_eDataRate enum </em> lists all the Data Rate
 *  values to be used to determine the rate at which the data is transmitted
 *  to the target.
 *
 *  \note None.
 */

/** \ingroup grp_hal_nfci
 *
 *  \brief NFCIP1 Data rates
 *
 */
typedef enum net_nfc_eDataRate_t
{
	net_nfc_eDataRate_106 = 0x00U,
	net_nfc_eDataRate_212,
	net_nfc_eDataRate_424,
	net_nfc_eDataRate_RFU
} net_nfc_eDataRate_t;

/** \ingroup grp_hal_nfci
 *
 *  \brief NFCIP1 Gate Information Container
 *
 *  The <em> NFCIP1 structure </em> includes the available information
 *  related to the discovered NFCIP1 remote device. This information
 *  is updated for every device discovery.
 *  \note None.
 *
 */
typedef struct _net_nfc_sNfcIPInfo_t
{
	/* Contains the random NFCID3I conveyed with the ATR_REQ.
	 always 10 bytes length
	 or contains the random NFCID3T conveyed with the ATR_RES.
	 always 10 bytes length */
	uint8_t NFCID[NET_NFC_MAX_UID_LENGTH];
	uint8_t NFCID_Length;
	/* ATR_RES = General bytes length, Max length = 48 bytes */
	uint8_t ATRInfo[NET_NFC_MAX_ATR_LENGTH];
	uint8_t ATRInfo_Length;
	/**< SAK information of the tag discovered */
	uint8_t SelRes;
	/**< ATQA information of the tag discovered */
	uint8_t SenseRes[NET_NFC_ATQA_LENGTH];
	/**< Is Detection Mode of the NFCIP Target Active */
	uint8_t nfcip_Active;
	/**< Maximum frame length supported by the NFCIP device */
	uint16_t MaxFrameLength;
	/**< Data rate supported by the NFCIP device */
	net_nfc_eDataRate_t nfcip_Datarate;

} net_nfc_sNfcIPInfo_t;

typedef union net_nfc_remoteDevInfo_t
{
	net_nfc_sIso14443AInfo_t Iso14443A_Info;
	net_nfc_sIso14443BInfo_t Iso14443B_Info;
	net_nfc_sIso14443BPrimeInfo_t Iso14443BPrime_Info;
	net_nfc_sNfcIPInfo_t NfcIP_Info;
	net_nfc_sFelicaInfo_t Felica_Info;
	net_nfc_sJewelInfo_t Jewel_Info;
	net_nfc_sIso15693Info_t Iso15693_Info;
} net_nfc_remoteDevInfo_t;

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

typedef enum _net_nfc_secure_element_type_e
{
	SECURE_ELEMENT_TYPE_INVALID = 0x00, /**< Indicates SE type is Invalid */
	SECURE_ELEMENT_TYPE_ESE = 0x01, /**< Indicates SE type is SmartMX */
	SECURE_ELEMENT_TYPE_UICC = 0x02, /**<Indicates SE type is   UICC */
	SECURE_ELEMENT_TYPE_UNKNOWN = 0x03 /**< Indicates SE type is Unknown */
} net_nfc_secure_element_type_e;

typedef struct _net_nfc_se_event_info_s
{
	data_s aid;
	data_s param;
	bool fg_dispatch;
	pid_t focus_app_pid;
	net_nfc_secure_element_type_e se_type;
}net_nfc_se_event_info_s;

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

#ifdef BROADCAST_MESSAGE
typedef struct _net_nfc_server_received_message_s
{
	int mes_type;
	int client_fd;
	struct _net_nfc_server_received_message_s *next;
}net_nfc_server_received_message_s;
#endif

typedef enum _client_state_e
{
	NET_NFC_CLIENT_INACTIVE_STATE = 0x00,
	NET_NFC_CLIENT_ACTIVE_STATE,
} client_state_e;

typedef enum _net_nfc_launch_popup_state_e
{
	NET_NFC_LAUNCH_APP_SELECT = 0x00,
	NET_NFC_NO_LAUNCH_APP_SELECT,
} net_nfc_launch_popup_state_e;

/* server state */
#define NET_NFC_SERVER_IDLE				0
#define NET_NFC_SERVER_DISCOVERY			(1 << 1)
#define NET_NFC_TAG_CONNECTED				(1 << 2)
#define NET_NFC_SE_CONNECTED				(1 << 3)
#define NET_NFC_SNEP_CLIENT_CONNECTED	(1 << 4)
#define NET_NFC_NPP_CLIENT_CONNECTED		(1 << 5)
#define NET_NFC_SNEP_SERVER_CONNECTED	(1 << 6)
#define NET_NFC_NPP_SERVER_CONNECTED		(1 << 7)

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

typedef struct _net_nfc_request_change_client_state_t
{
	NET_NFC_REQUEST_MSG_HEADER

	client_state_e client_state;
} net_nfc_request_change_client_state_t;

typedef struct _net_nfc_request_set_launch_state_t
{
	NET_NFC_REQUEST_MSG_HEADER
	net_nfc_launch_popup_state_e set_launch_popup;
}net_nfc_request_set_launch_state_t;

typedef struct _net_nfc_request_transceive_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	struct
	{
		uint32_t dev_type;
		net_nfc_data_s trans_data;
	} info;
} net_nfc_request_transceive_t;

typedef struct _net_nfc_request_target_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	uint32_t uint_param;
	net_nfc_data_s data;
} net_nfc_request_target_t;

typedef struct _net_nfc_request_read_ndef_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
} net_nfc_request_read_ndef_t;

typedef struct _net_nfc_request_test_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	uint32_t tech;
	uint32_t rate;
} net_nfc_request_test_t;

typedef struct _net_nfc_eedata_register_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	uint32_t mode;
	uint32_t reg_id;
	net_nfc_data_s data;
} net_nfc_request_eedata_register_t;

typedef struct _net_nfc_request_make_read_only_ndef_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
} net_nfc_request_make_read_only_ndef_t;

typedef struct _net_nfc_request_is_tag_connected_t
{
	NET_NFC_REQUEST_MSG_HEADER

	void *trans_param;
} net_nfc_request_is_tag_connected_t;

typedef struct _net_nfc_request_write_ndef_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	net_nfc_data_s data;
} net_nfc_request_write_ndef_t;

typedef struct _net_nfc_request_format_ndef_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	net_nfc_data_s key;
} net_nfc_request_format_ndef_t;

typedef struct _net_nfc_request_terminate_t
{
	NET_NFC_REQUEST_MSG_HEADER

	void *object;
} net_nfc_request_terminate_t;


typedef struct _net_nfc_request_reset_mode_t
{
	NET_NFC_REQUEST_MSG_HEADER

	int mode;
} net_nfc_request_reset_mode_t;

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
}net_nfc_request_se_event_t;

typedef struct _net_nfc_request_get_current_tag_info_t
{
	NET_NFC_REQUEST_MSG_HEADER

	void *trans_param;
} net_nfc_request_get_current_tag_info_t;

typedef struct _net_nfc_request_get_current_target_handle_t
{
	NET_NFC_REQUEST_MSG_HEADER

	void *trans_param;
} net_nfc_request_get_current_target_handle_t;

typedef struct _net_nfc_request_llcp_msg_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
} net_nfc_request_llcp_msg_t;

typedef struct _net_nfc_request_p2p_send_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_exchanger_data_type_e data_type;
	net_nfc_data_s data;
} net_nfc_request_p2p_send_t;

typedef struct _net_nfc_request_accept_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t incomming_socket;
	void *trans_param;
} net_nfc_request_accept_socket_t;

typedef struct _net_nfc_request_terminate_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t llcp_socket;
} net_nfc_request_terminate_socket_t;

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

typedef struct _net_nfc_request_reject_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t incomming_socket;
	void *trans_param;
} net_nfc_request_reject_socket_t;

typedef struct _net_nfc_request_connect_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	uint16_t miu; /** The remote Maximum Information Unit */
	uint8_t rw; /** The Receive Window size (4 bits)*/
	net_nfc_socket_type_e type;
	void *trans_param;
	net_nfc_data_s service_name;
} net_nfc_request_connect_socket_t;

typedef struct _net_nfc_request_connect_sap_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	uint16_t miu; /** The remote Maximum Information Unit */
	uint8_t rw; /** The Receive Window size (4 bits)*/
	net_nfc_socket_type_e type;
	sap_t sap;
	void *trans_param;
} net_nfc_request_connect_sap_socket_t;

typedef struct _net_nfc_request_disconnect_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
} net_nfc_request_disconnect_socket_t;

typedef struct _net_nfc_request_send_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
	net_nfc_data_s data;
} net_nfc_request_send_socket_t;

typedef struct _net_nfc_request_receive_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	size_t req_length;
	void *trans_param;
} net_nfc_request_receive_socket_t;

typedef struct _net_nfc_request_send_to_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
	net_nfc_data_s data;
} net_nfc_request_send_to_socket_t;

typedef struct _net_nfc_request_receive_from_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	size_t req_length;
	void *trans_param;
} net_nfc_request_receive_from_socket_t;

typedef struct _net_nfc_request_close_socket_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
} net_nfc_request_close_socket_t;

typedef struct _net_nfc_request_config_llcp_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_config_info_s config;
	void *trans_param;
} net_nfc_request_config_llcp_t;

typedef struct _net_nfc_response_llcp_socket_error_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t oal_socket;
	net_nfc_llcp_socket_t client_socket;
	net_nfc_error_e error;
	void *trans_param;
} net_nfc_response_llcp_socket_error_t;

typedef struct _net_nfc_request_watch_dog_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t devType;
	net_nfc_target_handle_s *handle;
} net_nfc_request_watch_dog_t;

typedef struct _net_nfc_request_set_se_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint8_t se_type;
	void *trans_param;
} net_nfc_request_set_se_t;

typedef struct _net_nfc_request_get_se_t
{
	NET_NFC_REQUEST_MSG_HEADER

	void *trans_param;
} net_nfc_request_get_se_t;

typedef struct _net_nfc_request_open_internal_se_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint8_t se_type;
	void *trans_param;
} net_nfc_request_open_internal_se_t;

typedef struct _net_nfc_request_close_internal_se_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
} net_nfc_request_close_internal_se_t;

typedef struct _net_nfc_request_send_apdu_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
	net_nfc_data_s data;
} net_nfc_request_send_apdu_t;

typedef struct _net_nfc_request_get_atr_t
{
	NET_NFC_REQUEST_MSG_HEADER

	net_nfc_target_handle_s *handle;
} net_nfc_request_get_atr_t;

typedef struct _net_nfc_request_se_change_card_emulation_t
{
	NET_NFC_REQUEST_MSG_HEADER

	void *trans_param;
	uint8_t se_mode;
} net_nfc_request_se_change_card_emulation_t;

typedef struct _net_nfc_request_connection_handover_t
{
	NET_NFC_REQUEST_MSG_HEADER

	uint32_t result;
	net_nfc_target_handle_s *handle;
	net_nfc_conn_handover_carrier_type_e type;
}
net_nfc_request_connection_handover_t;

// these are messages for response
//

#define NET_NFC_RESPONSE_MSG_HEADER \
	/* DON'T MODIFY THIS CODE - BEGIN */ \
	uint32_t length; \
	uint32_t response_type; \
	uint32_t flags; \
	uint32_t user_param; \
	net_nfc_error_e result;
	/* DON'T MODIFY THIS CODE - END */

typedef struct _net_nfc_response_msg_t
{
	NET_NFC_RESPONSE_MSG_HEADER
//	int response_type; /* NET_NFC_MESSAGE :  this type should be int DON'T USE enum! Because two enum values are used net_nfc_llcp_message_e and net_nfc_message_e enum */
	void *detail_message;
} net_nfc_response_msg_t;

typedef struct _net_nfc_response_test_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
} net_nfc_response_test_t;

typedef struct _net_nfc_response_notify_t
{
	NET_NFC_RESPONSE_MSG_HEADER

} net_nfc_response_notify_t;

typedef struct _net_nfc_response_init_t
{
	NET_NFC_RESPONSE_MSG_HEADER

} net_nfc_response_init_t;

typedef struct _net_nfc_response_tag_discovered_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint32_t devType;
	uint8_t is_ndef_supported;
	uint8_t ndefCardState;
	uint32_t maxDataSize;
	uint32_t actualDataSize;
	int number_of_keys;
	data_s target_info_values;
	data_s raw_data;
} net_nfc_response_tag_discovered_t;

typedef struct _net_nfc_response_se_event_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	data_s aid;
	data_s param;
	bool fg_dispatch;
	pid_t focus_app_pid;
	net_nfc_secure_element_type_e se_type;
} net_nfc_response_se_event_t;

typedef struct _net_nfc_response_get_current_tag_info_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint32_t devType;
	uint8_t is_ndef_supported;
	uint8_t ndefCardState;
	uint32_t maxDataSize;
	uint32_t actualDataSize;
	int number_of_keys;
	data_s target_info_values;
	data_s raw_data;
	void *trans_param;
} net_nfc_response_get_current_tag_info_t;

typedef struct _net_nfc_response_get_current_target_handle_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint32_t devType;
	void *trans_param;
} net_nfc_response_get_current_target_handle_t;

typedef struct _net_nfc_response_target_detached_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint32_t devType;
} net_nfc_response_target_detached_t;

typedef struct _net_nfc_response_transceive_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
	data_s data;
} net_nfc_response_transceive_t;

typedef struct _net_nfc_response_read_ndef_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
	data_s data;
} net_nfc_response_read_ndef_t;

typedef struct _net_nfc_response_write_ndef_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
} net_nfc_response_write_ndef_t;

typedef struct _net_nfc_response_make_read_only_ndef_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
} net_nfc_response_make_read_only_ndef_t;

typedef struct _net_nfc_response_is_tag_connected_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
	net_nfc_target_type_e devType;
} net_nfc_response_is_tag_connected_t;

typedef struct _net_nfc_response_format_ndef_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
} net_nfc_response_format_ndef_t;

typedef struct _net_nfc_response_p2p_discovered_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
} net_nfc_response_p2p_discovered_t;

typedef struct _net_nfc_response_p2p_send_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	void *trans_param;
} net_nfc_response_p2p_send_t;

typedef struct _net_nfc_response_llcp_discovered_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint32_t devType;
	int number_of_keys;
	data_s target_info_values;
	net_nfc_llcp_config_info_s llcp_config_info;
} net_nfc_response_llcp_discovered_t;

typedef struct _net_nfc_response_llcp_detached_t
{
	NET_NFC_RESPONSE_MSG_HEADER

} net_nfc_response_llcp_detached_t;

typedef struct _net_nfc_response_incomming_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t oal_socket;
	net_nfc_llcp_socket_option_s option;
	net_nfc_target_handle_s *handle;
	net_nfc_llcp_socket_t incomming_socket;
} net_nfc_response_incomming_llcp_t;

typedef struct _net_nfc_response_listen_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
} net_nfc_response_listen_socket_t;

typedef struct _net_nfc_response_connect_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
} net_nfc_response_connect_socket_t;

typedef struct _net_nfc_response_connect_sap_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	net_nfc_llcp_socket_t oal_socket;
	void *trans_param;
} net_nfc_response_connect_sap_socket_t;

typedef struct _net_nfc_response_accept_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	void *trans_param;
} net_nfc_response_accept_socket_t;

typedef struct _net_nfc_response_reject_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	void *trans_param;
} net_nfc_response_reject_socket_t;

typedef struct _net_nfc_response_send_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	void *trans_param;
} net_nfc_response_send_socket_t;

typedef struct _net_nfc_response_receive_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	data_s data;
	void *trans_param;
} net_nfc_response_receive_socket_t;

typedef struct _net_nfc_response_p2p_receive_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	data_s data;
} net_nfc_response_p2p_receive_t;

typedef struct _net_nfc_response_config_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
} net_nfc_response_config_llcp_t;

typedef struct _net_nfc_response_close_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	void *trans_param;
} net_nfc_response_close_socket_t;

typedef struct _net_nfc_response_disconnect_llcp_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_llcp_socket_t client_socket;
	void *trans_param;
} net_nfc_response_disconnect_socket_t;

typedef struct _net_nfc_response_set_se_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	uint8_t se_type;
	void *trans_param;
} net_nfc_response_set_se_t;

typedef struct _net_nfc_response_get_se_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	uint8_t se_type;
	void *trans_param;
} net_nfc_response_get_se_t;

typedef struct _net_nfc_response_se_change_card_emulation_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	uint8_t se_mode;
	void *trans_param;
} net_nfc_response_se_change_card_emulation_t;

typedef struct _net_nfc_response_open_internal_se_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_target_handle_s *handle;
	uint8_t se_type;
	void* trans_param;
} net_nfc_response_open_internal_se_t;

typedef struct _net_nfc_response_close_internal_se_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	void *trans_param;
} net_nfc_response_close_internal_se_t;

typedef struct _net_nfc_response_send_apdu_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	data_s data;
	void *trans_param;
} net_nfc_response_send_apdu_t;

typedef struct _net_nfc_response_get_atr_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	data_s data;
} net_nfc_response_get_atr_t;

typedef struct _net_nfc_response_get_server_state_t
{
	NET_NFC_RESPONSE_MSG_HEADER

	uint32_t state;
} net_nfc_response_get_server_state_t;

typedef struct _net_nfc_response_connection_handover
{
	NET_NFC_RESPONSE_MSG_HEADER

	net_nfc_exchanger_event_e event;
	net_nfc_conn_handover_carrier_type_e type;
	data_s data;
}
net_nfc_response_connection_handover_t;

typedef struct _net_nfc_response_get_firmware_version
{
	NET_NFC_RESPONSE_MSG_HEADER

	data_s data;
}
net_nfc_response_firmware_version_t;

typedef struct _client_context
{
	void *register_user_param; /* parameter that registed in the cb register time */
	net_nfc_error_e result;
	pthread_mutex_t g_client_lock;
	net_nfc_event_filter_e filter;
#ifdef SAVE_TARGET_INFO_IN_CC
	net_nfc_target_info_s *target_info;
#endif
	bool initialized;
	int set_launch_popup;
} client_context_t;

// data exchanger
typedef struct _net_nfc_exchanger_data_s
{
	net_nfc_exchanger_data_type_e type;
	data_s binary_data; /*  this can be binary data */
} net_nfc_exchanger_data_s;

// these are messages for response

typedef void (*target_detection_listener_cb)(void *data, void *user_param);
typedef void (*se_transaction_listener_cb)(void *data, void *user_param);
typedef void (*llcp_event_listener_cb)(void *data, void *user_param);

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

typedef enum _net_nfc_secure_element_state_e
{
	SECURE_ELEMENT_ACTIVE_STATE = 0x00, /**< state of the SE is active  */
	SECURE_ELEMENT_INACTIVE_STATE = 0x01 /**< state of the SE is In active*/

} net_nfc_secure_element_state_e;

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
	NET_NFC_MESSAGE_SERVICE_DEINIT,
	NET_NFC_MESSAGE_SERVICE_STANDALONE_TARGET_DETECTED,
	NET_NFC_MESSAGE_SERVICE_SE,
	NET_NFC_MESSAGE_SERVICE_TERMINATION,
	NET_NFC_MESSAGE_SERVICE_SLAVE_TARGET_DETECTED,
	NET_NFC_MESSAGE_SERVICE_SLAVE_ESE_DETECTED,
	NET_NFC_MESSAGE_SERVICE_RESTART_POLLING_LOOP,
	NET_NFC_MESSAGE_SERVICE_LLCP_ACCEPT,
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
	NET_NFC_MESSAGE_SERVICE_LLCP_CLOSE, /**< Type: Response Event,<br>  "net_nfc_close_llcp_socket" request is completed */
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

/* WIFI Info */
typedef struct _net_nfc_carrier_property_s
{
	bool is_group;
	uint16_t attribute;
	uint16_t length;
	void *data;
} net_nfc_carrier_property_s;

typedef struct _net_nfc_carrier_config_s
{
	net_nfc_conn_handover_carrier_type_e type;
	int length;
	struct _GList *data;
} net_nfc_carrier_config_s;

typedef struct _net_nfc_sub_field_s
{
	uint16_t length;
	uint8_t value[0];
}
__attribute__((packed)) net_nfc_sub_field_s;

typedef struct _net_nfc_signature_record_s
{
	uint8_t version;
	uint8_t sign_type : 7;
	uint8_t uri_present : 1;
	net_nfc_sub_field_s signature;
}
__attribute__((packed)) net_nfc_signature_record_s;

typedef struct _net_nfc_certificate_chain_s
{
	uint8_t num_of_certs : 4;
	uint8_t cert_format : 3;
	uint8_t uri_present : 1;
	uint8_t cert_store[0];
}
__attribute__((packed)) net_nfc_certificate_chain_s;

#define SMART_POSTER_RECORD_TYPE "Sp"
#define URI_RECORD_TYPE "U"
#define TEXT_RECORD_TYPE "T"
#define GC_RECORD_TYPE "Gc"
#define SIGNATURE_RECORD_TYPE "Sig"
#define CONN_HANDOVER_REQ_RECORD_TYPE "Hr"
#define CONN_HANDOVER_SEL_RECORD_TYPE "Hs"
#define CONN_HANDOVER_CAR_RECORD_TYPE "Hc"
#define COLLISION_DETECT_RECORD_TYPE "cr"
#define ALTERNATIVE_RECORD_TYPE "ac"
#define ERROR_RECORD_TYPE "err"

#define URI_SCHEM_FILE "file://"

#define UICC_TARGET_HANDLE 0xFF


#endif
