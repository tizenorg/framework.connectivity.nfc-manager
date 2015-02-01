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
#ifndef __NET_NFC_UTIL_HANDOVER_H__
#define __NET_NFC_UTIL_HANDOVER_H__

#include "net_nfc_typedef_internal.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CH_MAJOR_VER		1
#define CH_MINOR_VER		2
#define CH_VERSION		((CH_MAJOR_VER << 4) | CH_MINOR_VER)

#define CH_SAN			"urn:nfc:sn:handover"
#define CH_SAP			0x11	/* assign connection handover service access point */

#define CH_REQ_RECORD_TYPE	"Hr"
#define CH_REQ_RECORD_TYPE_LEN	2
#define CH_SEL_RECORD_TYPE	"Hs"
#define CH_SEL_RECORD_TYPE_LEN	2
#define CH_CAR_RECORD_TYPE	"Hc"
#define CH_CAR_RECORD_TYPE_LEN	2
#define CH_MED_RECORD_TYPE	"Hm"
#define CH_MED_RECORD_TYPE_LEN	2
#define CH_INI_RECORD_TYPE	"Hi"
#define CH_INI_RECORD_TYPE_LEN	2
#define CH_CR_RECORD_TYPE	"cr"
#define CH_CR_RECORD_TYPE_LEN	2
#define CH_AC_RECORD_TYPE	"ac"
#define CH_AC_RECORD_TYPE_LEN	2
#define CH_ERR_RECORD_TYPE	"err"
#define CH_ERR_RECORD_TYPE_LEN	3

#define CH_WIFI_WPS_MIME	"application/vnd.wfa.wsc"
#define CH_WIFI_WPS_MIME_LEN	23
#define CH_WIFI_BSS_MIME	CH_WIFI_WPS_MIME
#define CH_WIFI_P2P_MIME	"application/vnd.wfa.p2p"
#define CH_WIFI_P2P_MIME_LEN	23
#define CH_WIFI_IBSS_MIME	CH_WIFI_P2P_MIME
#define CH_WIFI_DIRECT_MIME	CH_WIFI_P2P_MIME

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
	uint32_t length;
	struct _GNode *data;
} net_nfc_carrier_config_s;


typedef enum
{
	NET_NFC_CH_TYPE_UNKNOWN,
	NET_NFC_CH_TYPE_REQUEST,
	NET_NFC_CH_TYPE_SELECT,
	NET_NFC_CH_TYPE_MEDIATION,
	NET_NFC_CH_TYPE_INITIAITE,
	NET_NFC_CH_TYPE_MAX,
}
net_nfc_ch_type_e;

typedef struct _net_nfc_ch_carrier_s
{
	net_nfc_conn_handover_carrier_type_e type;
	net_nfc_conn_handover_carrier_state_e cps;
	ndef_record_s *carrier_record;
	struct _GList *aux_records;
}
net_nfc_ch_carrier_s;

typedef struct _net_nfc_ch_message_s
{
	net_nfc_ch_type_e type;
	uint8_t version;
	uint16_t cr;
	struct _GList *carriers;
}
net_nfc_ch_message_s;

net_nfc_error_e net_nfc_util_create_carrier_config(
	net_nfc_carrier_config_s **config,
	net_nfc_conn_handover_carrier_type_e type);

net_nfc_error_e net_nfc_util_add_carrier_config_property(
	net_nfc_carrier_config_s *config,
	uint16_t attribute, uint16_t size, uint8_t *data);

net_nfc_error_e net_nfc_util_remove_carrier_config_property(
	net_nfc_carrier_config_s *config, uint16_t attribute);

net_nfc_error_e net_nfc_util_get_carrier_config_property(
	net_nfc_carrier_config_s *config,
	uint16_t attribute, uint16_t *size, uint8_t **data);

net_nfc_error_e net_nfc_util_append_carrier_config_group(
	net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group);

net_nfc_error_e net_nfc_util_remove_carrier_config_group(
	net_nfc_carrier_config_s *config, net_nfc_carrier_property_s *group);

net_nfc_error_e net_nfc_util_get_carrier_config_group(
	net_nfc_carrier_config_s *config, uint16_t attribute,
	net_nfc_carrier_property_s **group);

net_nfc_error_e net_nfc_util_free_carrier_config(
	net_nfc_carrier_config_s *config);


net_nfc_error_e net_nfc_util_create_carrier_config_group(
	net_nfc_carrier_property_s **group, uint16_t attribute);

net_nfc_error_e net_nfc_util_add_carrier_config_group_property(
	net_nfc_carrier_property_s *group,
	uint16_t attribute, uint16_t size, uint8_t *data);

net_nfc_error_e net_nfc_util_get_carrier_config_group_property(
	net_nfc_carrier_property_s *group,
	uint16_t attribute, uint16_t *size, uint8_t **data);

net_nfc_error_e net_nfc_util_remove_carrier_config_group_property(
	net_nfc_carrier_property_s *group, uint16_t attribute);

net_nfc_error_e net_nfc_util_free_carrier_group(
	net_nfc_carrier_property_s *group);

net_nfc_error_e net_nfc_util_create_ndef_record_with_carrier_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_util_create_carrier_config_from_config_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record);

net_nfc_error_e net_nfc_util_create_carrier_config_from_carrier(
	net_nfc_carrier_config_s **config, net_nfc_ch_carrier_s *carrier);

net_nfc_error_e net_nfc_util_create_handover_error_record(
	ndef_record_s **record, uint8_t reason, uint32_t data);


net_nfc_error_e net_nfc_util_create_handover_carrier(
	net_nfc_ch_carrier_s **carrier,
	net_nfc_conn_handover_carrier_state_e cps);

net_nfc_error_e net_nfc_util_duplicate_handover_carrier(
	net_nfc_ch_carrier_s **dest,
	net_nfc_ch_carrier_s *src);

net_nfc_error_e net_nfc_util_free_handover_carrier(
	net_nfc_ch_carrier_s *carrier);

net_nfc_error_e net_nfc_util_set_handover_carrier_cps(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_state_e cps);

net_nfc_error_e net_nfc_util_get_handover_carrier_cps(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_state_e *cps);

net_nfc_error_e net_nfc_util_set_handover_carrier_type(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_type_e type);

net_nfc_error_e net_nfc_util_get_handover_carrier_type(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_conn_handover_carrier_type_e *type);

net_nfc_error_e net_nfc_util_append_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s *record);

net_nfc_error_e net_nfc_util_get_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s **record);

net_nfc_error_e net_nfc_util_remove_handover_carrier_record(
	net_nfc_ch_carrier_s *carrier);

net_nfc_error_e net_nfc_util_append_handover_auxiliary_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s *record);

net_nfc_error_e net_nfc_util_get_handover_auxiliary_record_count(
	net_nfc_ch_carrier_s *carrier, uint32_t *count);

net_nfc_error_e net_nfc_util_get_handover_auxiliary_record(
	net_nfc_ch_carrier_s *carrier, int index, ndef_record_s **record);

net_nfc_error_e net_nfc_util_remove_handover_auxiliary_record(
	net_nfc_ch_carrier_s *carrier, ndef_record_s *record);


net_nfc_error_e net_nfc_util_create_handover_message(
	net_nfc_ch_message_s **message);

net_nfc_error_e net_nfc_util_free_handover_message(
	net_nfc_ch_message_s *message);

net_nfc_error_e net_nfc_util_set_handover_message_type(
	net_nfc_ch_message_s *message, net_nfc_ch_type_e type);

net_nfc_error_e net_nfc_util_get_handover_message_type(
	net_nfc_ch_message_s *message, net_nfc_ch_type_e *type);

net_nfc_error_e net_nfc_util_get_handover_random_number(
	net_nfc_ch_message_s *message, uint16_t *random_number);

net_nfc_error_e net_nfc_util_append_handover_carrier(
	net_nfc_ch_message_s *message, net_nfc_ch_carrier_s *carrier);

net_nfc_error_e net_nfc_util_get_handover_carrier_count(
	net_nfc_ch_message_s *message, uint32_t *count);

net_nfc_error_e net_nfc_util_get_handover_carrier(
	net_nfc_ch_message_s *message, int index,
	net_nfc_ch_carrier_s **carrier);

net_nfc_error_e net_nfc_util_get_handover_carrier_by_type(
	net_nfc_ch_message_s *message,
	net_nfc_conn_handover_carrier_type_e type,
	net_nfc_ch_carrier_s **carrier);


net_nfc_error_e net_nfc_util_export_handover_to_ndef_message(
	net_nfc_ch_message_s *message, ndef_message_s **result);

net_nfc_error_e net_nfc_util_import_handover_from_ndef_message(
	ndef_message_s *msg, net_nfc_ch_message_s **result);

net_nfc_error_e net_nfc_util_get_handover_random_number(
	net_nfc_ch_message_s *message, uint16_t *random_number);

net_nfc_error_e net_nfc_util_get_selector_power_status(
	net_nfc_ch_message_s *message,
	net_nfc_conn_handover_carrier_state_e *cps);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_UTIL_HANDOVER_H__
