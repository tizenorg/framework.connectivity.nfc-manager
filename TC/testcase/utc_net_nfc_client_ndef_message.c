/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
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


#include <tet_api.h>
#include <stdint.h>

#include "net_nfc_ndef_message.h"
#include "net_nfc_util_private.h"
#include "net_nfc.h" // to use net_nfc_data


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_create_ndef_message_p(void);
static void utc_net_nfc_create_ndef_message_n(void);
static void utc_net_nfc_create_rawdata_from_ndef_message_p(void);
static void utc_net_nfc_create_rawdata_from_ndef_message_n(void);
static void utc_net_nfc_create_ndef_message_from_rawdata_p(void);
static void utc_net_nfc_create_ndef_message_from_rawdata_n(void);
static void utc_net_nfc_get_ndef_message_byte_length_p(void);
static void utc_net_nfc_get_ndef_message_byte_length_n(void);
static void utc_net_nfc_append_record_to_ndef_message_p(void);
static void utc_net_nfc_append_record_to_ndef_message_n(void);
static void utc_net_nfc_free_ndef_message_p(void);
static void utc_net_nfc_free_ndef_message_n(void);
static void utc_net_nfc_get_ndef_message_record_count_p(void);
static void utc_net_nfc_get_ndef_message_record_count_n(void);




struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_create_ndef_message_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_create_ndef_message_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_create_rawdata_from_ndef_message_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_create_rawdata_from_ndef_message_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_create_ndef_message_from_rawdata_p, 1},
	{ utc_net_nfc_create_ndef_message_from_rawdata_n, 2 },
	{ utc_net_nfc_get_ndef_message_byte_length_p, 1},
	{ utc_net_nfc_get_ndef_message_byte_length_n, 2},
	{ utc_net_nfc_append_record_to_ndef_message_p, 1},
	{ utc_net_nfc_append_record_to_ndef_message_n, 2},
	{ utc_net_nfc_free_ndef_message_p, 1},
	{ utc_net_nfc_free_ndef_message_n, 2},
	{ utc_net_nfc_get_ndef_message_record_count_p, 1},
	{ utc_net_nfc_get_ndef_message_record_count_n, 2},
	{ NULL, 0 },
};

//this method is called only once in start
static void startup(void)
{
	/* start of TC */
}

static void cleanup(void)
{
	/* end of TC */
}
static void utc_net_nfc_create_ndef_message_p(void)
{
	int ret ;
	ndef_message_h message;

	ret = net_nfc_create_ndef_message(&message);
	net_nfc_free_ndef_message(message);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_ndef_message is failed");
}

static void utc_net_nfc_create_ndef_message_n(void)
{
	int ret=0;

	ret = net_nfc_create_ndef_message( NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_ndef_message not allow null");
}

static void utc_net_nfc_create_rawdata_from_ndef_message_p(void)
{
	int ret ;
	char url[] = "samsung.com";
	ndef_record_h record = NULL;
	ndef_message_h msg = NULL;
	data_h rawdata = NULL;

	net_nfc_create_uri_type_record(&record, url, NET_NFC_SCHEMA_HTTPS_WWW);

	net_nfc_create_ndef_message(&msg);

	net_nfc_append_record_to_ndef_message(msg, record);

	ret = net_nfc_create_rawdata_from_ndef_message (msg, &rawdata);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_rawdata_from_ndef_message is failed");
}

static void utc_net_nfc_create_rawdata_from_ndef_message_n(void)
{
	int ret ;

	ret = net_nfc_create_rawdata_from_ndef_message (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_rawdata_from_ndef_message not allow null");
}

static void utc_net_nfc_create_ndef_message_from_rawdata_p(void)
{
	int ret ;
	uint8_t url[] = "samsung.com";
	ndef_message_s* msg = NULL;
	data_s* rawdata = NULL;

	rawdata = calloc(1, sizeof(data_s));
	msg = calloc(1, sizeof(ndef_message_s));

	rawdata->buffer = url;
	rawdata->length = 11;

	ret = net_nfc_create_ndef_message_from_rawdata ((ndef_message_h*)msg, (data_h)rawdata);

	net_nfc_free_ndef_message((ndef_message_h)msg);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_ndef_message_from_rawdata is failed");
}

static void utc_net_nfc_create_ndef_message_from_rawdata_n(void)
{
	int ret ;

	ret = net_nfc_create_ndef_message_from_rawdata (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK,"net_nfc_create_ndef_message_from_rawdata not allow null");
}

static void utc_net_nfc_get_ndef_message_byte_length_p(void)
{
	int ret ;
	char url[] = "samsung.com";
	ndef_record_h record = NULL;
	ndef_message_h msg = NULL;
	uint32_t length = 0;

	net_nfc_create_uri_type_record(&record, url, NET_NFC_SCHEMA_HTTPS_WWW);

	net_nfc_create_ndef_message(&msg);

	net_nfc_append_record_to_ndef_message(msg, record);

	ret = net_nfc_get_ndef_message_byte_length( msg , &length);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_ndef_message_byte_length is failed");
}

static void utc_net_nfc_get_ndef_message_byte_length_n(void)
{
	int ret ;

	ret = net_nfc_get_ndef_message_byte_length (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK,"net_nfc_get_ndef_message_byte_length not allow null");
}

static void utc_net_nfc_append_record_to_ndef_message_p(void)
{
	int ret ;
	char url[] = "samsung.com";
	ndef_record_h record = NULL;
	ndef_message_h msg = NULL;

	net_nfc_create_uri_type_record(&record, url, NET_NFC_SCHEMA_HTTPS_WWW);

	net_nfc_create_ndef_message(&msg);

	ret = net_nfc_append_record_to_ndef_message(msg, record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_append_record_to_ndef_message is failed");
}

static void utc_net_nfc_append_record_to_ndef_message_n(void)
{
	int ret ;

	ret = net_nfc_append_record_to_ndef_message (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK,"net_nfc_append_record_to_ndef_message not allow null");
}

static void utc_net_nfc_free_ndef_message_p(void)
{
	int ret ;
	ndef_message_h message;

	net_nfc_create_ndef_message(&message);
	ret = net_nfc_free_ndef_message(message);

	dts_check_eq(__func__, ret, NET_NFC_OK, "utc_net_nfc_free_ndef_message_n is failed");
}

static void utc_net_nfc_free_ndef_message_n(void)
{
	int ret=0;

	ret = net_nfc_free_ndef_message( NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "utc_net_nfc_free_ndef_message_n not allow null");
}

static void utc_net_nfc_get_ndef_message_record_count_p(void)
{
	int ret ;
	char url[] = "samsung.com";
	ndef_record_h record = NULL;
	ndef_message_h msg = NULL;
	int count = 0;

	net_nfc_create_uri_type_record(&record, url, NET_NFC_SCHEMA_HTTPS_WWW);

	net_nfc_create_ndef_message(&msg);

	net_nfc_append_record_to_ndef_message(msg, record);

	ret = net_nfc_get_ndef_message_record_count( msg , &count );

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_ndef_message_record_count is failed");
}

static void utc_net_nfc_get_ndef_message_record_count_n(void)
{
	int ret=0;

	ret = net_nfc_get_ndef_message_record_count( NULL , NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_ndef_message_record_count not allow null");
}
