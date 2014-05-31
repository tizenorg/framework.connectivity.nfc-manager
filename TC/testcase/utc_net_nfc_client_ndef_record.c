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

#include "net_nfc_ndef_record.h"
#include "net_nfc_ndef_message.h"
#include "net_nfc_util_private.h"
#include "net_nfc_data.h"
//#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_create_record_p(void);
static void utc_net_nfc_create_record_n(void);
static void utc_net_nfc_create_text_type_record_p(void);
static void utc_net_nfc_create_text_type_record_n(void);
static void utc_net_nfc_create_uri_type_record_p(void);
static void utc_net_nfc_create_uri_type_record_n(void);
static void utc_net_nfc_free_record_p(void);
static void utc_net_nfc_free_record_n(void);
static void utc_net_nfc_get_record_payload_p(void);
static void utc_net_nfc_get_record_payload_n(void);
static void utc_net_nfc_get_record_type_p(void);
static void utc_net_nfc_get_record_type_n(void);
static void utc_net_nfc_set_record_id_p(void);
static void utc_net_nfc_set_record_id_n(void);
static void utc_net_nfc_get_record_id_p(void);
static void utc_net_nfc_get_record_id_n(void);
static void utc_net_nfc_get_record_tnf_p(void);
static void utc_net_nfc_get_record_tnf_n(void);
static void utc_net_nfc_get_record_flags_p(void);
static void utc_net_nfc_get_record_flags_n(void);
static void utc_net_nfc_get_record_mb_p(void);
static void utc_net_nfc_get_record_mb_n(void);
static void utc_net_nfc_get_record_me_p(void);
static void utc_net_nfc_get_record_me_n(void);
static void utc_net_nfc_get_record_cf_p(void);
static void utc_net_nfc_get_record_cf_n(void);
static void utc_net_nfc_get_record_il_p(void);
static void utc_net_nfc_get_record_il_n(void);
static void utc_net_nfc_get_record_sr_p(void);
static void utc_net_nfc_get_record_sr_n(void);
static void utc_net_nfc_create_text_string_from_text_record_p(void);
static void utc_net_nfc_create_text_string_from_text_record_n(void);
static void utc_net_nfc_get_languange_code_string_from_text_record_p(void);
static void utc_net_nfc_get_languange_code_string_from_text_record_n(void);
static void utc_net_nfc_get_encoding_type_from_text_record_p(void);
static void utc_net_nfc_get_encoding_type_from_text_record_n(void);
static void utc_net_nfc_create_uri_string_from_uri_record_p(void);
static void utc_net_nfc_create_uri_string_from_uri_record_n(void);







struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_create_record_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_create_record_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_create_text_type_record_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_create_text_type_record_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_create_uri_type_record_p, 1},
	{ utc_net_nfc_create_uri_type_record_n, 2 },
	{ utc_net_nfc_free_record_p, 1},
	{ utc_net_nfc_free_record_n, 2},
	{ utc_net_nfc_get_record_payload_p, 1},
	{ utc_net_nfc_get_record_payload_n, 2},
	{ utc_net_nfc_get_record_type_p, 1},
	{ utc_net_nfc_get_record_type_n, 2},
	{ utc_net_nfc_set_record_id_p, 1},
	{ utc_net_nfc_set_record_id_n, 2},
	{ utc_net_nfc_get_record_id_p, 1},
	{ utc_net_nfc_get_record_id_n, 2},
	{ utc_net_nfc_get_record_tnf_p, 1},
	{ utc_net_nfc_get_record_tnf_n, 2},
	{ utc_net_nfc_get_record_flags_p, 1},
	{ utc_net_nfc_get_record_flags_n, 2},
	{ utc_net_nfc_get_record_mb_p, 1},
	{ utc_net_nfc_get_record_mb_n, 2},
	{ utc_net_nfc_get_record_me_p, 1},
	{ utc_net_nfc_get_record_me_n, 2},
	{ utc_net_nfc_get_record_cf_p, 1},
	{ utc_net_nfc_get_record_cf_n, 2},
	{ utc_net_nfc_get_record_il_p, 1},
	{ utc_net_nfc_get_record_il_n, 2},
	{ utc_net_nfc_get_record_sr_p, 1},
	{ utc_net_nfc_get_record_sr_n, 2},
	{ utc_net_nfc_create_text_string_from_text_record_p, 1},
	{ utc_net_nfc_create_text_string_from_text_record_n, 2},
	{ utc_net_nfc_get_languange_code_string_from_text_record_p, 1},
	{ utc_net_nfc_get_languange_code_string_from_text_record_n, 2},
	{ utc_net_nfc_get_encoding_type_from_text_record_p, 1},
	{ utc_net_nfc_get_encoding_type_from_text_record_n, 2},
	{ utc_net_nfc_create_uri_string_from_uri_record_p, 1},
	{ utc_net_nfc_create_uri_string_from_uri_record_n, 2},
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
static void utc_net_nfc_create_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	data_s* payload = NULL;
	data_s* typeName = NULL;
	uint8_t url[] = "samsung.com";
	uint8_t temp[] = "U";

	typeName = calloc(1, sizeof(data_s));
	payload = calloc(1, sizeof(data_s));

	typeName->buffer = temp;
	typeName->length = 1;

	payload->buffer = url;
	payload->length = 11;

	ret = net_nfc_create_record(&record,  NET_NFC_RECORD_WELL_KNOWN_TYPE, (data_h)typeName, NULL, (data_h)payload);

	net_nfc_free_record(record);

	free(payload);
	free(typeName);
	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_record is failed");
}

static void utc_net_nfc_create_record_n(void)
{
	int ret=0;

	ret = net_nfc_create_record( NULL , 0 , NULL , NULL , NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_record not allow null");
}

static void utc_net_nfc_create_text_type_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;

	ret = net_nfc_create_text_type_record(&record, "This is real NFC", "en-US", NET_NFC_ENCODE_UTF_8);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_text_type_record is failed");
}

static void utc_net_nfc_create_text_type_record_n(void)
{
	int ret=0;

	ret = net_nfc_create_text_type_record( NULL , NULL , NULL , 0 );

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_text_type_record not allow null");
}

static void utc_net_nfc_create_uri_type_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;

	ret = net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_uri_type_record is failed");
}

static void utc_net_nfc_create_uri_type_record_n(void)
{
	int ret=0;

	ret = net_nfc_create_uri_type_record( NULL , NULL , 0 );

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_uri_type_record not allow null");
}

static void utc_net_nfc_free_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	ret = net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_free_record is failed");
}

static void utc_net_nfc_free_record_n(void)
{
	int ret=0;

	ret = net_nfc_free_record(NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_free_record not allow null");
}

static void utc_net_nfc_get_record_payload_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	data_h payload = NULL;

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	ret = net_nfc_get_record_payload(record, &payload);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_record_payload is failed");
}

static void utc_net_nfc_get_record_payload_n(void)
{
	int ret=0;

	ret = net_nfc_get_record_payload(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_record_payload not allow null");
}

static void utc_net_nfc_get_record_type_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	data_h record_type = NULL;

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	ret = net_nfc_get_record_type(record, &record_type);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_record_type is failed");
}

static void utc_net_nfc_get_record_type_n(void)
{
	int ret=0;

	ret = net_nfc_get_record_type(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_record_type not allow null");
}

static void utc_net_nfc_set_record_id_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	data_s* id = NULL;
	uint8_t temp[] = "test";

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	id = calloc(1, sizeof(data_s));
	id->buffer = temp;
	id->length = 4;

	ret = net_nfc_set_record_id(record, (data_h)id);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_set_record_id is failed");
}

static void utc_net_nfc_set_record_id_n(void)
{
	int ret=0;

	ret = net_nfc_set_record_id(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_set_record_id not allow null");
}

static void utc_net_nfc_get_record_id_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	data_s* id = NULL;
	data_h id_data = NULL;
	uint8_t temp[] = "test";

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	id = calloc(1, sizeof(data_s));
	id->buffer = temp;
	id->length = 4;

	net_nfc_set_record_id(record, (data_h)id);

	ret = net_nfc_get_record_id(record, &id_data);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_record_id is failed");
}

static void utc_net_nfc_get_record_id_n(void)
{
	int ret=0;

	ret = net_nfc_get_record_id(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_record_id not allow null");
}

static void utc_net_nfc_get_record_tnf_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	net_nfc_record_tnf_e* tnf = NULL;

	record = calloc( 1 , sizeof(ndef_record_h));

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	tnf = calloc( 1 , sizeof(net_nfc_record_tnf_e));

	ret = net_nfc_get_record_tnf(record, tnf);

	net_nfc_free_record(record);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_record_tnf is failed");
}

static void utc_net_nfc_get_record_tnf_n(void)
{
	int ret=0;

	ret = net_nfc_get_record_tnf(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_record_tnf not allow null");
}

static void utc_net_nfc_get_record_flags_p(void)
{
	net_nfc_error_e ret=0;
	ndef_record_s* record = NULL;
	uint8_t temp = 0x80;

	record = calloc(1, sizeof(ndef_record_s));

	net_nfc_create_uri_type_record((ndef_record_h*)&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	ret = net_nfc_get_record_flags((ndef_record_h)record, &temp);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_record_flags is failed");
}

static void utc_net_nfc_get_record_flags_n(void)
{
	net_nfc_error_e ret=0;

	ret = net_nfc_get_record_flags(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_record_flags is failed");
}

static void utc_net_nfc_get_record_mb_p(void)
{
	unsigned char ret=0;
	unsigned char flag = 0x80;

	ret = net_nfc_get_record_mb (flag);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_mb_n(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_mb(0x00);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_me_p(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_me(0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_me_n(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_me(0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_cf_p(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_cf(0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_cf_n(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_cf(0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_il_p(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_il(0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_il_n(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_il(0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_sr_p(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_sr (0xff);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_record_sr_n(void)
{
	unsigned char ret=0;

	ret = net_nfc_get_record_sr(0xff);

	dts_pass(__func__, "PASS");
}
static void utc_net_nfc_create_text_string_from_text_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	char *disp_text = NULL;

	net_nfc_create_text_type_record(&record, "This is real NFC", "en-US", NET_NFC_ENCODE_UTF_8);

	ret = net_nfc_create_text_string_from_text_record (record, &disp_text);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_text_string_from_text_record is failed");
}

static void utc_net_nfc_create_text_string_from_text_record_n(void)
{
	int ret ;

	ret = net_nfc_create_text_string_from_text_record (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_text_string_from_text_record not allow null");
}

static void utc_net_nfc_get_languange_code_string_from_text_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	char* language_code_str = NULL;

	net_nfc_create_text_type_record(&record, "This is real NFC", "en-US", NET_NFC_ENCODE_UTF_8);

	ret = net_nfc_get_languange_code_string_from_text_record (record, &language_code_str);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_languange_code_string_from_text_record is failed");
}

static void utc_net_nfc_get_languange_code_string_from_text_record_n(void)
{
	int ret ;

	ret = net_nfc_get_languange_code_string_from_text_record (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_languange_code_string_from_text_record not allow null");
}

static void utc_net_nfc_get_encoding_type_from_text_record_p(void)
{
	int ret ;
	ndef_record_h record = NULL;
	net_nfc_encode_type_e utf;

	net_nfc_create_text_type_record(&record, "This is real NFC", "en-US", NET_NFC_ENCODE_UTF_8);

	ret = net_nfc_get_encoding_type_from_text_record (record, &utf);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_encoding_type_from_text_record is failed");
}

static void utc_net_nfc_get_encoding_type_from_text_record_n(void)
{
	int ret ;

	ret = net_nfc_get_encoding_type_from_text_record (NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_encoding_type_from_text_record not allow null");
}

static void utc_net_nfc_create_uri_string_from_uri_record_p(void)
{
	int ret=0;
	ndef_record_h record = NULL;
	char *disp_text = NULL;

	net_nfc_create_uri_type_record(&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);

	net_nfc_create_uri_string_from_uri_record(record, &disp_text);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_uri_string_from_uri_record is failed");
}

static void utc_net_nfc_create_uri_string_from_uri_record_n(void)
{
	int ret=0;

	ret = net_nfc_create_uri_string_from_uri_record(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_uri_string_from_uri_record is failed");
}
