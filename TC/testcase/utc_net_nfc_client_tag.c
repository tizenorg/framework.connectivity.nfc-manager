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

#include "net_nfc_typedef_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc.h"


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_format_ndef_p(void);
static void utc_net_nfc_format_ndef_n(void);
static void utc_net_nfc_set_tag_filter_p(void);
static void utc_net_nfc_set_tag_filter_n(void);
static void utc_net_nfc_get_tag_filter_p(void);
static void utc_net_nfc_get_tag_filter_n(void);
static void utc_net_nfc_transceive_p(void);
static void utc_net_nfc_transceive_n(void);
static void utc_net_nfc_read_ndef_p(void);
static void utc_net_nfc_read_ndef_n(void);
static void utc_net_nfc_write_ndef_p(void);
static void utc_net_nfc_write_ndef_n(void);
static void utc_net_nfc_make_read_only_ndef_tag_p(void);
static void utc_net_nfc_make_read_only_ndef_tag_n(void);


struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_format_ndef_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_format_ndef_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_set_tag_filter_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_set_tag_filter_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_get_tag_filter_p, 1},
	{ utc_net_nfc_get_tag_filter_n, 2 },
	{ utc_net_nfc_transceive_p, 1},
	{ utc_net_nfc_transceive_n, 2},
	{ utc_net_nfc_read_ndef_p, 1},
	{ utc_net_nfc_read_ndef_n, 2},
	{ utc_net_nfc_write_ndef_p, 1},
	{ utc_net_nfc_write_ndef_n, 2},
	{ utc_net_nfc_make_read_only_ndef_tag_p, 1},
	{ utc_net_nfc_make_read_only_ndef_tag_n, 2},
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

static void utc_net_nfc_format_ndef_p(void)
{
	int ret=0;
	data_h key;
	uint8_t data [] = {0xff,0xff,0xff,0xff,0xff,0xff};

	net_nfc_initialize();

	net_nfc_create_data (&key, data, 6);

	ret = net_nfc_format_ndef((net_nfc_target_handle_h) 0x302023, key, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_format_ndef_n(void)
{
	int ret=0;

	ret = net_nfc_format_ndef(NULL, NULL, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_set_tag_filter_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_set_tag_filter(NET_NFC_ISO14443A_ENABLE);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_set_tag_filter_n(void)
{
	int ret=0;
	net_nfc_event_filter_e config = NET_NFC_ALL_ENABLE;

	ret = net_nfc_set_tag_filter(config);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_filter_p(void)
{
	net_nfc_event_filter_e ret=0;

	net_nfc_initialize();

	net_nfc_set_tag_filter(NET_NFC_ISO14443A_ENABLE);

	ret = net_nfc_get_tag_filter();

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_filter_n(void)
{
	net_nfc_event_filter_e ret=0;

	ret = net_nfc_get_tag_filter();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_transceive_p(void)
{
	int ret ;
	net_nfc_target_handle_h handle = NULL;
	void* trans_param = NULL;
	unsigned char send_buffer[6] = {0x00, };

	send_buffer[0] = 0x06;
	send_buffer[1] = 0x00;

	// use wild card for system code
	send_buffer[2] = 0xff;
	send_buffer[3] = 0xff;

	send_buffer[4] = 0xff;
	send_buffer[5] = 0xff;

	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = 6;

	ret = net_nfc_transceive(handle, (data_h)&rawdata, trans_param);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_transceive_n(void)
{
	int ret ;

	ret = net_nfc_transceive(NULL, NULL, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_read_ndef_p(void)
{
	int ret ;

	ret = net_nfc_read_tag((net_nfc_target_handle_h) 0x302023, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_read_ndef_n(void)
{
	int ret ;

	ret = net_nfc_read_tag(NULL, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_write_ndef_p(void)
{
	int ret ;
	ndef_message_h message = NULL;
	ndef_record_h record = NULL;

	net_nfc_initialize();

	net_nfc_create_ndef_message (&message);
	net_nfc_create_text_type_record (&record, "abc" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	net_nfc_append_record_to_ndef_message (message ,record);

	ret = net_nfc_write_ndef ((net_nfc_target_handle_h)0x302023 ,message ,NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_write_ndef_n(void)
{
	int ret ;

	ret = net_nfc_write_ndef(NULL, NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_make_read_only_ndef_tag_p(void)
{
	int ret ;

	net_nfc_initialize();

	ret = net_nfc_make_read_only_ndef_tag ((net_nfc_target_handle_h)0x302023 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_make_read_only_ndef_tag_n(void)
{
	int ret;

	ret = net_nfc_make_read_only_ndef_tag(NULL , NULL);

	dts_pass(__func__, "PASS");
}
