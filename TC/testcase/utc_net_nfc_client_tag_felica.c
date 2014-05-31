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

#include "net_nfc_ndef_record.h"
#include "net_nfc_ndef_message.h"
#include "net_nfc_util_private.h"
#include "net_nfc_data.h"
#include "net_nfc.h"
#include "net_nfc_tag_felica.h"


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_felica_poll_p(void);
static void utc_net_nfc_felica_poll_n(void);
static void utc_net_nfc_felica_request_service_p(void);
static void utc_net_nfc_felica_request_service_n(void);
static void utc_net_nfc_felica_request_response_p(void);
static void utc_net_nfc_felica_request_response_n(void);
static void utc_net_nfc_felica_read_without_encryption_p(void);
static void utc_net_nfc_felica_read_without_encryption_n(void);
static void utc_net_nfc_felica_write_without_encryption_p(void);
static void utc_net_nfc_felica_write_without_encryption_n(void);
static void utc_net_nfc_felica_request_system_code_p(void);
static void utc_net_nfc_felica_request_system_code_n(void);


struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_felica_poll_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_felica_poll_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_felica_request_service_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_felica_request_service_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_felica_request_response_p, 1},
	{ utc_net_nfc_felica_request_response_n, 2 },
	{ utc_net_nfc_felica_read_without_encryption_p, 1},
	{ utc_net_nfc_felica_read_without_encryption_n, 2},
	{ utc_net_nfc_felica_write_without_encryption_p, 1},
	{ utc_net_nfc_felica_write_without_encryption_n, 2},
	{ utc_net_nfc_felica_request_system_code_p, 1},
	{ utc_net_nfc_felica_request_system_code_n, 2},
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

static void utc_net_nfc_felica_poll_p(void)
{
	int ret=0;

	net_nfc_initialize();

	ret = net_nfc_felica_poll((net_nfc_target_handle_h) 0x302023, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST , 0x0 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_poll_n(void)
{
	int ret=0;
	uint8_t temp[]= "a";

	ret = net_nfc_felica_poll(NULL , NET_NFC_FELICA_POLL_NO_REQUEST , temp[0] , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_request_service_p(void)
{
	int ret=0;
	unsigned short service_code = 0xffff;

	net_nfc_initialize();

	net_nfc_felica_poll((net_nfc_target_handle_h) 0x302023, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST , 0x0 , NULL);

	ret = net_nfc_felica_request_service((net_nfc_target_handle_h) 0x302023 , 1 , &service_code , 1 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_request_service_n(void)
{
	int ret=0;

	ret = net_nfc_felica_request_service(NULL , 1 , NULL , 1, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_request_response_p(void)
{
	int ret=0;

	net_nfc_initialize();

	net_nfc_felica_poll((net_nfc_target_handle_h) 0x302023, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST , 0x0 , NULL);

	ret = net_nfc_felica_request_response((net_nfc_target_handle_h) 0x302023 ,  NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_request_response_n(void)
{
	int ret=0;

	ret = net_nfc_felica_request_response( NULL , NULL );

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_read_without_encryption_p(void)
{
	int ret=0;
	unsigned short service_code = 0xffff;
	unsigned char blocks = 0x2;

	net_nfc_initialize();

	net_nfc_felica_poll((net_nfc_target_handle_h) 0x302023, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST , 0x0 , NULL);

	ret = net_nfc_felica_read_without_encryption((net_nfc_target_handle_h) 0x302023, 1, &service_code, 1, &blocks, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_read_without_encryption_n(void)
{
	int ret=0;

	ret = net_nfc_felica_read_without_encryption(NULL, 1, NULL, 1, NULL, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_write_without_encryption_p(void)
{
	int ret=0;
	unsigned short service_code = 0xffff;
	unsigned char blocks = 0x2;
	unsigned char send_buffer[6] = {0x00, };

	send_buffer[0] = 0x06;
	send_buffer[1] = 0x00;

	// use wild card for system code
	send_buffer[2] = 0xff;
	send_buffer[3] = 0xff;

	send_buffer[4] = 0xff;
	send_buffer[5] = 0xff;

	data_h rawdata = NULL;

	rawdata = calloc(1,sizeof(data_h));

	net_nfc_initialize();

	net_nfc_felica_poll((net_nfc_target_handle_h) 0x302023, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST , 0x0 , NULL);

	ret = net_nfc_felica_write_without_encryption((net_nfc_target_handle_h) 0x302023, 1, &service_code, 1, &blocks, rawdata , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_write_without_encryption_n(void)
{
	int ret=0;

	ret = net_nfc_felica_write_without_encryption(NULL, 1, NULL, 1, NULL, NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_request_system_code_p(void)
{
	int ret=0;
	//unsigned short service_code = 0xffff;
	//unsigned char blocks = 0x2;

	net_nfc_initialize();

	net_nfc_felica_poll((net_nfc_target_handle_h) 0x302023, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST , 0x0 , NULL);

	ret = net_nfc_felica_request_system_code((net_nfc_target_handle_h) 0x302023 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_felica_request_system_code_n(void)
{
	int ret=0;

	ret = net_nfc_felica_request_system_code(NULL, NULL);

	dts_pass(__func__, "PASS");
}
