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

#include "net_nfc_tag.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_internal_se.h"
#include "net_nfc_util_private.h"
#include "net_nfc_data.h"


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_set_secure_element_type_p(void);
static void utc_net_nfc_set_secure_element_type_n(void);
static void utc_net_nfc_get_secure_element_type_p(void);
static void utc_net_nfc_get_secure_element_type_n(void);
static void utc_net_nfc_open_internal_secure_element_p(void);
static void utc_net_nfc_open_internal_secure_element_n(void);
static void utc_net_nfc_close_internal_secure_element_p(void);
static void utc_net_nfc_close_internal_secure_element_n(void);
static void utc_net_nfc_send_apdu_p(void);
static void utc_net_nfc_send_apdu_n(void);



struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_set_secure_element_type_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_set_secure_element_type_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_get_secure_element_type_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_get_secure_element_type_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_open_internal_secure_element_p, 1},
	{ utc_net_nfc_open_internal_secure_element_n, 2 },
	{ utc_net_nfc_close_internal_secure_element_p, 1},
	{ utc_net_nfc_close_internal_secure_element_n, 2},
	{ utc_net_nfc_send_apdu_p, 1},
	{ utc_net_nfc_send_apdu_n, 2},
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
static void utc_net_nfc_set_secure_element_type_p(void)
{
	int ret=0;

	ret = net_nfc_set_secure_element_type(NET_NFC_SE_TYPE_UICC, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_set_secure_element_type_n(void)
{
	int ret=0;

	ret = net_nfc_set_secure_element_type( -1 , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_secure_element_type_p(void)
{
	int ret=0;

	ret = net_nfc_get_secure_element_type(NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_secure_element_type_n(void)
{
	int ret=0;

	ret = net_nfc_get_secure_element_type(NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_open_internal_secure_element_p(void)
{
	net_nfc_open_internal_secure_element(NET_NFC_SE_TYPE_ESE, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_open_internal_secure_element_n(void)
{
	int ret=0;

	ret = net_nfc_open_internal_secure_element(NET_NFC_SE_TYPE_ESE, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_close_internal_secure_element_p(void)
{
	int ret=0;
	void * trans_data = NULL;

	ret = net_nfc_close_internal_secure_element ((net_nfc_target_handle_h)trans_data, NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_close_internal_secure_element_n(void)
{
	int ret=0;

	ret = net_nfc_close_internal_secure_element(NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_send_apdu_p(void)
{
	int ret ;
	net_nfc_target_handle_h data = NULL;
	data_h apdu = NULL;
	uint8_t apdu_cmd[4] = {0x00, 0xA4, 0x00, 0x0C} ; // CLA 0-> use default channel and no secure message. 0xA4 -> select instruction

       //data->connection_id = 1;
	//data->connection_type = NET_NFC_SE_CONNECTION;

	net_nfc_create_data(&apdu, apdu_cmd, 4);

	ret = net_nfc_send_apdu((net_nfc_target_handle_h)(data), apdu, data);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_send_apdu_n(void)
{
	int ret ;

	ret = net_nfc_send_apdu(NULL , NULL , NULL );

	dts_pass(__func__, "PASS");
}
