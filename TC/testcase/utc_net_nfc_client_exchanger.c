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
#include <net_nfc_data.h>
#include <stdint.h>

#include <net_nfc_exchanger.h>
#include <net_nfc_typedef.h>
#include <net_nfc_typedef_private.h>
#include <net_nfc_util_private.h>


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_create_exchanger_data_p(void);
static void utc_net_nfc_create_exchanger_data_n(void);
static void utc_net_nfc_free_exchanger_data_p(void);
static void utc_net_nfc_free_exchanger_data_n(void);
static void utc_net_nfc_set_exchanger_cb_p(void);
static void utc_net_nfc_set_exchanger_cb_n(void);
static void utc_net_nfc_unset_exchanger_cb_p(void);
static void utc_net_nfc_unset_exchanger_cb_n(void);





struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_create_exchanger_data_p , POSITIVE_TC_IDX},
	{ utc_net_nfc_create_exchanger_data_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_free_exchanger_data_p, 1},
	{ utc_net_nfc_free_exchanger_data_n, 2 },
	{ utc_net_nfc_set_exchanger_cb_p, 1},
	{ utc_net_nfc_set_exchanger_cb_n, 2},
	{ utc_net_nfc_unset_exchanger_cb_p, 1},
	{ utc_net_nfc_unset_exchanger_cb_n, 2},
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
static void utc_net_nfc_create_exchanger_data_p(void)
{
	int ret=0;
	net_nfc_exchanger_data_h* ex_data = NULL;
	char temp[] = "http://www.samsung.com";
	data_s payload;

	payload.length= 23;

	payload.buffer = calloc(1 , 23*sizeof(char));

	memcpy(payload.buffer , temp , sizeof(temp));

	ex_data = calloc(1 , sizeof(ex_data));

	ret = net_nfc_create_exchanger_data(ex_data , (data_h)&payload);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_exchanger_url_type_data is failed");
}

static void utc_net_nfc_create_exchanger_data_n(void)
{
	int ret=0;

	ret = net_nfc_create_exchanger_data(NULL , NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_exchanger_url_type_data not allow null");
}

static void utc_net_nfc_free_exchanger_data_p(void)
{
	int ret=0;
	net_nfc_exchanger_data_h ex_data = NULL;
	char temp[] = "http://www.samsung.com";
	data_s payload;

	payload.length= 23;

	payload.buffer = calloc(1 , 23*sizeof(char));

	memcpy(payload.buffer , temp , sizeof(temp));

	net_nfc_create_exchanger_data(&ex_data , (data_h)&payload );

	ret = net_nfc_free_exchanger_data(ex_data);

	dts_check_eq(__func__, ret, NET_NFC_OK, "utc_net_nfc_free_exchanger_data_p is failed");
}

static void utc_net_nfc_free_exchanger_data_n(void)
{
	int ret=0;

	ret = net_nfc_free_exchanger_data(NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "utc_net_nfc_free_exchanger_data_p not allow null");
}

