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

#include "net_nfc.h"
#include "net_nfc_typedef.h"
#include "net_nfc_util_private.h"

#ifdef SECURITY_SERVER
#include <security-server.h>
#endif


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_initialize_p(void);
static void utc_net_nfc_initialize_n(void);
static void utc_net_nfc_deinitialize_p(void);
static void utc_net_nfc_deinitialize_n(void);
static void utc_net_nfc_set_response_callback_p(void);
static void utc_net_nfc_set_response_callback_n(void);
static void utc_net_nfc_unset_response_callback_p(void);
static void utc_net_nfc_unset_response_callback_n(void);

static void net_nfc_test_client_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data )
{
};



struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_initialize_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_initialize_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_deinitialize_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_deinitialize_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_set_response_callback_p, 1},
	{ utc_net_nfc_set_response_callback_n, 2 },
	{ utc_net_nfc_unset_response_callback_p, 1},
	{ utc_net_nfc_unset_response_callback_n, 2},
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
static void utc_net_nfc_initialize_p(void)
{
	int ret ;

	ret = net_nfc_initialize();
	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_initialize_n(void)
{
	int ret=0;

	ret = net_nfc_initialize();
	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_deinitialize_p(void)
{
	int ret ;

	net_nfc_initialize();
	ret = net_nfc_deinitialize();

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_deinitialize is failed");
}

static void utc_net_nfc_deinitialize_n(void)
{
	int ret=0;

	ret = net_nfc_deinitialize();

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_deinitialize not allow null");
}

static void utc_net_nfc_set_response_callback_p(void)
{
	int ret ;
	//net_nfc_response_cb cb;

	net_nfc_initialize();

	ret = net_nfc_set_response_callback(net_nfc_test_client_cb, NULL);

	net_nfc_unset_response_callback();

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_set_response_callback is failed");
}

static void utc_net_nfc_set_response_callback_n(void)
{
	int ret=0;

	ret = net_nfc_set_response_callback(NULL, NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_set_response_callback not allow null");
}

static void utc_net_nfc_unset_response_callback_p(void)
{
	int ret ;
	//net_nfc_response_cb cb;

	net_nfc_initialize();

	net_nfc_set_response_callback(net_nfc_test_client_cb, NULL);

	ret = net_nfc_unset_response_callback();

	net_nfc_deinitialize();

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_unset_response_callback is failed");
}

static void utc_net_nfc_unset_response_callback_n(void)
{
	int ret=0;

	ret = net_nfc_unset_response_callback();

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_unset_response_callback not allow null");
}
