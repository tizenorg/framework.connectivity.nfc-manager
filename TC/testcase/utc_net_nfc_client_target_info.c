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

#include "net_nfc_typedef.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_target_info.h"
#include "net_nfc_data.h"
#include <stdbool.h>
#include "net_nfc.h"

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_get_tag_type_p(void);
static void utc_net_nfc_get_tag_type_n(void);
static void utc_net_nfc_get_tag_handle_p(void);
static void utc_net_nfc_get_tag_handle_n(void);
static void utc_net_nfc_get_tag_ndef_support_p(void);
static void utc_net_nfc_get_tag_ndef_support_n(void);
static void utc_net_nfc_get_tag_max_data_size_p(void);
static void utc_net_nfc_get_tag_max_data_size_n(void);
static void utc_net_nfc_get_tag_actual_data_size_p(void);
static void utc_net_nfc_get_tag_actual_data_size_n(void);
static void utc_net_nfc_get_tag_info_keys_p(void);
static void utc_net_nfc_get_tag_info_keys_n(void);
static void utc_net_nfc_get_tag_info_value_p(void);
static void utc_net_nfc_get_tag_info_value_n(void);


struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_get_tag_type_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_get_tag_type_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_get_tag_handle_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_get_tag_handle_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_get_tag_ndef_support_p, 1},
	{ utc_net_nfc_get_tag_ndef_support_n, 2 },
	{ utc_net_nfc_get_tag_max_data_size_p, 1},
	{ utc_net_nfc_get_tag_max_data_size_n, 2},
	{ utc_net_nfc_get_tag_actual_data_size_p, 1},
	{ utc_net_nfc_get_tag_actual_data_size_n, 2},
	{ utc_net_nfc_get_tag_info_keys_p, 1},
	{ utc_net_nfc_get_tag_info_keys_n, 2},
	{ utc_net_nfc_get_tag_info_value_p, 1},
	{ utc_net_nfc_get_tag_info_value_n, 2},
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

static void utc_net_nfc_get_tag_type_p(void)
{
	int ret=0;
	net_nfc_target_info_s* target_info;
	net_nfc_target_type_e type;

	target_info = calloc(1, sizeof(net_nfc_target_info_s));

	target_info->devType = NET_NFC_GENERIC_PICC;

	net_nfc_initialize();

	ret = net_nfc_get_tag_type((net_nfc_target_info_h)target_info , &type);

	net_nfc_deinitialize();

	free(target_info);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_type_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_type(NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_handle_p(void)
{
	int ret=0;
	net_nfc_target_info_s* target_info;
	net_nfc_target_handle_h id;

	target_info = calloc(1, sizeof(net_nfc_target_info_s));

	target_info->handle = (net_nfc_target_handle_s*)0x302023;

	net_nfc_initialize();

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)target_info , &id);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_handle_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_handle(NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_ndef_support_p(void)
{
	int ret=0;
	net_nfc_target_info_s* target_info;
	bool is_ndef;

	target_info = calloc(1, sizeof(net_nfc_target_info_s));
	target_info->is_ndef_supported = 1;

	net_nfc_initialize();

	ret = net_nfc_get_tag_ndef_support((net_nfc_target_info_h)target_info , &is_ndef);

	net_nfc_deinitialize();

	free(target_info);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_ndef_support_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_ndef_support(NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_max_data_size_p(void)
{
	int ret=0;
	net_nfc_target_info_s* target_info;
	net_nfc_target_type_e max_size = 0;

	target_info = calloc(1, sizeof(net_nfc_target_info_s));
	target_info->maxDataSize = 128;

	net_nfc_initialize();

	ret = net_nfc_get_tag_max_data_size((net_nfc_target_info_h)target_info , &max_size);

	net_nfc_deinitialize();

	free(target_info);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_max_data_size_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_max_data_size(NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_actual_data_size_p(void)
{
	int ret=0;
	net_nfc_target_info_s* target_info;
	net_nfc_target_type_e size = 0;

	target_info = calloc(1, sizeof(net_nfc_target_info_s));
	target_info->actualDataSize = 128;

	net_nfc_initialize();

	ret = net_nfc_get_tag_actual_data_size((net_nfc_target_info_h)target_info , &size);

	net_nfc_deinitialize();

	free(target_info);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_actual_data_size_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_actual_data_size(NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_info_keys_p(void)
{
	int ret=0;
	net_nfc_target_info_s* target_info;
	char** keys = NULL;
	int nok = 0;

	target_info = calloc(1, sizeof(net_nfc_target_info_s));

	net_nfc_initialize();

	ret = net_nfc_get_tag_info_keys((net_nfc_target_info_h)target_info, &keys, &nok);

	net_nfc_deinitialize();

	free(target_info);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_info_keys_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_info_keys(NULL ,  NULL , NULL);

	dts_pass(__func__, "PASS");
}
static void utc_net_nfc_get_tag_info_value_p(void)
{
	net_nfc_target_info_s* target_info;
	data_h* value = NULL;
	char* keys = NULL;

	keys = calloc( 1 , sizeof(char));

	target_info = calloc(1, sizeof(net_nfc_target_info_s));
	target_info->actualDataSize = 128;
	target_info->tag_info_list = calloc(1 , sizeof(net_nfc_tag_info_s));

	target_info->tag_info_list->key = '1';
	target_info->tag_info_list->value = calloc(1 , sizeof(data_h));

	value = calloc(1, sizeof(data_h));

	net_nfc_initialize();

	//net_nfc_get_tag_info_keys((net_nfc_target_info_h)target_info, &keys, &nok);

	net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info , keys , value);

	net_nfc_deinitialize();

	free(target_info->tag_info_list->value);
	free(target_info->tag_info_list);
	free(target_info);
	free(keys);
	free(value);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_get_tag_info_value_n(void)
{
	int ret=0;

	ret = net_nfc_get_tag_info_value(NULL , NULL , NULL);

	dts_pass(__func__, "PASS");
}
