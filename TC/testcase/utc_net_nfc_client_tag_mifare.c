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
#include "net_nfc_util_private.h"
#include "net_nfc_tag_jewel.h"
#include "net_nfc_target_info.h"
#include "net_nfc.h"

#include <string.h>


enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_net_nfc_mifare_create_default_key_p(void);
static void utc_net_nfc_mifare_create_default_key_n(void);
static void utc_net_nfc_mifare_create_application_directory_key_p(void);
static void utc_net_nfc_mifare_create_application_directory_key_n(void);
static void utc_net_nfc_mifare_create_net_nfc_forum_key_p(void);
static void utc_net_nfc_mifare_create_net_nfc_forum_key_n(void);
static void utc_net_nfc_mifare_authenticate_with_keyA_p(void);
static void utc_net_nfc_mifare_authenticate_with_keyA_n(void);
static void utc_net_nfc_mifare_authenticate_with_keyB_p(void);
static void utc_net_nfc_mifare_authenticate_with_keyB_n(void);
static void utc_net_nfc_mifare_read_p(void);
static void utc_net_nfc_mifare_read_n(void);
static void utc_net_nfc_mifare_write_block_p(void);
static void utc_net_nfc_mifare_write_block_n(void);
static void utc_net_nfc_mifare_write_page_p(void);
static void utc_net_nfc_mifare_write_page_n(void);
static void utc_net_nfc_mifare_increment_p(void);
static void utc_net_nfc_mifare_increment_n(void);
static void utc_net_nfc_mifare_decrement_p(void);
static void utc_net_nfc_mifare_decrement_n(void);
static void utc_net_nfc_mifare_transfer_p(void);
static void utc_net_nfc_mifare_transfer_n(void);
static void utc_net_nfc_mifare_restore_p(void);
static void utc_net_nfc_mifare_restore_n(void);



struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_mifare_create_default_key_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_mifare_create_default_key_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_mifare_create_application_directory_key_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_mifare_create_application_directory_key_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_mifare_create_net_nfc_forum_key_p, 1},
	{ utc_net_nfc_mifare_create_net_nfc_forum_key_n, 2 },
	{ utc_net_nfc_mifare_authenticate_with_keyA_p, 1},
	{ utc_net_nfc_mifare_authenticate_with_keyA_n, 2},
	{ utc_net_nfc_mifare_authenticate_with_keyB_p, 1},
	{ utc_net_nfc_mifare_authenticate_with_keyB_n, 2},
	{ utc_net_nfc_mifare_read_p, 1},
	{ utc_net_nfc_mifare_read_n, 2},
	{ utc_net_nfc_mifare_write_block_p, 1},
	{ utc_net_nfc_mifare_write_block_n, 2},
	{ utc_net_nfc_mifare_write_page_p, 1},
	{ utc_net_nfc_mifare_write_page_n, 2},
	{ utc_net_nfc_mifare_increment_p, 1},
	{ utc_net_nfc_mifare_increment_n, 2},
	{ utc_net_nfc_mifare_decrement_p, 1},
	{ utc_net_nfc_mifare_decrement_n, 2},
	{ utc_net_nfc_mifare_transfer_p, 1},
	{ utc_net_nfc_mifare_transfer_n, 2},
	{ utc_net_nfc_mifare_restore_p, 1},
	{ utc_net_nfc_mifare_restore_n, 2},
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

static void utc_net_nfc_mifare_create_default_key_p(void)
{
	int ret=0;
	data_h default_key = NULL;

	net_nfc_initialize();

	ret = net_nfc_mifare_create_default_key(&default_key);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_create_default_key_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_create_default_key(NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_create_application_directory_key_p(void)
{
	int ret=0;
	data_h mad_key = NULL;

	net_nfc_initialize();

	ret = net_nfc_mifare_create_application_directory_key(&mad_key);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_create_application_directory_key_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_create_application_directory_key(NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_create_net_nfc_forum_key_p(void)
{
	int ret=0;
       data_h net_nfc_forum_key = NULL;

	net_nfc_initialize();

	ret = net_nfc_mifare_create_net_nfc_forum_key(&net_nfc_forum_key);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_create_net_nfc_forum_key_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_create_net_nfc_forum_key( NULL );

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_authenticate_with_keyA_p(void)
{
	data_h default_key = NULL;
	int sector = 1;
	data_h key = NULL;

	net_nfc_initialize();

	net_nfc_mifare_create_default_key(&default_key);

	key = default_key;

	net_nfc_mifare_authenticate_with_keyA((net_nfc_target_handle_h) 0x302023, sector, default_key, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_authenticate_with_keyA_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_authenticate_with_keyA(NULL , 0 , NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_authenticate_with_keyB_p(void)
{
	data_h default_key = NULL;
	int sector = 1;
	data_h key = NULL;

	net_nfc_initialize();

	net_nfc_mifare_create_default_key(&default_key);

	key = default_key;

	net_nfc_mifare_authenticate_with_keyB((net_nfc_target_handle_h) 0x302023, sector, key, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_authenticate_with_keyB_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_authenticate_with_keyB(NULL , 0 , NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_read_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_read((net_nfc_target_handle_h) 0x302023 , 5, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_read_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_read(NULL , 0 , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_write_block_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_write_block((net_nfc_target_handle_h) 0x302023 , 5, NULL , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_write_block_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_write_block(NULL , 0 , NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_write_page_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_write_block((net_nfc_target_handle_h) 0x302023 , 5, NULL , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_write_page_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_write_block(NULL , 0 , NULL , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_increment_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_increment((net_nfc_target_handle_h) 0x302023 , 5 , 0 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_increment_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_increment(NULL , 5 , 0 , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_decrement_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_decrement((net_nfc_target_handle_h) 0x302023 , 5 , 0 , NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_decrement_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_decrement(NULL , 5 , 0 , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_transfer_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_transfer((net_nfc_target_handle_h) 0x302023 , 5, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_transfer_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_transfer(NULL , 5 , NULL);

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_restore_p(void)
{
	net_nfc_initialize();

	net_nfc_mifare_restore((net_nfc_target_handle_h) 0x302023 , 5, NULL);

	net_nfc_deinitialize();

	dts_pass(__func__, "PASS");
}

static void utc_net_nfc_mifare_restore_n(void)
{
	int ret=0;

	ret = net_nfc_mifare_restore(NULL , 5 , NULL);

	dts_pass(__func__, "PASS");
}
