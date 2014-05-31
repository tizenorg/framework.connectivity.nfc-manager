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

#include <net_nfc_data.h>
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

static void utc_net_nfc_create_data_only_p(void);
static void utc_net_nfc_create_data_only_n(void);
static void utc_net_nfc_create_data_p(void);
static void utc_net_nfc_create_data_n(void);
static void utc_net_nfc_get_data_p(void);
static void utc_net_nfc_get_data_n(void);
static void utc_net_nfc_set_data_p(void);
static void utc_net_nfc_set_data_n(void);
static void utc_net_nfc_get_data_length_p(void);
static void utc_net_nfc_get_data_length_n(void);
static void utc_net_nfc_get_data_buffer_p(void);
static void utc_net_nfc_get_data_buffer_n(void);
static void utc_net_nfc_free_data_p(void);
static void utc_net_nfc_free_data_n(void);




struct tet_testlist tet_testlist[] = {
	{ utc_net_nfc_create_data_only_p , POSITIVE_TC_IDX },
	{ utc_net_nfc_create_data_only_n , NEGATIVE_TC_IDX },
	{ utc_net_nfc_create_data_p, POSITIVE_TC_IDX },
	{ utc_net_nfc_create_data_n , NEGATIVE_TC_IDX},
	{ utc_net_nfc_get_data_p, 1},
	{ utc_net_nfc_get_data_n, 2 },
	{ utc_net_nfc_set_data_p, 1},
	{ utc_net_nfc_set_data_n, 2},
	{ utc_net_nfc_get_data_length_p, 1},
	{ utc_net_nfc_get_data_length_n, 2},
	{ utc_net_nfc_get_data_buffer_p, 1},
	{ utc_net_nfc_get_data_buffer_n, 2},
	{ utc_net_nfc_free_data_p, 1},
	{ utc_net_nfc_free_data_n, 2},
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
static void utc_net_nfc_create_data_only_p(void)
{
	int ret=0;
	data_h* config = NULL;

	config = calloc(1 , sizeof(data_h));

	ret = net_nfc_create_data_only(config);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_data_only is failed");
}

static void utc_net_nfc_create_data_only_n(void)
{
	int ret=0;

	ret = net_nfc_create_data_only(NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_data not allow null");
}

static void utc_net_nfc_create_data_p(void)
{
	int ret=0;
	data_h* config = NULL;
	uint8_t* sec_param = NULL;

	config = calloc(1, sizeof(data_h));
	sec_param = calloc(1, sizeof(uint8_t));
	memcpy(sec_param , "U" , sizeof(uint8_t));

	ret = net_nfc_create_data(config , sec_param/*"U"*/ , 1);

	free(config);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_create_data is failed");
}

static void utc_net_nfc_create_data_n(void)
{
	int ret=0;

	ret = net_nfc_create_data(NULL , NULL , 0);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_create_data_only not allow null");
}

static void utc_net_nfc_get_data_p(void)
{
	int ret=0;
	data_h data = NULL;
	uint8_t* byte = NULL;
	uint32_t length;

       byte = calloc(10, sizeof(uint8_t));

	data = calloc(1, sizeof(data_s));

	ret = net_nfc_get_data(data , &byte  , &length);

	free(data);
	free(byte);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_data is failed");
}

static void utc_net_nfc_get_data_n(void)
{
	int ret=0;

	ret = net_nfc_get_data(NULL , NULL , NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_data not allow null");
}

static void utc_net_nfc_set_data_p(void)
{
	int ret=0;
	data_h data = NULL;
	uint8_t main_record_name[] = "samsung.com:allshare";

	data = calloc(1, sizeof(data_h));

	ret = net_nfc_set_data (data, main_record_name, 20);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_set_data is failed");
}

static void utc_net_nfc_set_data_n(void)
{
	int ret=0;

	ret = net_nfc_set_data(NULL , NULL , 0);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_set_data not allow null");
}

static void utc_net_nfc_get_data_length_p(void)
{
	int ret=0;
	int length = 0;
	data_s* data = NULL;
	//uint8_t temp_data[] = "www.samsung.com";
	uint32_t temp_size = 16;

	data = calloc(1, sizeof(data_s));

	//data->buffer = temp_data;
	data->length = temp_size;

	length = net_nfc_get_data_length ((data_h)data);

	if(length > 0)
	{
		ret = NET_NFC_OK;
	}
	else
	{
		ret = NET_NFC_UNKNOWN_ERROR;
	}

	free(data);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_data_length is failed");
}

static void utc_net_nfc_get_data_length_n(void)
{
	int ret=0;
	int length = 0;

	length = net_nfc_get_data_length(NULL);

	if(length > 0)
	{
		ret = NET_NFC_OK;
	}
	else
	{
		ret = NET_NFC_UNKNOWN_ERROR;
	}

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_data_length not allow null");
}

static void utc_net_nfc_get_data_buffer_p(void)
{
	int ret=0;
	uint8_t* buffer = NULL;
	data_s* data = NULL;
	uint8_t temp_data[] = "www.samsung.com";
	int temp_size = 16;

	data = calloc(1, sizeof(data_s));

	data->buffer = temp_data;
	data->length = temp_size;

	buffer = net_nfc_get_data_buffer ((data_h)data);

	if(buffer != NULL)
	{
		ret = NET_NFC_OK;
	}
	else
	{
		ret = NET_NFC_UNKNOWN_ERROR;
	}

	free(data);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_get_data_buffer is failed");
}

static void utc_net_nfc_get_data_buffer_n(void)
{
	int ret=0;
	uint8_t* buffer = NULL;

	buffer = net_nfc_get_data_buffer(NULL);

	if(buffer != NULL)
	{
		ret = NET_NFC_OK;
	}
	else
	{
		ret = NET_NFC_UNKNOWN_ERROR;
	}

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_get_data_buffer not allow null");
}

static void utc_net_nfc_free_data_p(void)
{
	int ret=0;
	data_h data = NULL;
	//uint8_t temp_data[] = "www.samsung.com";
	//uint32_t temp_size = 16;

	data = calloc(1, sizeof(data_h));

	ret = net_nfc_free_data (data);

	dts_check_eq(__func__, ret, NET_NFC_OK, "net_nfc_free_data is failed");
}

static void utc_net_nfc_free_data_n(void)
{
	int ret=0;

	ret = net_nfc_free_data(NULL);

	dts_check_ne(__func__, ret, NET_NFC_OK, "net_nfc_free_data not allow null");
}
