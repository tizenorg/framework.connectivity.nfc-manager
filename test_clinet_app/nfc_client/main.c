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


#include <stdio.h>
#include <stdlib.h>
#include <net_nfc_typedef.h>
#include <net_nfc.h>
#include <net_nfc_exchanger.h>

#include <pthread.h>
#include "nfc_api_test.h"

#include <glib.h>

/* Function definition list*/
int nfcTestClientInit(uint8_t testNumber,void* arg_ptr2);
int nfcTestNdefParser(uint8_t testNumber,void* arg_ptr2);
int nfcTestWriteMode(uint8_t testNumber,void* arg_ptr2);
int nfcTestReaderMode(uint8_t testNumber,void* arg_ptr2);
int nfcTestTransceive(uint8_t testNumber,void* arg_ptr2);
int nfcTestAPIBasicTest1(uint8_t testNumber,void* arg_ptr2);
int nfcTestAPIBasicTest2(uint8_t testNumber,void* arg_ptr2);
int nfcTestAPIBasicTest3(uint8_t testNumber,void* arg_ptr2);
int nfcTestReadWriteMode(uint8_t testNumber,void* arg_ptr2);
int nfcTestAPIMultipleRequest(uint8_t testNumber,void* arg_ptr2);
int nfcTestLLCP(uint8_t testNumber,void* arg_ptr2);
int nfcTestStressLLCP(uint8_t testNumber,void* arg_ptr2);
int nfcTestExchanger(uint8_t testNumber,void* arg_ptr2);
int nfcConnHandover(uint8_t testNumber,void* arg_ptr2);
int nfcTestAPIException (uint8_t testNumber,void* arg_ptr);
int nfcTestAPIException_tagAPI (uint8_t testNumber,void* arg_ptr);
int nfcTestAPIException_targetInfo (uint8_t testNumber,void* arg_ptr);
int nfcConnHandoverMessageTest (uint8_t testNumber,void* arg_ptr);
int nfcTestFormatNdef(uint8_t testNumber,void* arg_ptr2);
int nfcTestInternalSe(uint8_t testNumber,void* arg_ptr2);
int nfcTestSnep(uint8_t testNumber,void* arg_ptr);


void print_test_result (char * str, net_nfc_test_result_e result);

#define NET_NFC_TAG_DISCOVERED			1
#define NET_NFC_TAG_CONNECT			(1 << 1)
#define NET_NFC_TAG_CHECK_NDEF		(1 << 2)
#define NET_NFC_TAG_NDEF_READ			(1 << 3)
#define NET_NFC_TAG_NDEF_WRITE			(1 << 4)
#define NET_NFC_TAG_NDEF_READ_BIG		(1 << 5)
#define NET_NFC_TAG_NDEF_WRITE_BIG	(1 << 6)
#define NET_NFC_TAG_DISCONNECT			(1 << 7)
#define NET_NFC_MAX_TAG_TYPE	20

static nfcTestType nfcTestMatrix[] =
{
//	{"API STRESS_WRITE_READ TEST", nfcTestReadWriteMode, NET_NFC_TEST_NOT_YET}, // OK
//	{"Remove tag while writing", nfcTestWriteMode, NET_NFC_TEST_NOT_YET}, //OK
//	{"Remove tag while reading", nfcTestAPIBasicTest2, NET_NFC_TEST_NOT_YET}, // OK
	//{"API BASIC TEST3", nfcTestAPIBasicTest3, NET_NFC_TEST_NOT_YET},
//	{"API MUTIPLE REQUEST", nfcTestAPIMultipleRequest, NET_NFC_TEST_NOT_YET}, // OK
//	{"API BASIC TEST1", nfcTestAPIBasicTest1, NET_NFC_TEST_NOT_YET}, // OK
//	{"Check NDEF message",		nfcTestNdefParser,		NET_NFC_TEST_NOT_YET}, // OK
//	{"write mode", 			nfcTestWriteMode,		NET_NFC_TEST_NOT_YET},
//	{"reader mode", 		nfcTestReaderMode,		NET_NFC_TEST_NOT_YET},
//	{"format ndef", 		nfcTestFormatNdef,		NET_NFC_TEST_NOT_YET},
//	{"internal_se_test", 		nfcTestInternalSe,		NET_NFC_TEST_NOT_YET},
//	{"exchange mode", 		nfcTestExchanger,		NET_NFC_TEST_NOT_YET},
//	{"Transceive Test",		nfcTestTransceive,		NET_NFC_TEST_NOT_YET},
//	{"LLCP Test",		nfcTestLLCP, NET_NFC_TEST_NOT_YET},
//	{"connection handover msg test",		nfcConnHandover, NET_NFC_TEST_NOT_YET},
//	{"API Exception Test",		nfcTestAPIException, NET_NFC_TEST_NOT_YET},
//	{"API Exception Test2",		nfcTestAPIException_tagAPI, NET_NFC_TEST_NOT_YET},
///	{"API Exception Test3",		nfcTestAPIException_targetInfo, NET_NFC_TEST_NOT_YET},
//	{"LLCP Test",		nfcTestLLCP, NET_NFC_TEST_NOT_YET},
//	{"LLCP Test",		nfcTestStressLLCP, NET_NFC_TEST_NOT_YET},
//    {"Handover Message",	nfcConnHandoverMessageTest , NET_NFC_TEST_NOT_YET},
	{"snep test", 		nfcTestSnep,		NET_NFC_TEST_NOT_YET},
	{NULL, 				NULL, 				NET_NFC_TEST_NOT_YET},
};

static uint32_t testDevType = 0;
static uint32_t testCardMaxNdefLength = 0;
static uint8_t tagTestResult[NET_NFC_MAX_TAG_TYPE];

static int read_count = 0;
static int write_count = 0;
static int detect_count = 0;

static net_nfc_target_handle_h tag_handle = NULL;
static int test_count = 0;



/* Below smart poster data can has problem or parser has some problem.
	Need to check */
uint8_t  nfcTestSpHex[]= {0xD1,0x02,0x37,0x53,0x70,0x91,0x01,0x18,0x54,0x04,
			0x74,0x65,0x73,0x74,0x53,0x6D,0x61,0x72,0x74,0x70,
			0x6F,0x73,0x74,0x65,0x72,0x20,0x45,0x78,0x61,0x6D,
			0x70,0x6C,0x65,0x11,0x03,0x01,0x61,0x63,0x74,0x00,
			0x51,0x01,0x10,0x55,0x00,0x77,0x77,0x77,0x2E,0x73,
			0x61,0x6D,0x73,0x75,0x6E,0x67,0x2E,0x63,0x6F,0x6D};

/*
uint8_t  nfcTestSp[]={0xD1,0x02,0x24,0x53,0x70,0x91,0x01,0x14,0x54
					,0x00,0x53,0x6D,0x61,0x72,0x74,0x70,0x6F,0x73
					,0x74,0x65,0x72,0x20,0x45,0x78,0x61,0x6D,0x70
					,0x6C,0x65,0x11,0x03,0x01,0x61,0x63,0x74,0x00
					,0x51,0x01,0x01,0x55,0x00};
*/

// test Text "Samsung Linux Platform NFC TEST"
uint8_t nfcTestTextHex[]= {0xD1,0x01,0x20,0x54,0x00,0x53,0x61,0x6D,0x73,0x75
				   ,0x6E,0x67,0x20,0x4C,0x69,0x6E,0x75,0x78,0x20,0x50
				   ,0x6C,0x61,0x74,0x66,0x6F,0x72,0x6D,0x20,0x4E,0x46
				   ,0x43,0x20,0x54,0x45,0x53,0x54};


// test URI "http://www.samsunglinuxplatform.nfctest.com"
uint8_t nfcTestUriHex[]={0xD1,0x01,0x2C,0x55,0x00,0x68,0x74,0x74,0x70,0x3A
					,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x73,0x61,0x6D,0x73
					,0x75,0x6E,0x67,0x6C,0x69,0x6E,0x75,0x78,0x70,0x6C
					,0x61,0x74,0x66,0x6F,0x72,0x6D,0x2E,0x6E,0x66,0x63
					,0x74,0x65,0x73,0x74,0x2E,0x63,0x6F,0x6D};

uint8_t	nfcTestText[] = "payload http://www.samsunglinuxplatform.nfctest.com";
uint8_t	nfcTestUri[] = {0xD1,0x01,0x13,0x55,0x1,0x73,0x61,0x6D,0x73,0x75,0x6E,0x67,0x6D,0x6F,0x62,0x69,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x2F};



static pthread_cond_t pcond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t plock = PTHREAD_MUTEX_INITIALIZER;

static gboolean test_process_func(gpointer data)
{
	uint8_t	i, testNumber;
	int count = 0;

	while (nfcTestMatrix[count].testName != NULL){
		count ++;
	}

	for(i=0; i<count; i++)
	{
		PRINT_INFO("%d. %s START\n", i, nfcTestMatrix[i].testName);

		if(nfcTestMatrix[i].testFn !=NULL){
			nfcTestMatrix[i].testResult = nfcTestMatrix[i].testFn(i, NULL);
			//print_test_result (nfcTestMatrix[i].testName, nfcTestMatrix[i].testResult);
		}
	}

	return false;
}

int main()
{

	GMainLoop* loop = NULL;
	loop = g_main_new(TRUE);

	g_timeout_add_seconds(1, test_process_func, NULL); // 1secs
	g_main_loop_run(loop);

	return 0;
}

void print_test_result (char * str, net_nfc_test_result_e result)
{
	if (result == NET_NFC_TEST_OK){
		PRINT_RESULT_SUCCESS("TEST [%s] is PASSED",str);
	}
	else if (result == NET_NFC_TEST_FAIL){
		PRINT_RESULT_FAIL("TEST [%s] is FAILED",str);
	}
	else {
		PRINT_INFO("TEST is being tested\n");
	}
}


/*=================================================================================*/

static net_nfc_test_result_e test_case_result;

static void net_nfc_test_read_write_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data );
static void net_nfc_test_static_handover_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data);

static void net_nfc_test_client_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data )
{
	// do nothing
}

int nfcTestClientInit(uint8_t testNumber,void* arg_ptr2)
{
	net_nfc_error_e result;
	result = net_nfc_initialize();
	CHECK_RESULT(result);


	result = net_nfc_set_response_callback (net_nfc_test_client_cb, NULL);
	CHECK_RESULT(result);

	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);

	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);

	return NET_NFC_TEST_OK;
}


net_nfc_exchanger_data_h net_nfc_exchanger_callback(net_nfc_exchanger_event_e event, void * user_param)
{
	PRINT_INFO(" event = [%d] \n", event);
	test_case_result = NET_NFC_TEST_OK;

	switch(event)
	{
		case NET_NFC_EXCHANGER_DATA_REQUESTED:
		{
			PRINT_INFO("exchange is requested");
			net_nfc_exchanger_data_h ex_data = NULL;
			net_nfc_error_e error = NET_NFC_OK;
			data_h payload = NULL;

/*
			uint8_t buffer[1024] = {0};

			int i = 0;
			for(; i< 1024; i++){
				buffer[i] = 'a';
			}

			net_nfc_create_data(&payload, buffer, 1024);
*/

			if((error = net_nfc_create_exchanger_data(&ex_data, (uint8_t *)"http://www.samsung.com")) == NET_NFC_OK)
			//if((error = net_nfc_create_exchanger_url_type_data(&ex_data, NET_NFC_SCHEMA_FULL_URI, (uint8_t *)"file://test.txt")) == NET_NFC_OK)
			//if((error = net_nfc_create_exchanger_raw_type_data(&ex_data, "text/plain", payload)) == NET_NFC_OK)
			{
				return ex_data;
			}
			else
			{
				PRINT_INFO("create exchanger data is failed = [%d]", error);
				//pthread_cond_signal (&pcond);
				return NULL;
			}
		}
		case NET_NFC_EXCHANGER_TRANSFER_FAILED:
		case NET_NFC_EXCHANGER_TRANSFER_COMPLETED:
		default:
		{
			//pthread_cond_signal (&pcond);

			if(event == NET_NFC_EXCHANGER_TRANSFER_COMPLETED)
			{
				PRINT_INFO("transfer exchanger msg is completed");
			}
			else
			{
				PRINT_INFO("transfer exchanger msg is failed");
			}

			return NULL;
		}
	}

}

/*=================================================================================*/
static void net_nfc_test_reader_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	PRINT_INFO("user_param = [%d] trans_param = [%d]", user_param, trans_data);

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h id;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle(target_info, &id);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target id: %X\n", id);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			if (is_ndef){
				int actual_size;
				int max_size;
				net_nfc_get_tag_actual_data_size (target_info ,&actual_size);
				net_nfc_get_tag_max_data_size (target_info ,&max_size);
				PRINT_INFO("\tmax data [%d]\tactual data [%d]\n", max_size,actual_size );
				net_nfc_read_tag (id, (void *)2);
			}
			else{
				PRINT_INSTRUCT("Please use NDEF formated tag!!");
				test_case_result = NET_NFC_TEST_FAIL;
			}
			break;
		}
		case NET_NFC_MESSAGE_READ_NDEF:{
			if(data != NULL){
				ndef_message_h ndef = (ndef_message_h)(data);
				data_h rawdata;
				net_nfc_create_rawdata_from_ndef_message (ndef ,&rawdata);
				PRINT_INFO("read ndef message is ok, length is [%d]", net_nfc_get_data_length(rawdata));
				//_//net_nfc_ndef_print_message (ndef);
				/*

				if (memcmp(net_nfc_get_data_buffer (rawdata),nfcTestSpHex, net_nfc_get_data_length (rawdata)) == 0){
					test_case_result = NET_NFC_TEST_OK;
				}
				*/
			}
			pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);
			break;
		}
		default:
			break;
	}
}


static void net_nfc_test_format_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	PRINT_INFO("user_param = [%d] trans_param = [%d]", user_param, trans_data);

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:{

			PRINT_INFO("NET_NFC_MESSAGE_TAG_DISCOVERED");

			net_nfc_target_type_e type;
			net_nfc_target_handle_h id;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle(target_info, &id);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target id: %X\n", id);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			data_h ndef_key = NULL;
			net_nfc_mifare_create_net_nfc_forum_key(&ndef_key);
			net_nfc_format_ndef(id, ndef_key, NULL);

		}
		break;

		case NET_NFC_MESSAGE_FORMAT_NDEF:{
			PRINT_INFO("NET_NFC_MESSAGE_FORMAT_NDEF");
			PRINT_INFO("result = [%d]", result);
		}
		break;
		case NET_NFC_MESSAGE_TAG_DETACHED:
		{
			PRINT_INFO("NET_NFC_MESSAGE_TAG_DETACHED");
		}
		break;
		default:
			break;
	}
}

static void net_nfc_test_se_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	switch(message)
	{
		case NET_NFC_MESSAGE_GET_SE :
		{
			PRINT_INFO("NET_NFC_MESSAGE_GET_SE result = [%d] se type = [%d]", result, *((uint8_t *)data));
			//net_nfc_set_secure_element_type(NET_NFC_SE_TYPE_ESE, NULL);
			net_nfc_set_secure_element_type(NET_NFC_SE_TYPE_UICC, NULL);
		}
		break;
		case NET_NFC_MESSAGE_SET_SE :
		{
			PRINT_INFO("NET_NFC_MESSAGE_SET_SE result = [%d] se type = [%d]", result, *((uint8_t *)data));
			net_nfc_open_internal_secure_element(NET_NFC_SE_TYPE_ESE, NULL);
			//net_nfc_open_internal_secure_element(NET_NFC_SE_TYPE_UICC, NULL);
		}
		break;
		case NET_NFC_MESSAGE_OPEN_INTERNAL_SE :
		{
			PRINT_INFO("NET_NFC_MESSAGE_OPEN_INTERNAL_SE result = [%d] and handle = [0x%x]", result, data);
			data_h apdu = NULL;
			uint8_t apdu_cmd[4] = {0x00, 0xA4, 0x00, 0x0C} ; // CLA 0-> use default channel and no secure message. 0xA4 -> select instruction
			net_nfc_create_data(&apdu, apdu_cmd, 4);
			net_nfc_send_apdu((net_nfc_target_handle_h)(data), apdu, data);

		}
		break;
		case NET_NFC_MESSAGE_SEND_APDU_SE:
		{
			PRINT_INFO("NET_NFC_MESSAGE_SEND_APDU_SE result = [%d]", result);

			if(data != NULL)
			{
				uint8_t * r_buffer = net_nfc_get_data_buffer (data);
				uint32_t r_buffer_length = net_nfc_get_data_length (data);

				PRINT_INFO ("Received data [size:%d] \n", net_nfc_get_data_length (data));

				int idx = 0;
				for (idx = 0; idx < r_buffer_length; idx++){
					printf (" %02X", r_buffer[idx]);
				}printf ("\n");
			}

			net_nfc_close_internal_secure_element((net_nfc_target_handle_h)trans_data, NULL);
		}
		break;
		case NET_NFC_MESSAGE_CLOSE_INTERNAL_SE :
		{

			PRINT_INFO("NET_NFC_MESSAGE_CLOSE_INTERNAL_SE result = [%d]", result);
		}
		break;
		default:
			break;
	}

	PRINT_INFO("user_param = [%d] trans_param = [%d]", user_param, trans_data);
}

/*=================================================================================*/
static void net_nfc_test_static_handover_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;
	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h id;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;
			net_nfc_carrier_config_h * config;
			ndef_record_h record;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle(target_info, &id);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target id: %X\n", id);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			if (is_ndef){

				ndef_message_h ndef = NULL;
				data_h bt_config = NULL;
				net_nfc_create_data_only(&bt_config);

				// 2byte :: OOB length, 6byte :: bt addr
				uint8_t temp[8] = {0x00, 0x08, 0x00, 0x02, 0x78, 0xDD, 0xC4, 0x8A};
				net_nfc_create_carrier_config (&config,NET_NFC_CONN_HANDOVER_CARRIER_BT );
				net_nfc_add_carrier_config_property (config ,NET_NFC_BT_ATTRIBUTE_ADDRESS ,8 ,temp);
				net_nfc_create_ndef_record_with_carrier_config (&record, config);
				net_nfc_create_handover_select_message (&ndef);
				net_nfc_append_carrier_config_record (message,record,NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE);

				net_nfc_write_ndef(id, ndef, NULL);

			}
			else{
				PRINT_INSTRUCT("Please use NDEF formated tag!!");
				test_case_result = NET_NFC_TEST_FAIL;
			}
			break;
		}
		case NET_NFC_MESSAGE_WRITE_NDEF:{

			if(result == NET_NFC_OK){
				PRINT_INFO("write ndef message is ok");
				test_case_result = NET_NFC_TEST_OK;
			}

			pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);
			break;
		}
		default:
			break;
	}
}

int nfcConnHandover(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
#if 1
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();

	net_nfc_state_activate(1);

	CHECK_RESULT(result);
	result = net_nfc_set_response_callback (net_nfc_test_static_handover_cb, NULL);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );
	/*
	PRINT_INFO("operation is end");

	result = net_nfc_unset_response_callback ();

	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
	*/
#else

/*
	ndef_message_h ndef = NULL;

	if(net_nfc_retrieve_current_ndef_message(&ndef) == NET_NFC_OK){
		PRINT_INFO("retrieve is ok");
	}
	else{
		PRINT_INFO("retrieve is failed");
		return NET_NFC_TEST_FAIL;
	}
*/
	ndef_message_h ndef = NULL;
	data_h bt_config = NULL;
	net_nfc_create_data_only(&bt_config);

	// 2byte :: OOB length, 6byte :: bt addr
	uint8_t temp[8] = {0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

	net_nfc_set_data(bt_config, temp, 8);
	net_nfc_create_static_connection_handover_select_message(&ndef, bt_config, NULL);

	net_nfc_conn_handover_info_h handover_info = NULL;

	if(net_nfc_parse_connection_handover_ndef_message(ndef, &handover_info) == NET_NFC_OK){
		PRINT_INFO("parsing is ok");

		uint8_t version = 0;

		if((result = net_nfc_get_connection_handover_version(handover_info, &version)) == NET_NFC_OK){
			PRINT_INFO("version = [%d]", version);
		}
		else{
			PRINT_INFO("get version is failed = [%d]", result);
		}


		unsigned short random_number = 0;
		if((result = net_nfc_get_connection_handover_random_number(handover_info, &random_number)) == NET_NFC_OK)
		{
			PRINT_INFO("random_number = [%d]", random_number);
		}
		else
		{
			PRINT_INFO("get random_number is failed = [%d]", result);
		}

		data_h record_type = NULL;
		net_nfc_get_connection_handover_record_type(handover_info, &record_type);
		PRINT_INFO("record type = [%c] [%c]", (net_nfc_get_data_buffer(record_type))[0], (net_nfc_get_data_buffer(record_type))[1]);

		uint8_t carrier_count = 0;
		net_nfc_get_connection_handover_alternative_carrier_count(handover_info, &carrier_count);

		int i = 0;
		for(; i < carrier_count; i++)
		{
			net_nfc_conn_handover_carrier_info_h carrier_info = NULL;
			net_nfc_get_connection_handover_carrier_handle_by_index(handover_info, i, &carrier_info);

			if(carrier_info != NULL){
				net_nfc_conn_handover_carrier_type_e carrier_type = 0;
				net_nfc_get_carrier_type(carrier_info, &carrier_type);

				if(carrier_type == NET_NFC_CONN_HANDOVER_CARRIER_BT)
				{
					PRINT_INFO("carrier is BT");
				}
				else if(carrier_type == NET_NFC_CONN_HANDOVER_CARRIER_WIFI)
				{
					PRINT_INFO("carrier is WIFI");
				}
				else
				{
					PRINT_INFO("carrier is unknown");
				}

				data_h id = NULL;
				net_nfc_get_carrier_id(carrier_info, &id);

				PRINT_INFO("id = [0x%x]", (net_nfc_get_data_buffer(id))[0]);

				net_nfc_conn_handover_carrier_state_e carrier_state = 0;
				net_nfc_get_carrier_power_state(carrier_info, &carrier_state);

				PRINT_INFO("cps is = [0x%x]", carrier_state);

				data_h config = NULL;
				if((result = net_nfc_get_carrier_configuration(carrier_info, &config)) == NET_NFC_OK)
				{
					PRINT_INFO("good to get config");
				}
				else
				{
					PRINT_INFO("failed to get config = [%d]", result);
				}

				uint8_t* buffer = NULL;
				if((buffer = net_nfc_get_data_buffer(config)) != NULL)
				{
					unsigned short size = ( buffer[0] << 8 ) |buffer[1];
					PRINT_INFO("size is = [%d]", size);

					if(size == 8)
					{
						PRINT_INFO("carrier addr is [0x%x]", buffer[2]);
						PRINT_INFO("carrier addr is [0x%x]", buffer[3]);
						PRINT_INFO("carrier addr is [0x%x]", buffer[4]);
						PRINT_INFO("carrier addr is [0x%x]", buffer[5]);
						PRINT_INFO("carrier addr is [0x%x]", buffer[6]);
						PRINT_INFO("carrier addr is [0x%x]", buffer[7]);
					}
					else
					{
						PRINT_INFO("more data -_-;; ");
					}
				}
				else
				{
					PRINT_INFO("failed to buffer");
				}
			}

		}
	}
	else{

		PRINT_INFO("parsing is failed");

		return NET_NFC_TEST_FAIL;
	}


	if(handover_info != NULL){
		if((net_nfc_free_connection_handover_info(handover_info)) == NET_NFC_OK){
			PRINT_INFO("free is good");
		}
		else{
			PRINT_INFO("free is failed");
		}
	}
#endif

	return test_case_result;
}

int nfcTestFormatNdef(uint8_t testNumber,void* arg_ptr2)
{
	PRINT_INFO("%s is start", __func__);

	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();

	net_nfc_state_activate(1);

	CHECK_RESULT(result);
	result = net_nfc_set_response_callback (net_nfc_test_format_cb, (void *)1);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );

/*
	PRINT_INFO("operation is end");

	result = net_nfc_unset_response_callback ();

	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);

*/

	return test_case_result;
}

int nfcTestInternalSe(uint8_t testNumber,void* arg_ptr2)
{
	PRINT_INFO("%s is start", __func__);

	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();

	net_nfc_state_activate(1);

	CHECK_RESULT(result);
	result = net_nfc_set_response_callback (net_nfc_test_se_cb, (void *)1);
	CHECK_RESULT(result);

	net_nfc_get_secure_element_type(NULL);

	PRINT_INSTRUCT("Please close a tag to device!!");

	return test_case_result;
}



int nfcTestReaderMode(uint8_t testNumber,void* arg_ptr2)
{
	PRINT_INFO("%s is start", __func__);

	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();

	net_nfc_state_activate(1);

	CHECK_RESULT(result);
	result = net_nfc_set_response_callback (net_nfc_test_reader_cb, (void *)1);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );

/*
	PRINT_INFO("operation is end");

	result = net_nfc_unset_response_callback ();

	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);

*/

	return test_case_result;
}


/*=================================================================================*/

static void net_nfc_test_write_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h handle;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle (target_info, &handle);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target id: %X\n", handle);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			tag_handle = handle;

			if (is_ndef){

				net_nfc_error_e error = NET_NFC_OK;
				ndef_message_h msg = NULL;
				ndef_record_h record = NULL;

				if( (error = net_nfc_create_uri_type_record(&record, "http://www.naver.com", NET_NFC_SCHEMA_FULL_URI)) == NET_NFC_OK)
				{
					if( (error = net_nfc_create_ndef_message(&msg)) == NET_NFC_OK)
					{
						if( (error = net_nfc_append_record_to_ndef_message(msg, record)) == NET_NFC_OK)
						{
							////net_nfc_ndef_print_message(msg);
							net_nfc_write_ndef(tag_handle, msg, &user_context);
							net_nfc_free_ndef_message(msg);
						}
						else
						{
							PRINT_INFO("failed to append ndef message = [%d]", error);
							net_nfc_free_record(record);
							net_nfc_free_ndef_message(msg);

							pthread_mutex_lock (&plock);
							pthread_cond_signal (&pcond);
							pthread_mutex_unlock (&plock);
						}
					}
					else
					{
						PRINT_INFO("failed to create ndef msg");
						net_nfc_free_record(record);

						pthread_mutex_lock (&plock);
						pthread_cond_signal (&pcond);
						pthread_mutex_unlock (&plock);
					}
				}
				else
				{
					PRINT_INFO("failed to create text type record");

					pthread_mutex_lock (&plock);
					pthread_cond_signal (&pcond);
					pthread_mutex_unlock (&plock);
				}
			}
			else{
				PRINT_INSTRUCT("Please use NDEF formated tag!!");
				break;
			}

			break;
		}
		case NET_NFC_MESSAGE_TAG_DETACHED:
		{
			if (write_count++ >= 20) {
				test_case_result = NET_NFC_TEST_OK;
				pthread_mutex_lock (&plock);
				pthread_cond_signal (&pcond);
				pthread_mutex_unlock (&plock);
			}
			else {
				PRINT_INSTRUCT("Please close a tag to device again!!");
			}
		}
		break;

		case NET_NFC_MESSAGE_WRITE_NDEF:
		{
			/*if (result == NET_NFC_OK) {
				test_case_result = NET_NFC_TEST_OK;
			}
			else {
				PRINT_INFO("received error: %d\n", result);
				test_case_result = NET_NFC_TEST_FAIL;
			}
			*/

		/*	pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);
		*/

			if(write_count++ == 20)
			{

				PRINT_INSTRUCT("completed, please remove tag");
			}

			{

				net_nfc_error_e error = NET_NFC_OK;
				ndef_message_h msg = NULL;
				ndef_record_h record = NULL;

				if( (error = net_nfc_create_text_type_record(&record, "This is real NFC", "en-US", NET_NFC_ENCODE_UTF_8)) == NET_NFC_OK)
				{
					if( (error = net_nfc_create_ndef_message(&msg)) == NET_NFC_OK)
					{
						if( (error = net_nfc_append_record_to_ndef_message(msg, record)) == NET_NFC_OK)
						{
							////net_nfc_ndef_print_message(msg);
							net_nfc_write_ndef(tag_handle, msg, &user_context);
							net_nfc_free_ndef_message(msg);
						}
						else
						{
							PRINT_INFO("failed to append ndef message = [%d]", error);
							net_nfc_free_record(record);
							net_nfc_free_ndef_message(msg);
							test_case_result = NET_NFC_TEST_FAIL;

							pthread_mutex_lock (&plock);
							pthread_cond_signal (&pcond);
							pthread_mutex_unlock (&plock);
						}
					}
					else
					{
						PRINT_INFO("failed to create ndef msg");
						net_nfc_free_record(record);
						test_case_result = NET_NFC_TEST_FAIL;

						pthread_mutex_lock (&plock);
						pthread_cond_signal (&pcond);
						pthread_mutex_unlock (&plock);
					}
				}
				else
				{
					PRINT_INFO("failed to create text type record");
					test_case_result = NET_NFC_TEST_FAIL;

					pthread_mutex_lock (&plock);
					pthread_cond_signal (&pcond);
					pthread_mutex_unlock (&plock);

				}
			}

			break;
		}
		default:
			break;
	}
}


int nfcTestWriteMode(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();
	CHECK_RESULT(result);

	net_nfc_state_activate(1);

	result = net_nfc_set_response_callback (net_nfc_test_write_cb, NULL);
	CHECK_RESULT(result);

	write_count = 0;
	PRINT_INSTRUCT("TEST: remove tag while write");
	PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );

/*
	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
*/
	return test_case_result;

}


int nfcTestReadWriteMode(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	read_count = 0;
	write_count = 0;

	result = net_nfc_initialize();
	CHECK_RESULT(result);

	net_nfc_state_activate(1);

	result = net_nfc_set_response_callback (net_nfc_test_read_write_cb, NULL);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("Testing (50 each) read and write test");
	PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );
/*
	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
*/


	return test_case_result;

}

/*=================================================================================*/

static void net_nfc_test_transceive_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	printf ("callback is called with message %d\n", message);
	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h id;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;
			net_nfc_error_e result = NET_NFC_OK;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle (target_info, &id);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target id: %X\n", id);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			tag_handle = id;

			if(type == NET_NFC_MIFARE_ULTRA_PICC){

				if((result = net_nfc_mifare_read(tag_handle, 0, NULL)) != NET_NFC_OK){
					PRINT_INFO("failed to read = [%d]", result);
				}
			}

			else if(type >= NET_NFC_MIFARE_MINI_PICC && type <= NET_NFC_MIFARE_4K_PICC){

				data_h mad_key = NULL;
				data_h net_nfc_forum_key = NULL;
				data_h default_key = NULL;

				net_nfc_mifare_create_application_directory_key(&mad_key);
				net_nfc_mifare_create_net_nfc_forum_key(&net_nfc_forum_key);
				net_nfc_mifare_create_default_key(&default_key);

				int sector = 1;

				data_h key = NULL;
				test_count = 4;

				if(sector == 0){
					key = mad_key;
				}
				else{
					key = default_key;
//					key = net_nfc_forum_key;
				}

//				if(net_nfc_mifare_authenticate_with_keyB(id, sector, key, NULL) != NET_NFC_OK){
				if(net_nfc_mifare_authenticate_with_keyA(id, sector, default_key, NULL) != NET_NFC_OK){
					PRINT_INFO("failed to authenticate sector");

				}
				else{

					int nBlocks = 0;

					if(type == NET_NFC_MIFARE_4K_PICC && sector > 31){

						nBlocks = 16;
					}
					else{
						nBlocks = 4;
					}


/*
					int j = 0;

					for(; j < nBlocks; j++){
						if((result = net_nfc_mifare_read(tag_handle, sector * 4 + j, NULL)) != NET_NFC_OK){
							PRINT_INFO("failed to read = [%d]", result);
						}else{
							PRINT_INFO("block [%d] is read", sector * 4 + j);
						}
					}
*/
/*
					data_h write_block = NULL;
					uint8_t buffer[16] = {0x00,};
					uint8_t* temp = buffer;

					int value = 1000;
					int value_comp = 1 + ~value;
					uint8_t addr = 5;
					uint8_t addr_comp = 1 + ~addr;


					// read block 5 and write block 5 and read again
					if((result = net_nfc_mifare_read(tag_handle, addr, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read = [%d]", result);
					}else{
						PRINT_INFO("block 5 is read");
					}

					// read block 5 and write block 5 and read again

					memcpy(temp, &value, sizeof(int));
					temp = temp + sizeof(int);

					memcpy(temp, &value_comp, sizeof(int));
					temp = temp + sizeof(int);

					memcpy(temp, &value, sizeof(int));
					temp = temp + sizeof(int);

					*temp = addr;
					temp = temp + 1;

					*temp = addr_comp;
					temp = temp + 1;

					*temp = addr;
					temp = temp + 1;

					*temp = addr_comp;

					net_nfc_create_data(&write_block, buffer, 16);

					if((result = net_nfc_mifare_write_block(tag_handle, addr, write_block,NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to write = [%d]", result);
					}else{
						PRINT_INFO("block 5 is written");
					}

					if((result = net_nfc_mifare_read(tag_handle, addr, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read = [%d]", result);
					}else{
						PRINT_INFO("block 5 is read");
					}
*/

					// read block 6 and decrease 6 and read again

/*
					if((result = net_nfc_mifare_read(tag_handle, 7, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read = [%d]", result);
					}else{
						PRINT_INFO("read sector trailor of sector 1. it will be a block 7 th");
					}
*/

/*
					data_h write_block = NULL;
					uint8_t buffer[16] = {0x00, 0x00, 0x03, 0xE8, 0xFF, 0xFF, 0xFC, 0x18, 0x00, 0x00, 0x03, 0xE8, 0x05, 0xFB, 0x05, 0xFB};

					net_nfc_create_data(&write_block, buffer, 16);

					if((result = net_nfc_mifare_write_block(tag_handle, 5, write_block, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to write = [%d]", result);
					}else{
						PRINT_INFO("block 5 is written");
					}


					if((result = net_nfc_mifare_read(tag_handle, 5, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read = [%d]", result);
					}else{
						PRINT_INFO("block 5 is read");
					}
*/


					if((result = net_nfc_mifare_read(tag_handle, 5, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read = [%d]", result);
					}


					int decrease_amount = 10; // 10 won

					if((result = net_nfc_mifare_decrement(tag_handle, 5, decrease_amount, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to decrease = [%d]", result);
					}else{
						PRINT_INFO("block 5 is decreased");
					}

					if((result = net_nfc_mifare_transfer(tag_handle, 5,  NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to transfer = [%d]", result);
					}else{
						PRINT_INFO("internal register is transfered to block 5");
					}

/*
					if((result = net_nfc_mifare_read(tag_handle, 5, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read = [%d]", result);
					}
*/

					net_nfc_free_data(mad_key);
					net_nfc_free_data(default_key);
					net_nfc_free_data(net_nfc_forum_key);

				}


			}
			else if(type == NET_NFC_JEWEL_PICC){

				if(net_nfc_jewel_read_id(id, NULL) != NET_NFC_OK){
					PRINT_INFO("failed to read ID");
				}

				test_count = 0;

			}else if(type == NET_NFC_FELICA_PICC){

				test_count = 4;
				net_nfc_error_e result = NET_NFC_OK;

/*
				if((result = net_nfc_felica_poll(id, NET_NFC_FELICA_POLL_COMM_SPEED_REQUEST, 0x0, NULL)) != NET_NFC_OK){
					PRINT_INFO("can not execute cmd felica poll");
				}
				else{
					PRINT_INFO("send poll req cmd is success");
				}

				if((result = net_nfc_felica_request_system_code(id, NULL)) != NET_NFC_OK){
					PRINT_INFO("can not execute cmd felica request system code");
				}
				else{
					PRINT_INFO("send request system req cmd is success");
				}

				if((result = net_nfc_felica_request_response(id, NULL)) != NET_NFC_OK){
					PRINT_INFO("can not execute cmd felica request response");
				}
				else{
					PRINT_INFO("send request response cmd is success");
				}

				uint16_t service_code = 0xffff;
				if((result = net_nfc_felica_request_service(id, 1, &service_code, 1, NULL)) != NET_NFC_OK){
					PRINT_INFO("can not execute cmd felica request response");
				}
				else{
					PRINT_INFO("send request response cmd is success");
				}
*/

				uint16_t service_code = 0xffff;
				uint8_t blocks = 0x2;

				if((result = net_nfc_felica_read_without_encryption(id, 1, &service_code, 1, &blocks, NULL)) != NET_NFC_OK){
					PRINT_INFO("can not execute cmd felica request response");
				}
				else{
					PRINT_INFO("send request response cmd is success");
				}
			}

			break;
		}
		case NET_NFC_MESSAGE_TRANSCEIVE:{
			if (result == NET_NFC_OK) {

				if(test_count == 0){
					int idx;
					data_h r_data = (data_h) data;

					uint8_t * r_buffer = net_nfc_get_data_buffer (r_data);
					uint32_t r_buffer_length = net_nfc_get_data_length (r_data);

					PRINT_INFO ("read uid is ok. format is = > [HeadRom0][HeadRom1][UID0][UID1][UID2][UID3]");
					PRINT_INFO ("Received data [size:%d] \n", net_nfc_get_data_length (r_data));

					for (idx = 0; idx < r_buffer_length; idx++){
						printf (" %02X", r_buffer[idx]);
					}printf ("\n");

					PRINT_INFO("READ ALL DATA");
					if((result = net_nfc_jewel_read_all(tag_handle, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read all jewel tag = [%d]", result);
					}

					test_count = 1;
				}
				else if(test_count == 1){
					int idx;
					data_h r_data = (data_h) data;

					uint8_t * r_buffer = net_nfc_get_data_buffer (r_data);
					uint32_t r_buffer_length = net_nfc_get_data_length (r_data);

					PRINT_INFO ("Received data [size:%d] \n", net_nfc_get_data_length (r_data));

					for (idx = 0; idx < r_buffer_length; idx++){
						printf (" %02X", r_buffer[idx]);
					}printf ("\n");

					test_case_result = NET_NFC_TEST_OK;

					// read UID0

					PRINT_INFO("READ one byte. addr is the first byte of block 0");
					if((result = net_nfc_jewel_read_byte(tag_handle, 0, 0, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read all jewel tag = [%d]", result);
					}

					test_count = 2;

				}
				else if(test_count == 2){
					int idx;
					data_h r_data = (data_h) data;

					uint8_t * r_buffer = net_nfc_get_data_buffer (r_data);
					uint32_t r_buffer_length = net_nfc_get_data_length (r_data);

					PRINT_INFO ("Received data [size:%d] \n", net_nfc_get_data_length (r_data));

					for (idx = 0; idx < r_buffer_length; idx++){
						printf (" %02X", r_buffer[idx]);
					}printf ("\n");

					test_case_result = NET_NFC_TEST_OK;

					// read UID0
					PRINT_INFO("erase and write data 0xff . addr is the first byte of block 1");
					if((result = net_nfc_jewel_write_with_erase(tag_handle,  1, 0, 0xff, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read all jewel tag = [%d]", result);
					}

					test_count = 3;
				}
				else if(test_count == 3){
					int idx;
					data_h r_data = (data_h) data;

					uint8_t * r_buffer = net_nfc_get_data_buffer (r_data);
					uint32_t r_buffer_length = net_nfc_get_data_length (r_data);

					PRINT_INFO ("Received data [size:%d] \n", net_nfc_get_data_length (r_data));

					for (idx = 0; idx < r_buffer_length; idx++){
						printf (" %02X", r_buffer[idx]);
					}printf ("\n");

					test_case_result = NET_NFC_TEST_OK;

					// read UID0
					PRINT_INFO("read one byte . addr is the first byte of block 1");
					if((result = net_nfc_jewel_read_byte(tag_handle, 1, 0, NULL)) != NET_NFC_OK){
						PRINT_INFO("failed to read all jewel tag = [%d]", result);
					}

					test_count = 4;
				}
				else if(test_count == 4){

					int idx;
					data_h r_data = (data_h) data;

					uint8_t * r_buffer = net_nfc_get_data_buffer (r_data);
					uint32_t r_buffer_length = net_nfc_get_data_length (r_data);

					PRINT_INFO ("Received data [size:%d] \n", net_nfc_get_data_length (r_data));

					for (idx = 0; idx < r_buffer_length; idx++){
						printf (" %02X", r_buffer[idx]);
					}printf ("\n");
				}
				else if(test_count == 5){
					PRINT_INFO("auth key A is success = [%d]", result);
					test_case_result = NET_NFC_TEST_OK;
					net_nfc_error_e result = NET_NFC_OK;
					/*
					if((result = net_nfc_mifare_read(tag_handle, 0, NULL)) != NET_NFC_OK){

						PRINT_INFO("failed to read = [%d]", result);
					}else{
						PRINT_INFO("calling read is ok");
					}

					test_count = 4;
					*/
				}
			}
			else {

				PRINT_INFO("trancecive is failed with  %d\n", result);
				test_case_result = NET_NFC_TEST_FAIL;

				//pthread_mutex_lock (&plock);
				//pthread_cond_signal (&pcond);
				//pthread_mutex_unlock (&plock);
			}
		}

		default:
			break;
	}
}


#define NUM_OF_THREAD 10
#define REQUEST_PER_THREAD 5

static number_of_read_completed = 0;

static void* net_nfc_read_ndef_test(void* handle)
{
	net_nfc_target_handle_h target_handle = (net_nfc_target_handle_h)handle;
	int count = 0;

	for (count = 0; count < REQUEST_PER_THREAD ; count ++)
	{
		if(net_nfc_read_tag(target_handle, NULL) == NET_NFC_OK)
		{
			PRINT_INFO("send request is success");
		}
		else
		{
			PRINT_INFO("send request is failed");
		}
	}

	return (void *)NULL;
}
static void net_nfc_test_multiple_request_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	printf ("callback is called with message %d\n", message);

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h handle;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle (target_info, &handle);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target handle: %X\n", handle);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			test_case_result = NET_NFC_TEST_OK;
			number_of_read_completed = 0;

			pthread_t read_thread[NUM_OF_THREAD];
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

			int i =0;
			for(; i < NUM_OF_THREAD; i++)
			{
				pthread_create(&read_thread[i], &attr, net_nfc_read_ndef_test, handle);
			}

		}
		break;

		case NET_NFC_MESSAGE_READ_NDEF:
		{
			PRINT_INFO("NET_NFC_MESSAGE_READ_NDEF result = [%d]\n", result);

			if(data != NULL)
			{
				PRINT_INFO("read ndef msg");
				number_of_read_completed ++;

				ndef_message_h ndef = (ndef_message_h)(data);

				////net_nfc_ndef_print_message(ndef);

				if (number_of_read_completed == NUM_OF_THREAD * REQUEST_PER_THREAD)
				{
					test_case_result = NET_NFC_TEST_OK;
					PRINT_INSTRUCT("Test is completed. please remove the tag !!");
				}
			}
		}
		break;

		case NET_NFC_MESSAGE_TAG_DETACHED:
		{
			PRINT_INFO("NET_NFC_MESSAGE_TAG_DETACHED \n");

			pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);
		}
		break;

		case NET_NFC_MESSAGE_NOTIFY:
		{
			PRINT_INFO("NET_NFC_MESSAGE_NOTIFY \n");
		}
		break;

		default:
			break;
	}
}

#define NUM_OF_DETECT_TRY 10

static void net_nfc_test_detected_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	printf ("callback is called with message %d\n", message);

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h id;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle (target_info, &id);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);

			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target handle: %X\n", id);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			char** keys = NULL;
			int nok = 0; // number of keys
			net_nfc_error_e error = NET_NFC_OK;

			if((error = net_nfc_get_tag_info_keys(target_info, &keys, &nok)) == NET_NFC_OK)
			{
				int i = 0;
				for(; i < nok; i++)
				{
					PRINT_INFO("key [%s]", keys[i]);

					data_h value = NULL;
					if((error = net_nfc_get_tag_info_value(target_info, keys[i], &value)) == NET_NFC_OK)
					{
						int index = 0;
						uint32_t data_length = net_nfc_get_data_length(value);
						uint8_t* data_buffer = net_nfc_get_data_buffer(value);

						PRINT_INFO("\n key >> ", keys[i]);
						if(data_length > 1)
						{
							for(; index < data_length; index++)
							{
								printf(" [0x%x] ", data_buffer[index]);
							}
						}
						else
						{
							printf(" [0x%x] ", *data_buffer);
						}


						PRINT_INFO("<< \n");
					}
					else
					{
						PRINT_INFO("get value is failed = [0x%x]", error);
					}
				}
			}
			else
			{
				PRINT_INFO("failed to get keys = [%d]", error);
			}

			free(keys);


			detect_count++;

			PRINT_INFO("TAG is detected = [%d]", detect_count);
			PRINT_INSTRUCT("please remove the tag !! Test left [%d] times", NUM_OF_DETECT_TRY - detect_count);

		}
		break;

		case NET_NFC_MESSAGE_TAG_DETACHED:
		{
			PRINT_INSTRUCT("please close the tag again!!");

			//pthread_mutex_lock (&plock);
			//pthread_cond_signal (&pcond);
			//pthread_mutex_unlock (&plock);

			if(detect_count >= NUM_OF_DETECT_TRY)
			{
				test_case_result = NET_NFC_TEST_OK;
				pthread_mutex_lock (&plock);
				pthread_cond_signal (&pcond);
				pthread_mutex_unlock (&plock);
			}
		}
		break;

		case NET_NFC_MESSAGE_NOTIFY:
		{
			PRINT_INFO("NET_NFC_MESSAGE_NOTIFY \n");
		}
		break;

		default:
			break;
	}
}


static void* net_nfc_read_stress_ndef_test(void* handle)
{
	net_nfc_target_handle_h target_handle = (net_nfc_target_handle_h)handle;
	int count = 0;

	for (count = 0; count < 200 ; count ++)
	{
		if(net_nfc_read_tag(target_handle, NULL) == NET_NFC_OK)
		{
		}
		else
		{
			PRINT_INFO("send request is failed");
		}
	}

	PRINT_INFO("send request is completed");

	return (void *)NULL;
}

static void net_nfc_test_read_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h handle;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle (target_info, &handle);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target handle: %X\n", handle);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			if(is_ndef)
			{
				pthread_t read_thread;
				pthread_attr_t attr;
				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

				pthread_create(&read_thread, &attr, net_nfc_read_stress_ndef_test, handle);
			}
			else
			{
				PRINT_INFO("non ndef tag.");

				test_case_result = NET_NFC_TEST_FAIL;

				pthread_mutex_lock (&plock);
				pthread_cond_signal (&pcond);
				pthread_mutex_unlock (&plock);
			}

		}
		break;

		case NET_NFC_MESSAGE_READ_NDEF:
		{
			if(data != NULL){

				ndef_message_h ndef = (ndef_message_h)(data);

				////net_nfc_ndef_print_message(ndef);

				test_case_result = NET_NFC_TEST_OK;

				read_count++;
			}

			if(read_count == 20)
			{
				PRINT_INSTRUCT("please remove the tag !!");
			}

			break;
		}
		break;

		case NET_NFC_MESSAGE_TAG_DETACHED:
		{
			PRINT_INFO("NET_NFC_MESSAGE_TAG_DETACHED \n");

			if (read_count >= 20 && read_count < 200){
				test_case_result = NET_NFC_TEST_OK;
					pthread_mutex_lock (&plock);
					pthread_cond_signal (&pcond);
					pthread_mutex_unlock (&plock);
			}
			else {
				PRINT_INSTRUCT("please close the tag again !!");
			}


		}
		break;

		case NET_NFC_MESSAGE_NOTIFY:
		{
			PRINT_INFO("NET_NFC_MESSAGE_NOTIFY \n");
		}
		break;

		default:
			break;
	}
}


static void net_nfc_test_read_write_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	int user_context;

	printf ("callback is called with message %d\n", message);

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{
			net_nfc_target_type_e type;
			net_nfc_target_handle_h handle;
			bool is_ndef;
			net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;

			net_nfc_get_tag_type (target_info, &type);
			net_nfc_get_tag_handle (target_info, &handle);
			net_nfc_get_tag_ndef_support (target_info, &is_ndef);
			PRINT_INFO("target type: %d\n", type);
			PRINT_INFO("target handle: %X\n", handle);
			PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

			if(is_ndef)
			{
				tag_handle = handle;
				if(net_nfc_read_tag(handle, user_param) == NET_NFC_OK)
				{
					PRINT_INFO("try to read ndef");
				}
			}
			else
			{
				PRINT_INFO("non ndef tag.");

				test_case_result = NET_NFC_TEST_FAIL;

				pthread_mutex_lock (&plock);
				pthread_cond_signal (&pcond);
				pthread_mutex_unlock (&plock);
			}

		}
		break;

		case NET_NFC_MESSAGE_READ_NDEF:
		{
			if (write_count >= 50){
				PRINT_INSTRUCT("Test is finished. Please remove the tag from device!!");
				test_case_result = NET_NFC_TEST_OK;
				break;
			}
			if(data != NULL){

				ndef_message_h ndef = (ndef_message_h)(data);

				////net_nfc_ndef_print_message(ndef);

				test_case_result = NET_NFC_TEST_OK;

				net_nfc_error_e error = NET_NFC_OK;
				ndef_message_h msg = NULL;
				ndef_record_h record = NULL;

				if( (error = net_nfc_create_text_type_record(&record, "This is real NFC", "en-US", NET_NFC_ENCODE_UTF_8)) == NET_NFC_OK)
				{
					if( (error = net_nfc_create_ndef_message(&msg)) == NET_NFC_OK)
					{
						if( (error = net_nfc_append_record_to_ndef_message(msg, record)) == NET_NFC_OK)
						{
							////net_nfc_ndef_print_message(msg);

							if(net_nfc_write_ndef(tag_handle, msg, &user_context) == NET_NFC_OK)
							{
								PRINT_INFO("write count = [%d] \n", write_count++);
								PRINT_INFO("write ndef msg");
							}
							net_nfc_free_ndef_message(msg);
						}
						else
						{
							PRINT_INFO("failed to append ndef message = [%d]", error);
							net_nfc_free_record(record);
							net_nfc_free_ndef_message(msg);

							pthread_mutex_lock (&plock);
							pthread_cond_signal (&pcond);
							pthread_mutex_unlock (&plock);
						}
					}
					else
					{
						PRINT_INFO("failed to create ndef msg");
						net_nfc_free_record(record);

						pthread_mutex_lock (&plock);
						pthread_cond_signal (&pcond);
						pthread_mutex_unlock (&plock);
					}
				}
				else
				{
					PRINT_INFO("failed to create text type record");

					pthread_mutex_lock (&plock);
					pthread_cond_signal (&pcond);
					pthread_mutex_unlock (&plock);

				}

			}
			else
			{
				test_case_result = NET_NFC_TEST_FAIL;

				pthread_mutex_lock (&plock);
				pthread_cond_signal (&pcond);
				pthread_mutex_unlock (&plock);

				break;
			}

			//net_nfc_read_ndef(tag_handle, user_param);

			break;
		}
		break;

		case NET_NFC_MESSAGE_WRITE_NDEF:
		{
			if (result == NET_NFC_OK) {

				test_case_result = NET_NFC_TEST_OK;

				if(net_nfc_read_tag(tag_handle, user_param) == NET_NFC_OK)
				{
					PRINT_INFO("read count = [%d] \n", read_count++);
					PRINT_INFO("try to read ndef");
				}
			}
			else {
				PRINT_INFO("received error: %d\n", result);
				test_case_result = NET_NFC_TEST_FAIL;

				pthread_mutex_lock (&plock);
				pthread_cond_signal (&pcond);
				pthread_mutex_unlock (&plock);
			}
		}
		break;

		case NET_NFC_MESSAGE_TAG_DETACHED:
		{
			PRINT_INFO("NET_NFC_MESSAGE_TAG_DETACHED \n");

			pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);
		}
		break;

		case NET_NFC_MESSAGE_NOTIFY:
		{
			PRINT_INFO("NET_NFC_MESSAGE_NOTIFY \n");
		}
		break;

		default:
			break;
	}
}


int nfcTestAPIMultipleRequest(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();
	CHECK_RESULT(result);

	net_nfc_state_activate(1);

	result = net_nfc_set_response_callback (net_nfc_test_multiple_request_cb, NULL);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("Please close a tag to device for a while!!");

	//pthread_cond_wait (&pcond,&plock );
/*
	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);

	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
*/
	return test_case_result;
}


int nfcTestAPIBasicTest1(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	int length = 0;

/*
	char** keys = NULL;

	int i = 0;

	for(i; i < NET_NFC_NFCIP1_INITIATOR; i++)
	{
		if(net_nfc_get_tag_info_keys(i, &keys, &length) == NET_NFC_OK)
		{
			int index = 0;

			PRINT_INFO("############################\n") ;
			for(; index < length; index++)
			{
				PRINT_INFO("supported key = [%s] \n", keys[index]);
			}
			PRINT_INFO("############################\n")	;

			test_case_result = NET_NFC_TEST_OK;
		}
	}
*/

	result = net_nfc_initialize();
	CHECK_RESULT(result);

	net_nfc_state_activate(1);

	result = net_nfc_set_response_callback (net_nfc_test_detected_cb, NULL);

//	net_nfc_set_tag_filter(NET_NFC_ALL_DISABLE);
//	net_nfc_set_tag_filter(NET_NFC_ISO14443A_ENABLE);
//	net_nfc_set_tag_filter(NET_NFC_ISO14443B_ENABLE);
//	net_nfc_set_tag_filter(NET_NFC_ISO15693_ENABLE );
//	net_nfc_set_tag_filter(NET_NFC_FELICA_ENABLE );
//	net_nfc_set_tag_filter(NET_NFC_JEWEL_ENABLE );
//	net_nfc_set_tag_filter(NET_NFC_ALL_ENABLE );


	CHECK_RESULT(result);

	//PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );

/*
	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);

	result = net_nfc_deinitialize ();

	sleep(1000);

	CHECK_RESULT(result);
*/

	return test_case_result;
}

int nfcTestAPIBasicTest2(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();
	CHECK_RESULT(result);

	net_nfc_state_activate(1);

	read_count = 0;

	result = net_nfc_set_response_callback (net_nfc_test_read_cb, NULL);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("remove tag while reading operation !!");
	PRINT_INSTRUCT("Please close a tag to device!!");

/*
	pthread_cond_wait (&pcond,&plock );

	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);

	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
*/
	return test_case_result;
}

int nfcTestAPIBasicTest3(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	ndef_message_h ndef_message = NULL;

	if(net_nfc_retrieve_current_ndef_message(&ndef_message) == NET_NFC_OK)
	{
		int count = 0;
		if(net_nfc_get_ndef_message_record_count(ndef_message, &count) == NET_NFC_OK)
		{
			int i = 0;
			for(; i < count; i++)
			{
				ndef_record_h record = NULL;
				if(net_nfc_get_record_by_index(ndef_message, i, &record) == NET_NFC_OK)
				{
					net_nfc_record_tnf_e tnf;
					if(net_nfc_get_record_tnf(record, &tnf) == NET_NFC_OK)
					{
						switch(tnf)
						{
							case NET_NFC_RECORD_WELL_KNOWN_TYPE:
							{
								data_h type = NULL;
								data_h payload = NULL;

								if(net_nfc_get_record_type(record, &type) == NET_NFC_OK && net_nfc_get_record_payload(record, &payload) == NET_NFC_OK)
								{
									if(strcmp(net_nfc_get_data_buffer(type), "Sp") == 0)
									{

									}
									else if(strcmp(net_nfc_get_data_buffer(type), "T") == 0)
									{

										net_nfc_encode_type_e utf;
										uint32_t utf_length = 0;
										uint32_t lang_length = 0;
										char* text = NULL;
										uint32_t text_length = 0;
										char* language_code_str = NULL;

										if(net_nfc_get_encoding_type_from_text_record(record, &utf) == NET_NFC_OK)
										{
											PRINT_INFO("utf = [%s]", utf);
										}
										else
										{
											PRINT_INFO("failed to get utf");
										}

										if(net_nfc_get_languange_code_string_from_text_record(record, &language_code_str) == NET_NFC_OK)
										{
											PRINT_INFO("language_code = [%s]", language_code_str);
										}
										else
										{
											PRINT_INFO("failed to get language code");
										}

										if(net_nfc_create_text_string_from_text_record(record, &text) == NET_NFC_OK)
										{
											PRINT_INFO("text = [%s]", text);
										}
										else
										{
											PRINT_INFO("failed to get text");
										}

										if(text != NULL)
											free(text);
/*
										uint8_t* utf = NULL;
										uint8_t* language_code = NULL;
										uint8_t* text = NULL;
										int index = 0;

										uint8_t* buffer = net_nfc_get_data_buffer(payload);
										uint32_t buffer_length = net_nfc_get_data_length(payload);

										PRINT_INFO("\n from file >>>");

										for(; index < buffer_length; index++)
										{
											printf(" [%d] ", buffer[index]);
										}

										PRINT_INFO("\n from file <<<");

										index = 0;

										int controllbyte = buffer[0];

										if((controllbyte & 0x80)== 1)
										{
											PRINT_INFO("UTF-16");
											utf = (uint8_t*)"UTF-16";
										}
										else
										{
											PRINT_INFO("UTF-8");
											utf = (uint8_t*)"UTF-8";
										}

										int lang_code_length = controllbyte & 0x3F;

										index = 1;

										language_code = (uint8_t *)malloc(lang_code_length + 1);

										memset(language_code, 0x00, lang_code_length + 1);
										memcpy(language_code, &(buffer[index]), lang_code_length);

										PRINT_INFO("lang_code = [%s]", language_code);

										index = lang_code_length + 1;

										int text_length = buffer_length - (lang_code_length + 1); // payload length - (lang code length + control byte)

										PRINT_INFO("buffer length = [%d]", buffer_length);
										PRINT_INFO("lang_code_length = [%d]", lang_code_length);
										PRINT_INFO("text_length = [%d]", text_length);

										text = (uint8_t *)malloc(text_length + 1);

										memset(text, 0x00, text_length + 1);
										memcpy(text, &(buffer[index]), text_length);

										PRINT_INFO("encoding type = [%s]", utf);
										PRINT_INFO("lang_code = [%s]", language_code);
										PRINT_INFO("text = [%s]", text);
										test_case_result = NET_NFC_TEST_OK;
*/
									}
									else if(strcmp(net_nfc_get_data_buffer(type), "U") == 0)
									{

									}
									else
									{

									}
								}

							}
							break;

							default:
								PRINT_INFO("unknow type");
							break;
						}
					}
				}
			}
		}
	}


	CHECK_RESULT(result);

	return test_case_result;
}

int nfcTestTransceive(uint8_t testNumber,void* arg_ptr2)
{
	int user_context = 0;
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	result = net_nfc_initialize();
	CHECK_RESULT(result);

	net_nfc_state_activate(1);

	result = net_nfc_set_response_callback (net_nfc_test_transceive_cb, NULL);
	CHECK_RESULT(result);

	PRINT_INSTRUCT("Please close a tag to device!!");

	//pthread_cond_wait (&pcond,&plock );
	/*
	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
	*/

	return test_case_result;
}

/*=================================================================================*/


int nfcTestNdefParser(uint8_t testNumber,void* arg_ptr2)
{
	net_nfc_error_e result;

	ndef_message_h uriMsg = NULL;
	ndef_message_h spMsg = NULL;
	ndef_record_h  uriRecord  = NULL;
	ndef_record_h  spRecord = NULL;
	data_h type_data = NULL;
	data_h raw_data = NULL;
	char smart_poster_type[] = "Sp";
	ndef_record_h record = NULL;
	test_case_result = NET_NFC_TEST_OK;

	result = net_nfc_create_ndef_message (&uriMsg);
	CHECK_RESULT(result);

	result = net_nfc_create_uri_type_record (&record ,"http://www.naver.com", NET_NFC_SCHEMA_FULL_URI);
	CHECK_RESULT(result);

	result = net_nfc_append_record_to_ndef_message (uriMsg, record);
	CHECK_RESULT(result);

	uriRecord = record;

	result = net_nfc_create_text_type_record (&record ,"This is the URI Test" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	CHECK_RESULT(result);

	result = net_nfc_append_record_to_ndef_message (uriMsg, record);
	CHECK_RESULT(result);

	result = net_nfc_create_text_type_record (&record ,"Hello World" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	CHECK_RESULT(result);

	result = net_nfc_append_record_by_index (uriMsg,0 ,record);
	CHECK_RESULT(result);

	result = net_nfc_create_text_type_record (&record ,"TEST1" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	CHECK_RESULT(result);

	result = net_nfc_append_record_by_index (uriMsg,1 ,record);
	CHECK_RESULT(result);

	result = net_nfc_create_text_type_record (&record ,"TEST2" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	CHECK_RESULT(result);

	result = net_nfc_append_record_by_index (uriMsg,2 ,record);
	CHECK_RESULT(result);

	result = net_nfc_create_text_type_record (&record ,"TEST3" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	CHECK_RESULT(result);

	int position;
	result = net_nfc_get_ndef_message_record_count (uriMsg,&position);
	CHECK_RESULT(result);

	result = net_nfc_append_record_by_index (uriMsg, position ,record);
	CHECK_RESULT(result);

	//_//net_nfc_ndef_print_message (uriMsg);

	result = net_nfc_create_data (&type_data ,"U", 1);
	CHECK_RESULT(result);

	result = net_nfc_search_record_by_type (uriMsg ,NET_NFC_RECORD_WELL_KNOWN_TYPE ,type_data ,&record);
	CHECK_RESULT(result);
	if (record != uriRecord){
		PRINT_RESULT_FAIL("Record search result does not matched");
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_remove_record_by_index (uriMsg ,1);
	CHECK_RESULT(result);

	result = net_nfc_remove_record_by_index (uriMsg ,0);
	CHECK_RESULT(result);

	result = net_nfc_get_ndef_message_record_count (uriMsg,&position);
	CHECK_RESULT(result);

	result = net_nfc_remove_record_by_index (uriMsg, position - 1);
	CHECK_RESULT(result);

	result = net_nfc_remove_record_by_index (uriMsg ,2);
	CHECK_RESULT(result);

	//_//net_nfc_ndef_print_message (uriMsg);

	result = net_nfc_create_rawdata_from_ndef_message (uriMsg, &raw_data);
	CHECK_RESULT(result);

	result = net_nfc_create_data (&type_data, smart_poster_type, strlen (smart_poster_type));
	CHECK_RESULT(result);

	result = net_nfc_create_record (&spRecord, NET_NFC_RECORD_WELL_KNOWN_TYPE,type_data , NULL, raw_data);
	CHECK_RESULT(result);

	result = net_nfc_create_ndef_message (&spMsg);
	CHECK_RESULT(result);

	result = net_nfc_append_record_to_ndef_message (spMsg, spRecord);
	CHECK_RESULT(result);

	net_nfc_free_data (type_data);
	net_nfc_free_data (raw_data);

	return test_case_result;
}

/*=================================================================================*/

net_nfc_llcp_socket_t server_socket;
net_nfc_llcp_socket_t accepted_socket;
net_nfc_llcp_socket_t client_socket;

static void net_nfc_client_socket_cb (net_nfc_llcp_message_e message, net_nfc_error_e result, void * data, void * user_data, void * trans_data)
{
	PRINT_INFO ("\nCLIENT callback is called MESSAGE[%d]", message);
	int x;
	switch (message)
	{
		case NET_NFC_MESSAGE_LLCP_LISTEN:
		break;
		case NET_NFC_MESSAGE_LLCP_ACCEPTED:
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT:
		{
			PRINT_INFO ("LLCP connect is completed with error code %d", result);
			data_h data;
			char * str = "Client message: Hello, server!";
			net_nfc_create_data (&data, str ,strlen (str) + 1);
			net_nfc_send_llcp (client_socket, data, NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT_SAP:
		break;
		case NET_NFC_MESSAGE_LLCP_SEND:
		{
			PRINT_INFO ("LLCP send is completed with error code %d", result);
			net_nfc_receive_llcp (client_socket, 512 ,NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_RECEIVE:
			PRINT_INFO ("LLCP receive is completed with error code %d", result);
			data_h received_data = (data_h) data;
			PRINT_INFO ("Server --> Client : %s" , net_nfc_get_data_buffer (received_data));

			net_nfc_disconnect_llcp (client_socket ,NULL);
		break;
		case NET_NFC_MESSAGE_LLCP_DISCONNECT:
		{
			PRINT_INFO ("LLCP disconnect is completed with error code %d", result);
			net_nfc_close_llcp_socket (client_socket, NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_ERROR:
			PRINT_INFO ("LLCP socket error is completed with error code %d", result);
			net_nfc_close_llcp_socket (client_socket, NULL);
		break;
		default:
		break;
	}

}


static void net_nfc_server_socket_cb (net_nfc_llcp_message_e message, net_nfc_error_e result, void * data, void * user_data, void * trans_data)
{
	PRINT_INFO ("\nSERVER callback is called MESSAGE[%d]", message);
	switch (message)
	{
		case NET_NFC_MESSAGE_LLCP_LISTEN:
		{
			PRINT_INFO ("LLCP Listen is completed with error code %d", result);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_ACCEPTED:
		{
			PRINT_INFO ("LLCP accept is completed with error code %d", result);
			accepted_socket = *(net_nfc_llcp_socket_t *)(data);
			net_nfc_set_llcp_socket_callback (accepted_socket, net_nfc_server_socket_cb, NULL);
			net_nfc_receive_llcp (accepted_socket, 512 ,NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT:
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT_SAP:
		break;
		case NET_NFC_MESSAGE_LLCP_SEND:
		{
			PRINT_INFO ("LLCP send is completed with error code %d", result);
			net_nfc_disconnect_llcp (accepted_socket ,NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_RECEIVE:
		{
			PRINT_INFO ("LLCP receive is completed with error code %d", result);
			data_h received_data = (data_h) data;
			PRINT_INFO ("Server <-- Client : %s" , net_nfc_get_data_buffer (received_data));

			data_h data;
			char * str = "Server message: Welcome NFC llcp world!";
			net_nfc_create_data (&data, str ,strlen (str) + 1);
			net_nfc_send_llcp (accepted_socket, data, NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_DISCONNECT:
		{
			PRINT_INFO ("LLCP disconnect is completed with error code %d", result);
			net_nfc_close_llcp_socket (accepted_socket, NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_ERROR:
		{
			PRINT_INFO ("LLCP socket error is received with code %d", result);
			net_nfc_close_llcp_socket (accepted_socket, NULL);
			net_nfc_close_llcp_socket (server_socket, NULL);
		}
		break;
		default:
		break;
	}
}

net_nfc_target_handle_h snep_handle;
net_nfc_exchanger_data_h snep_ex_data = NULL;
int temp_count;

static void net_nfc_test_snep_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	PRINT_INFO ("client message received [%d]", message);

	switch (message) {
#if 0
		case NET_NFC_MESSAGE_P2P_DISCOVERED:
		{
			snep_handle = (net_nfc_target_handle_h) data;
			//= (net_nfc_target_handle_h) target_info->handle;
			/* Fill the data to send. */

			if(NET_NFC_OK == net_nfc_create_exchanger_data(&snep_ex_data, nfcTestUri))
			{
				if(net_nfc_send_exchanger_data(snep_ex_data,  snep_handle) == NET_NFC_OK)
				{
					PRINT_INFO ("exchanger data send success");
				}
				else
				{
					PRINT_INFO ("exchanger data send fail");
				}
			}
			else
			{
				PRINT_INFO ("create exchanger data fail");
			}

		}
		break;
#endif
		case NET_NFC_MESSAGE_P2P_SEND:
		{
			PRINT_INFO ("NET_NFC_MESSAGE_P2P_SEND result [%d]", result);

		}
		break;

		case NET_NFC_MESSAGE_P2P_DETACHED:
		{
			PRINT_INFO ("Target disconnected.");
			temp_count = 0;
		}
		break;

		case NET_NFC_MESSAGE_P2P_RECEIVE:
		{
//			int i;
//			data_h received_data = (data_h)data;

//			PRINT_INFO ("NET_NFC_MESSAGE_P2P_RECEIVE [%s]", net_nfc_get_data_buffer(received_data));
//			PRINT_INFO ("	length [%d]", net_nfc_get_data_length(received_data));
		}
		break;

		default:
		break;
	}
}

static void net_nfc_test_llcp_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	// do nothing
	switch (message) {
		case NET_NFC_MESSAGE_LLCP_DISCOVERED:
		{
			net_nfc_llcp_config_info_h config =  (net_nfc_llcp_config_info_h) data;
			uint8_t lto, option;
			uint16_t wks, miu;
			net_nfc_get_llcp_configure_lto (config , &lto);
			net_nfc_get_llcp_configure_wks (config , &wks);
			net_nfc_get_llcp_configure_miu (config , &miu);
			net_nfc_get_llcp_configure_option (config , &option);

			PRINT_INFO ("Remote Device llcp info:\n \tlto: %d, \twks: %d, \tmiu: %d, \toption: %d", lto, wks, miu, option);

			net_nfc_create_llcp_socket (&server_socket, NULL);
			net_nfc_set_llcp_socket_callback (server_socket, net_nfc_server_socket_cb, NULL);
			net_nfc_listen_llcp (server_socket, "urn:nfc:xsn:samsung.com:testllcp" ,16 ,NULL);

			net_nfc_create_llcp_socket (&client_socket, NULL);
			net_nfc_set_llcp_socket_callback (client_socket, net_nfc_client_socket_cb, NULL);
			net_nfc_connect_llcp (client_socket,"urn:nfc:xsn:samsung.com:testllcp",NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_CONFIG:
		{
			PRINT_INFO ("LLCP llcp local config is completed with error code %d", result);
		}
		break;

		case NET_NFC_MESSAGE_P2P_DETACHED:
		{
			PRINT_INFO ("LLCP NET_NFC_MESSAGE_P2P_DETACHED %d", result);
		}
		break;

		default:
		break;
	}
}

int nfcTestSnep(uint8_t testNumber,void* arg_ptr)
{
	net_nfc_error_e result;

	result = net_nfc_initialize();
	CHECK_RESULT(result);
	net_nfc_state_activate (1);
	result = net_nfc_set_response_callback (net_nfc_test_snep_cb, NULL);

	PRINT_INSTRUCT("START SNEP test !!");
	return NET_NFC_TEST_OK;
}

int nfcTestLLCP(uint8_t testNumber,void* arg_ptr2)
{
	net_nfc_error_e result;
	net_nfc_llcp_config_info_h config;
	result = net_nfc_initialize();
	CHECK_RESULT(result);
	net_nfc_state_activate (1);
	result = net_nfc_set_response_callback (net_nfc_test_llcp_cb, NULL);
	CHECK_RESULT(result);
	result = net_nfc_create_llcp_configure_default (&config);
	CHECK_RESULT(result);
	result = net_nfc_set_llcp_local_configure (config ,NULL);

	PRINT_INSTRUCT("Please start P2P communicate!!");

/*
	pthread_cond_wait (&pcond,&plock );

	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
*/

	return NET_NFC_TEST_OK;
}

/*=================================================================================*/

/* LLCP Stress Test */

net_nfc_llcp_socket_t server_socket;
net_nfc_llcp_socket_t client_socket;

static void net_nfc_client_stress_socket_cb (net_nfc_llcp_message_e message, net_nfc_error_e result, void * data, void * user_data, void * trans_data)
{
	PRINT_INFO ("\nCLIENT callback is called MESSAGE[%d]", message);
	int x;
	switch (message)
	{
		case NET_NFC_MESSAGE_LLCP_LISTEN:
		break;
		case NET_NFC_MESSAGE_LLCP_ACCEPTED:
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT:
		{
			PRINT_INFO ("LLCP connect is completed with error code %d", result);
			data_h data;
			char * str = "Client message: Hello, server!";
			net_nfc_create_data (&data, str ,strlen (str) + 1);
			net_nfc_send_llcp (client_socket, data, NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT_SAP:
		break;
		case NET_NFC_MESSAGE_LLCP_SEND:
		{
			PRINT_INFO ("LLCP send is completed with error code %d", result);
			net_nfc_receive_llcp (client_socket, 512 ,NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_RECEIVE:
			PRINT_INFO ("LLCP receive is completed with error code %d", result);
			data_h received_data = (data_h) data;
			PRINT_INFO ("Server --> Client : %s" , net_nfc_get_data_buffer (received_data));

			net_nfc_disconnect_llcp (client_socket ,NULL);
		break;
		case NET_NFC_MESSAGE_LLCP_DISCONNECT:
		{
			PRINT_INFO ("LLCP disconnect is completed with error code %d", result);
			net_nfc_close_llcp_socket (client_socket, NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_ERROR:
			PRINT_INFO ("LLCP socket error is completed with error code %d", result);
			net_nfc_close_llcp_socket (client_socket, NULL);
		break;
		default:
		break;
	}

}


static void net_nfc_server_stress_socket_cb (net_nfc_llcp_message_e message, net_nfc_error_e result, void * data, void * user_data, void * trans_data)
{
	PRINT_INFO ("\nSERVER callback is called MESSAGE[%d]", message);
	switch (message)
	{
		case NET_NFC_MESSAGE_LLCP_LISTEN:
		{
			PRINT_INFO ("LLCP Listen is completed with error code %d", result);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_ACCEPTED:
		{
			PRINT_INFO ("LLCP accept is completed with error code %d", result);
			net_nfc_receive_llcp (server_socket, 512 ,NULL);
		}
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT:
		break;
		case NET_NFC_MESSAGE_LLCP_CONNECT_SAP:
		break;
		case NET_NFC_MESSAGE_LLCP_SEND:
		{
			PRINT_INFO ("LLCP send is completed with error code %d", result);
			net_nfc_disconnect_llcp (server_socket ,NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_RECEIVE:
		{
			PRINT_INFO ("LLCP receive is completed with error code %d", result);
			data_h received_data = (data_h) data;
			PRINT_INFO ("Server <-- Client : %s" , net_nfc_get_data_buffer (received_data));

			data_h data;
			char * str = "Server message: Welcome NFC llcp world!";
			net_nfc_create_data (&data, str ,strlen (str) + 1);
			net_nfc_send_llcp (server_socket, data, NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_DISCONNECT:
		{
			PRINT_INFO ("LLCP disconnect is completed with error code %d", result);
			net_nfc_close_llcp_socket (server_socket, NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_ERROR:
		{
			PRINT_INFO ("LLCP socket error is received with code %d", result);
			net_nfc_close_llcp_socket (server_socket, NULL);
		}
		break;
		default:
		break;
	}
}

static void net_nfc_test_llcp_stress_cb(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	// do nothing
	switch (message) {
		case NET_NFC_MESSAGE_LLCP_DISCOVERED:
		{
			net_nfc_llcp_config_info_h config =  (net_nfc_llcp_config_info_h) data;
			uint8_t lto, option;
			uint16_t wks, miu;
			net_nfc_get_llcp_configure_lto (config , &lto);
			net_nfc_get_llcp_configure_wks (config , &wks);
			net_nfc_get_llcp_configure_miu (config , &miu);
			net_nfc_get_llcp_configure_option (config , &option);

			PRINT_INFO ("Remote Device llcp info:\n \tlto: %d, \twks: %d, \tmiu: %d, \toption: %d", lto, wks, miu, option);

			net_nfc_create_llcp_socket (&server_socket, NULL);
			net_nfc_set_llcp_socket_callback (server_socket, net_nfc_server_stress_socket_cb, NULL);
			net_nfc_listen_llcp (server_socket, "urn:nfc:xsn:samsung.com:testllcp" ,16 ,NULL);

			net_nfc_create_llcp_socket (&client_socket, NULL);
			net_nfc_set_llcp_socket_callback (client_socket, net_nfc_client_stress_socket_cb, NULL);
			net_nfc_connect_llcp (client_socket,"urn:nfc:xsn:samsung.com:testllcp",NULL);
		}
		break;

		case NET_NFC_MESSAGE_LLCP_CONFIG:
		{
			PRINT_INFO ("LLCP llcp local config is completed with error code %d", result);
		}
		break;

		case NET_NFC_MESSAGE_P2P_DETACHED:
		{
			PRINT_INFO ("LLCP NET_NFC_MESSAGE_P2P_DETACHED %d", result);
		}
		break;

		default:
		break;
	}
}

int nfcTestStressLLCP(uint8_t testNumber,void* arg_ptr2)
{
	net_nfc_error_e result;
	net_nfc_llcp_config_info_h config;
	result = net_nfc_initialize();
	CHECK_RESULT(result);
	net_nfc_state_activate (1);
	result = net_nfc_set_response_callback (net_nfc_test_llcp_stress_cb, NULL);
	CHECK_RESULT(result);
	result = net_nfc_create_llcp_configure_default (&config);
	CHECK_RESULT(result);
	result = net_nfc_set_llcp_local_configure (config ,NULL);

	PRINT_INSTRUCT("Please start P2P communicate!!");
/*
	pthread_cond_wait (&pcond,&plock );

	result = net_nfc_unset_response_callback ();
	CHECK_RESULT(result);
	result = net_nfc_deinitialize ();
	CHECK_RESULT(result);
*/

	return NET_NFC_TEST_OK;
}

/*=================================================================================*/


static void net_nfc_test_API_exception_cb1(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	PRINT_INFO ("Message is received 1 %d", result);
	test_case_result = NET_NFC_TEST_FAIL;
	pthread_mutex_lock (&plock);
	pthread_cond_signal (&pcond);
	pthread_mutex_unlock (&plock);
}

static void net_nfc_test_API_exception_cb2(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	PRINT_INFO ("Message is received 2 %d", result);
	test_case_result = NET_NFC_TEST_FAIL;
	pthread_mutex_lock (&plock);
	pthread_cond_signal (&pcond);
	pthread_mutex_unlock (&plock);
}

static void net_nfc_test_API_exception_cb3(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	PRINT_INFO ("Message is received 3 %d", result);
	test_case_result = NET_NFC_TEST_OK;
	pthread_mutex_lock (&plock);
	pthread_cond_signal (&pcond);
	pthread_mutex_unlock (&plock);
}




int nfcTestAPIException (uint8_t testNumber,void* arg_ptr)
{
	net_nfc_error_e result;
	test_case_result = NET_NFC_TEST_FAIL;

	CHECK_ASSULT(net_nfc_initialize() == NET_NFC_OK);
	CHECK_ASSULT(net_nfc_initialize() == NET_NFC_ALREADY_INITIALIZED);
	CHECK_ASSULT(net_nfc_deinitialize () == NET_NFC_OK);

	int count_try = 0;
	for (count_try = 0; count_try < 20; count_try ++)
	{
		CHECK_ASSULT(net_nfc_initialize() == NET_NFC_OK);
		CHECK_ASSULT(net_nfc_deinitialize () == NET_NFC_OK);
	}

	CHECK_ASSULT(net_nfc_deinitialize () == NET_NFC_NOT_INITIALIZED);
	CHECK_ASSULT(net_nfc_deinitialize () == NET_NFC_NOT_INITIALIZED);


	CHECK_ASSULT(net_nfc_initialize() == NET_NFC_OK);

	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb1, NULL));
	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb2, NULL));
	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb3, NULL));
	net_nfc_state_activate (1);

	PRINT_INSTRUCT("Please close a tag to device!!");

	pthread_cond_wait (&pcond,&plock );
	if (!test_case_result) return test_case_result;

	PRINT_INSTRUCT("Please remove the tag from device!!");
	pthread_cond_wait (&pcond,&plock );

	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb2, NULL));
	CHECK_ASSULT (NET_NFC_OK != net_nfc_set_response_callback (NULL, NULL));

	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb2, NULL));
	CHECK_ASSULT (NET_NFC_OK == net_nfc_unset_response_callback ());

	PRINT_INSTRUCT("Please close a tag to device!! in 10 sec");

	int idx = 0;
	for (idx = 10 ;idx > 0 ; idx --)
	{
		PRINT_INSTRUCT("count down [%d]", idx);
		sleep (1);
	}
	if (!test_case_result) return test_case_result;

	PRINT_INSTRUCT("Please remove the tag from device!!");
	sleep (2);

	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb3, NULL));
	net_nfc_state_activate (1);
	net_nfc_state_activate (1);
	net_nfc_state_activate (1);

	PRINT_INSTRUCT("Please close a tag to device!!");

	pthread_cond_wait (&pcond,&plock );
	if (!test_case_result) return test_case_result;
	PRINT_INSTRUCT("Please remove the tag from device!!");
	pthread_cond_wait (&pcond,&plock );

	net_nfc_state_deactivate ();
	PRINT_INSTRUCT("Please close a tag to device!! in 10 sec");

	for (idx = 10 ;idx > 0 ; idx --)
	{
		PRINT_INSTRUCT("count down [%d]", idx);
		sleep (1);
	}
	if (!test_case_result) return test_case_result;
	PRINT_INSTRUCT("Please remove the tag from device!!");
	sleep (2);

	net_nfc_state_activate (1);
	CHECK_ASSULT(net_nfc_deinitialize () == NET_NFC_OK);

	PRINT_INSTRUCT("Please close a tag to device!! in 10 sec");


	for (idx = 10 ;idx > 0 ; idx --)
	{
		PRINT_INSTRUCT("count down [%d]", idx);
		sleep (1);
	}
	if (!test_case_result) return test_case_result;

	PRINT_INSTRUCT("Please remove the tag from device!!");
	sleep (2);

	CHECK_ASSULT(net_nfc_initialize() == NET_NFC_OK);
	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_cb3, NULL));
	net_nfc_state_activate (1);

	PRINT_INSTRUCT("Please close a tag to device!!");

	pthread_cond_wait (&pcond,&plock );
	if (!test_case_result) return test_case_result;

	return NET_NFC_TEST_OK;
}

/*=================================================================================*/


static void net_nfc_test_API_exception_tagAPI(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	PRINT_INFO ("Message is received 3 %d", result);
	test_case_result = NET_NFC_TEST_OK;

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{
			switch (*(int*) user_param)
			{
				case 0: // transceive
				{
					net_nfc_target_type_e type;
					net_nfc_target_handle_h id;
					bool is_ndef;
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;
					net_nfc_error_e e_ret ;

					net_nfc_get_tag_type (target_info, &type);
					net_nfc_get_tag_handle (target_info, &id);
					net_nfc_get_tag_ndef_support (target_info, &is_ndef);
					PRINT_INFO("target type: %d\n", type);
					PRINT_INFO("target id: %X\n", id);
					PRINT_INFO("Is NDEF supoort: %d\n", is_ndef);

					net_nfc_deinitialize (); // Before calling transceive

				}
				break;
				case 1:
				{
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;
					net_nfc_target_handle_h id;
					net_nfc_get_tag_handle (target_info, &id);
					net_nfc_deinitialize();
					if (NET_NFC_OK == net_nfc_read_tag (id ,NULL)){
						test_case_result = NET_NFC_TEST_FAIL;
					}
				}
				break;
				case 2:
				{
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;
					net_nfc_target_handle_h id;
					ndef_message_h message = NULL;
					ndef_record_h record = NULL;

					net_nfc_get_tag_handle (target_info, &id);
					net_nfc_deinitialize();

					net_nfc_create_ndef_message (&message);
					net_nfc_create_text_type_record (&record, "abc" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
					net_nfc_append_record_to_ndef_message (message ,record);
					if (NET_NFC_OK == net_nfc_write_ndef (id ,message ,NULL)){
						test_case_result = NET_NFC_TEST_FAIL;
					}

				}
				break;
				case 3:
				{
					net_nfc_target_info_h target_info = (net_nfc_target_info_h)data;
					net_nfc_target_handle_h id;
					data_h key;
					char data [] = {0xff,0xff,0xff,0xff,0xff,0xff};
					net_nfc_create_data (&key, data, 6);
					net_nfc_get_tag_handle (target_info, &id);
					net_nfc_deinitialize();
					if (NET_NFC_OK == net_nfc_format_ndef(id, key, NULL)){
						test_case_result = NET_NFC_TEST_FAIL;
					}
				}
				break;
			}

			pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);
		}
		break;
	}
}


int nfcTestAPIException_tagAPI (uint8_t testNumber,void* arg_ptr)
{
	int test_case = 0;

	/* Call API before initailize */

	data_h key;
	char data [] = {0xff,0xff,0xff,0xff,0xff,0xff};
	net_nfc_create_data (&key, data, 6);
	CHECK_ASSULT (NET_NFC_OK != net_nfc_format_ndef((net_nfc_target_handle_h) 0x302023, key, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_format_ndef(NULL, key, NULL));
	CHECK_ASSULT (NET_NFC_OK != net_nfc_format_ndef((net_nfc_target_handle_h) 0x302023, NULL, NULL));

	CHECK_ASSULT (NET_NFC_OK != net_nfc_read_tag ((net_nfc_target_handle_h) 0x302023 ,NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_read_tag (NULL ,NULL));

	ndef_message_h message = NULL;
	ndef_record_h record = NULL;
	net_nfc_create_ndef_message (&message);
	net_nfc_create_text_type_record (&record, "abc" ,"en-US" ,NET_NFC_ENCODE_UTF_8);
	net_nfc_append_record_to_ndef_message (message ,record);
	CHECK_ASSULT (NET_NFC_OK != net_nfc_write_ndef ((net_nfc_target_handle_h)0x302023 ,message,NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_write_ndef (NULL ,message,NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_write_ndef ((net_nfc_target_handle_h)0x302023 ,NULL,NULL));
	net_nfc_free_ndef_message (message);


	for (test_case = 0 ; test_case < 4; test_case++){
		CHECK_ASSULT(net_nfc_initialize() == NET_NFC_OK);
		net_nfc_state_activate (1);
		PRINT_INSTRUCT("Please close a tag to device!!");
		CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_tagAPI, &test_case));
		pthread_cond_wait (&pcond,&plock );
		if (test_case_result == NET_NFC_TEST_FAIL) return test_case_result;
		PRINT_INSTRUCT("Please remoe the tag from device!!");
		sleep(2);
	}

	CHECK_ASSULT(net_nfc_deinitialize () != NET_NFC_OK);

	return NET_NFC_TEST_OK;
}
/*=================================================================================*/


static void net_nfc_test_API_exception_targetInfo(net_nfc_message_e message, net_nfc_error_e result, void* data, void* user_param, void * trans_data)
{
	PRINT_INFO ("Message is received 3 %d", result);
	test_case_result = NET_NFC_TEST_OK;

	char **keys;
	int length;
	data_h value;

	switch(message)
	{
		case NET_NFC_MESSAGE_TAG_DISCOVERED:
		{

			if (NET_NFC_OK != net_nfc_get_tag_info_keys((net_nfc_target_info_h)data, &keys, &length)){
				test_case_result = NET_NFC_TEST_FAIL;
				return;
			}

			if (NET_NFC_OK == net_nfc_get_tag_info_value ((net_nfc_target_info_h)data, "abc", &value)){
				test_case_result = NET_NFC_TEST_FAIL;
				return;
			}
			PRINT_INSTRUCT("Please remove the tag from device!!");

		}
		break;
		case NET_NFC_MESSAGE_TAG_DETACHED:

			if (NET_NFC_OK == net_nfc_get_tag_info_keys((net_nfc_target_info_h)data, &keys, &length)){
				test_case_result = NET_NFC_TEST_FAIL;
				return;
			}

			pthread_mutex_lock (&plock);
			pthread_cond_signal (&pcond);
			pthread_mutex_unlock (&plock);


		break;
	}
}

int nfcTestAPIException_targetInfo (uint8_t testNumber,void* arg_ptr)
{
	net_nfc_target_type_e target_type;
	net_nfc_target_handle_h target_id;
	bool is_support;
	unsigned int size;
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_type ((net_nfc_target_info_h)0x302023, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_type (NULL, &target_type));

	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_handle((net_nfc_target_info_h)0x302023, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_handle(NULL, &target_id));

	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_ndef_support ((net_nfc_target_info_h)0x302023, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_ndef_support (NULL, &is_support));

	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_max_data_size ((net_nfc_target_info_h)0x302023, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_max_data_size (NULL, &size));

	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_actual_data_size ((net_nfc_target_info_h)0x302023, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_actual_data_size (NULL, &size));

	char **keys;
	int length;
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_info_keys((net_nfc_target_info_h)0x302023, NULL, &length));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_info_keys((net_nfc_target_info_h)0x302023, &keys, NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_info_keys(NULL, &keys, &length));

	const char* key = "hello";
	data_h value;

	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_info_value((net_nfc_target_info_h)0x302023, key , NULL));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_info_value((net_nfc_target_info_h)0x302023, NULL, &value));
	CHECK_ASSULT (NET_NFC_NULL_PARAMETER == net_nfc_get_tag_info_value(NULL, key, &value));

	CHECK_ASSULT(net_nfc_initialize() == NET_NFC_OK);
	net_nfc_state_activate (1);
	CHECK_ASSULT (NET_NFC_OK == net_nfc_set_response_callback (net_nfc_test_API_exception_targetInfo, NULL));
	PRINT_INSTRUCT("Please close a tag to device!!");

	pthread_cond_wait (&pcond,&plock );

	CHECK_ASSULT(net_nfc_deinitialize() == NET_NFC_OK);
	return NET_NFC_TEST_OK;
}

/*=================================================================================*/


int nfcConnHandoverMessageTest (uint8_t testNumber,void* arg_ptr)
{
	net_nfc_carrier_config_h carrier;
	net_nfc_property_group_h group;
	ndef_record_h carrier_record;
	ndef_message_h message;
	uint8_t buffer[256] = {0,};
	uint8_t * pdata;
	int length = 0;
	net_nfc_error_e result;
	char SSID[] = "HomeWLAN";
	char dev_name[] = "DeviceName";
	uint8_t btdev_addr[] = {0x01, 0x07, 0x80, 0x80, 0xBF, 0xA1};

	result = net_nfc_create_carrier_config (&carrier ,NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS);
	CHECK_RESULT(result);

	buffer[0] = 0x10;
	result = net_nfc_add_carrier_config_property (carrier, NET_NFC_WIFI_ATTRIBUTE_VERSION, 1, buffer);
	CHECK_RESULT(result);
	result = net_nfc_create_carrier_config_group (&group, NET_NFC_WIFI_ATTRIBUTE_CREDENTIAL);
	CHECK_RESULT(result);

	buffer[0] = 0x1;
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_NET_INDEX, 1, buffer);
	CHECK_RESULT(result);

	length = sprintf (buffer, "%s", SSID);
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_SSID, length, buffer);
	CHECK_RESULT(result);

	*((uint16_t*) buffer ) = 0x20;
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_AUTH_TYPE, 2, buffer);
	CHECK_RESULT(result);

	*((uint16_t*) buffer ) = 0x0008;
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_ENC_TYPE, 2, buffer);
	CHECK_RESULT(result);

	length = sprintf (buffer, "MyPreSharedKey");
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_NET_KEY, length, buffer);
	CHECK_RESULT(result);

	buffer[0] = 0x00;
	buffer[1] = 0x07;
	buffer[2] = 0xE9;
	buffer[3] = 0x4C;
	buffer[4] = 0xA8;
	buffer[5] = 0x1C;
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_MAC_ADDR, 6, buffer);
	CHECK_RESULT(result);


	*((uint16_t*) buffer ) = 0x0001;
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_CHANNEL, 2, buffer);
	CHECK_RESULT(result);

	buffer[0] = 0x00;
	buffer[1] = 0x37;
	buffer[2] = 0x2A;
	result = net_nfc_add_carrier_config_group_property (group, NET_NFC_WIFI_ATTRIBUTE_VEN_EXT, 3, buffer);
	CHECK_RESULT(result);

	result = net_nfc_append_carrier_config_group (carrier, group);
	CHECK_RESULT(result);

	buffer[0] = 0x20;
	result = net_nfc_add_carrier_config_property (carrier, NET_NFC_WIFI_ATTRIBUTE_VERSION2, 1, buffer);
	CHECK_RESULT(result);

	result = net_nfc_create_ndef_record_with_carrier_config (&carrier_record ,carrier);
	CHECK_RESULT(result);

	result = net_nfc_free_carrier_config (carrier); /* this free all data include group */
	CHECK_RESULT(result);

	result = net_nfc_create_handover_request_message (&message);
	CHECK_RESULT(result);

	//net_nfc_ndef_print_message (message);

	result = net_nfc_append_carrier_config_record (message, carrier_record, NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE);
	CHECK_RESULT(result);

	//net_nfc_ndef_print_message (message);


	// Create BT config
	result = net_nfc_create_carrier_config (&carrier ,NET_NFC_CONN_HANDOVER_CARRIER_BT);
	CHECK_RESULT(result);

	buffer[0] = btdev_addr[0];
	buffer[1] = btdev_addr[1];
	buffer[2] = btdev_addr[2];
	buffer[3] = btdev_addr[3];
	buffer[4] = btdev_addr[4];
	buffer[5] = btdev_addr[5];
	result = net_nfc_add_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_ADDRESS ,6 ,buffer);
	CHECK_RESULT(result);

	buffer[0] = 0x08;
	buffer[1] = 0x06;
	buffer[2] = 0x20;
	result = net_nfc_add_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_OOB_COD ,3 ,buffer);
	CHECK_RESULT(result);


	result = net_nfc_add_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_OOB_HASH_C ,16 ,buffer);
	CHECK_RESULT(result);

	result = net_nfc_add_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_OOB_HASH_R ,16 ,buffer);
	CHECK_RESULT(result);

	buffer[0] = 0x06;
	buffer[1] = 0x11;
	buffer[2] = 0x20;
	buffer[3] = 0x11;
	result = net_nfc_add_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_UUID16 ,4 ,buffer);
	CHECK_RESULT(result);

	length = sprintf (buffer, "%s", dev_name);
	result = net_nfc_add_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_NAME ,length ,buffer);
	CHECK_RESULT(result);

	result = net_nfc_create_ndef_record_with_carrier_config (&carrier_record ,carrier);
	CHECK_RESULT(result);

	result = net_nfc_append_carrier_config_record (message, carrier_record, NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING);
	CHECK_RESULT(result);

	//net_nfc_ndef_print_message (message);

	result = net_nfc_free_carrier_config (carrier);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_record (message,0 ,&carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_create_carrier_config_from_config_record (&carrier ,carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_property (carrier ,NET_NFC_WIFI_ATTRIBUTE_VERSION , &length, &pdata);
	CHECK_RESULT(result);
	if (pdata[0] != 0x10){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d, value %d",__FILE__,__LINE__, pdata[0]);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_carrier_config_group (carrier ,0 , &group);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_group_property (group ,NET_NFC_WIFI_ATTRIBUTE_SSID, &length, &pdata);
	CHECK_RESULT(result);
	if (memcmp (pdata, SSID, length) != 0){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_remove_carrier_config_group_property (group,NET_NFC_WIFI_ATTRIBUTE_VEN_EXT);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_record (message,1 ,&carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_create_carrier_config_from_config_record (&carrier ,carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_ADDRESS , &length, &pdata);
	CHECK_RESULT(result);
	if (memcmp (pdata, btdev_addr, length) != 0) {
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_NAME , &length, &pdata);
	CHECK_RESULT(result);
	if (memcmp (pdata, dev_name, length) != 0){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_alternative_carrier_record_count (message, &length);
	CHECK_RESULT(result);

	if (length != 2) {
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d, count = %d",__FILE__,__LINE__, length);
		return NET_NFC_TEST_FAIL;
	}

	net_nfc_conn_handover_carrier_state_e power_state;
	result = net_nfc_get_alternative_carrier_power_status (message,0 ,&power_state);
	CHECK_RESULT(result);

	if (power_state != NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}
	result = net_nfc_set_alternative_carrier_power_status (message,1 ,NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE);
	CHECK_RESULT(result);

	result = net_nfc_get_alternative_carrier_power_status (message,1 ,&power_state);
	CHECK_RESULT(result);

	if (power_state != NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d, status = %d",__FILE__,__LINE__, power_state);
		return NET_NFC_TEST_FAIL;
	}

	net_nfc_conn_handover_carrier_type_e ctype;
	result = net_nfc_get_alternative_carrier_type (message, 0 , &ctype);

	if (ctype != NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	unsigned short r_num;
	result = net_nfc_get_handover_random_number (message, &r_num);

	result = net_nfc_get_carrier_config_record (message,0 ,&carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_remove_carrier_config_record (message, carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_record (message,0 ,&carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_create_carrier_config_from_config_record (&carrier ,carrier_record);
	CHECK_RESULT(result);

	result = net_nfc_get_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_ADDRESS , &length, &pdata);
	CHECK_RESULT(result);
	if (memcmp (pdata, btdev_addr, length) != 0) {
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_carrier_config_property (carrier ,NET_NFC_BT_ATTRIBUTE_NAME , &length, &pdata);
	CHECK_RESULT(result);
	if (memcmp (pdata, dev_name, length) != 0){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_alternative_carrier_record_count (message, &length);
	CHECK_RESULT(result);

	if (length != 1) {
				PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_alternative_carrier_power_status (message,0 ,&power_state);
	CHECK_RESULT(result);

	if (power_state != NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE){
				PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	result = net_nfc_get_alternative_carrier_type (message, 0 , &ctype);

	if (ctype != NET_NFC_CONN_HANDOVER_CARRIER_BT){
		PRINT_RESULT_FAIL("FILE:%s, LINE:%d,",__FILE__,__LINE__);
		return NET_NFC_TEST_FAIL;
	}

	//net_nfc_ndef_print_message (message);

	return NET_NFC_TEST_OK;

}

/*=================================================================================*/


