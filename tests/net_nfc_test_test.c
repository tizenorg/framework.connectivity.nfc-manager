/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glib-object.h>

#include "net_nfc_client_test.h"



static void run_next_callback(gpointer user_data);

static void sim_test_completed(net_nfc_error_e result,
			void *user_data);

static void prbs_test_completed(net_nfc_error_e result,
				void *user_data);

static void get_firmware_version_completed(net_nfc_error_e result,
					char *version,
					void *user_data);

static void set_ee_data_completed(net_nfc_error_e reuslt,
				void *user_data);



static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;
		callback = (GCallback)(user_data);
		callback();
	}
}



static void sim_test_completed(net_nfc_error_e result,
			void *user_data)
{
	g_print("SimTestCompleted Completed %d\n", result);
	run_next_callback(user_data);
}



static void prbs_test_completed(net_nfc_error_e result,
				void *user_data)
{
	g_print("PrbsTest Completed %d\n", result);
	run_next_callback(user_data);
}



static void get_firmware_version_completed(net_nfc_error_e result,
					char *version,
					void *user_data)
{
	g_print("GetFirmwareVersion Completed %d: %s\n", result, version);
	run_next_callback(user_data);
}



static void set_ee_data_completed(net_nfc_error_e result,
				void *user_data)
{
	g_print("SetEeData Completed %d\n", result);
	run_next_callback(user_data);
}


void net_nfc_test_test_sim_test(gpointer data,
				gpointer user_data)
{
	net_nfc_client_test_sim_test(sim_test_completed, user_data);
}



void net_nfc_test_test_prbs_test(gpointer data,
				gpointer user_data)
{
	/* FIXME : fill right value */
	uint32_t tech = 0;
	uint32_t rate = 0;

	net_nfc_client_test_prbs_test(tech,
				rate,
				prbs_test_completed,
				user_data);
}



void net_nfc_test_test_get_firmware_version(gpointer data,
					gpointer user_data)
{
	net_nfc_client_test_get_firmware_version(
					get_firmware_version_completed,
					user_data);
}



void net_nfc_test_test_set_ee_data(gpointer data,
				gpointer user_data)
{

	/* FIXME : fill right value */
	int mode = 0;
	int reg_id = 0;
	data_h ee_data = (data_h)data;

	net_nfc_client_test_set_ee_data(mode,
					reg_id,
					ee_data,
					set_ee_data_completed,
					user_data);

}



void net_nfc_test_test_sim_test_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	result = net_nfc_client_test_sim_test_sync();
	g_print("SimTest: %d\n", result);
	run_next_callback(user_data);
}



void net_nfc_test_test_prbs_test_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;

	/* FIXME : fill right value */
	uint32_t tech = 0;
	uint32_t rate = 0;
	result = net_nfc_client_test_prbs_test_sync(tech, rate);
	g_print("PrbsTest: %d\n", result);
	run_next_callback(user_data);

}



void net_nfc_test_test_get_firmware_version_sync(gpointer data,
						gpointer user_data)
{
	net_nfc_error_e result;
	char *version = NULL;

	result = net_nfc_client_test_get_firmware_version_sync(&version);

	g_print("GetFirmwareVersion: %d, %s\n", result, version);
	run_next_callback(user_data);

}



void net_nfc_test_test_set_ee_data_sync(gpointer data,
					gpointer user_data)
{

	net_nfc_error_e result;

	/* FIXME : fill right value */
	int mode = 0;
	int reg_id = 0;
	data_h ee_data = (data_h)data;

	result = net_nfc_client_test_set_ee_data_sync(mode,
						reg_id,
						ee_data);
	g_print("SetEeData: %d\n", result);
	run_next_callback(user_data);

}

