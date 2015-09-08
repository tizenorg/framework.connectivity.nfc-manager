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

#include "net_nfc_client_manager.h"
#include "net_nfc_typedef_internal.h"

static void run_next_callback(gpointer user_data);

static void print_server_state(gint state);

static void set_activated_cb(bool state,
		void *user_data);

static void set_active_completed_cb(net_nfc_error_e result,
				void *user_data);

static void get_server_state_completed_cb(net_nfc_error_e result,
				unsigned int state,
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

static void print_server_state(gint state)
{
	if (state == 0)
		g_print(" --- state : Unknown(%d)\n", state);
	else
	{
		g_print(" --- state :\n");
		if (state & NET_NFC_SERVER_DISCOVERY)
			g_print("\tNET_NFC_SERVER_DISCOVERY(%d)\n", state);
		if (state & NET_NFC_TAG_CONNECTED)
			g_print("\tNET_NFC_TAG_CONNECTED(%d)\n", state);
		if (state & NET_NFC_SE_CONNECTION)
			g_print("\tNET_NFC_SE_CONNECTED(%d)\n", state);
		if (state & NET_NFC_SNEP_CLIENT_CONNECTED)
		{
			g_print("\tNET_NFC_SNEP_CLIENT_CONNECTED(%d)\n",
								state);
		}
		if (state & NET_NFC_NPP_CLIENT_CONNECTED)
			g_print("\tNET_NFC_NPP_CLIENT_CONNECTED(%d)\n", state);
		if (state & NET_NFC_SNEP_SERVER_CONNECTED)
			g_print("\tNET_NFC_SNEP_SERVER_CONNECTED(%d)\n", state);
		if (state & NET_NFC_NPP_SERVER_CONNECTED)
			g_print("\tNET_NFC_NPP_SERVER_CONNECTED(%d)\n", state);
	}
}

static void set_activated_cb(bool state,
			void *user_data)
{
	g_print("Activated state %d\n", state);
}

static void set_active_completed_cb(net_nfc_error_e result,
				void *user_data)
{
	g_print("SetActive Completed %d\n", result);
	run_next_callback(user_data);
}

static void get_server_state_completed_cb(net_nfc_error_e result,
				unsigned int state,
				void *user_data)
{
	g_print("GetServerState Completed %d\n", result);

	print_server_state(state);

	run_next_callback(user_data);
}

void net_nfc_test_manager_set_active(gpointer data,
				gpointer user_data)
{
	net_nfc_client_manager_set_activated(set_activated_cb, NULL);

	net_nfc_client_manager_set_active(1,
					set_active_completed_cb,
					user_data);
}

void net_nfc_test_manager_get_server_state(gpointer data,
			gpointer user_data)
{
	net_nfc_client_manager_get_server_state(get_server_state_completed_cb,
						user_data);
}

void net_nfc_test_manager_set_active_sync(gpointer data,
				gpointer user_data)
{
	gint i;

	i = net_nfc_client_manager_set_active_sync(1);

	g_print("Return %d\n", i);

	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);

		callback();
	}
}

void net_nfc_test_manager_get_server_state_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	guint state = 0;

	result = net_nfc_client_manager_get_server_state_sync(&state);

	g_print("GetServerState: %d\n", result);

	print_server_state(state);

	run_next_callback(user_data);
}
