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

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <pthread.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <gio/gio.h>
#include <sys/utsname.h>
#include <privilege-control.h>

#include <vconf.h>

#include "net_nfc_server_common.h"
#include "net_nfc_server_vconf.h"
#include "net_nfc_server_manager.h"
#include "net_nfc_server_se.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_app_util_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_manager.h"
#include "net_nfc_server.h"

static gboolean use_daemon = FALSE;

GOptionEntry option_entries[] = {
	{ "daemon", 'd', 0, G_OPTION_ARG_NONE, &use_daemon,
		"Use Daemon mode", NULL },
	{ NULL }
};

static GMainLoop *loop = NULL;

static bool net_nfc_check_mode_conditions();

void net_nfc_manager_quit()
{
	DEBUG_MSG("net_nfc_manager_quit kill the nfc-manager daemon!!");
	if (loop != NULL) {
		g_main_loop_quit(loop);
	}
}

static void on_bus_acquired(GDBusConnection *connection,
			const gchar *path,
			gpointer user_data)
{
	gint state;

	DEBUG_MSG("bus path : %s", path);

	net_nfc_server_gdbus_init();

	net_nfc_server_controller_init();

	if (vconf_get_bool(VCONFKEY_NFC_STATE, &state) != 0)
	{
		DEBUG_MSG("VCONFKEY_NFC_STATE is not exist");
		net_nfc_manager_quit();

		return;
	}

	net_nfc_server_vconf_init();

	if (state == 1)
		net_nfc_server_manager_set_active(TRUE);
	else if (net_nfc_check_mode_conditions())
		net_nfc_server_manager_set_active(FALSE);
#ifndef ESE_ALWAYS_ON
	else if (use_daemon == TRUE)
	{
		DEBUG_ERR_MSG("net_nfc_server_controller_deinit");
		net_nfc_server_controller_deinit();
	}
#endif
}

static void on_name_acquired(GDBusConnection *connection,
			const gchar *name,
			gpointer user_data)
{
	DEBUG_SERVER_MSG("name : %s", name);
}

static void on_name_lost(GDBusConnection *connnection,
			const gchar *name,
			gpointer user_data)
{
	DEBUG_SERVER_MSG("name : %s", name);

	net_nfc_manager_quit();
}


int main(int argc, char *argv[])
{

	void *handle = NULL;
	guint id = 0;
	gboolean use_daemon = FALSE;
	GOptionContext *option_context;
	GError *error = NULL;
	bool check_csc = 0;

	if (getuid() == 0)
	{
		int ret = perm_app_set_privilege("system", NULL, NULL);
		if(ret != 0)
			return 0;
	}

	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	g_type_init();

	option_context = g_option_context_new("Nfc manager");
	g_option_context_add_main_entries(option_context,
					option_entries,
					NULL);

	if (g_option_context_parse(option_context,
				&argc,
				&argv,
				&error) == FALSE)
	{
		DEBUG_ERR_MSG("can not parse option: %s",
				error->message);
		g_error_free(error);

		g_option_context_free(option_context);
		return 0;
	}

	DEBUG_SERVER_MSG("start nfc manager");
	DEBUG_SERVER_MSG("use_daemon : %d", use_daemon);

	check_csc = net_nfc_check_csc_vconf();
	if (check_csc)
		return 0;

	net_nfc_manager_init_log();

	net_nfc_app_util_clean_storage(MESSAGE_STORAGE);

	handle = net_nfc_controller_onload();
	if (handle == NULL)
	{
		DEBUG_ERR_MSG("load plugin library is failed");

		if (vconf_set_bool(VCONFKEY_NFC_FEATURE,
				VCONFKEY_NFC_FEATURE_OFF) != 0)
		{
			DEBUG_ERR_MSG("VCONFKEY_NFC_FEATURE set to %d failed",
					VCONFKEY_NFC_FEATURE_OFF);
		}

		if (vconf_set_bool(VCONFKEY_NFC_STATE, 0) != 0)
		{
			DEBUG_ERR_MSG("VCONFKEY_NFC_STATE set to %d failed",
					0);
		}

		goto EXIT;
	}

	if (vconf_set_bool(VCONFKEY_NFC_FEATURE, VCONFKEY_NFC_FEATURE_ON) != 0)
	{
		DEBUG_ERR_MSG("VCONFKEY_NFC_FEATURE set to %d failed",
				VCONFKEY_NFC_FEATURE_ON);
	}

	id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
		"org.tizen.NetNfcService",
		G_BUS_NAME_OWNER_FLAGS_NONE,
		on_bus_acquired,
		on_name_acquired,
		on_name_lost,
		NULL,
		NULL);

	loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(loop);

EXIT :
	net_nfc_server_vconf_deinit();
	net_nfc_server_gdbus_deinit();

	if (id)
	{
		g_bus_unown_name(id);
	}

	net_nfc_controller_unload(handle);

	net_nfc_manager_fini_log();

	g_option_context_free(option_context);

	return 0;
}

static bool net_nfc_check_mode_conditions()
{
#ifdef ENABLE_TELEPHONY
	gint flight_mode = 0;
	gint result = 0;

	result = vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &flight_mode);
	if (result != 0)
	{
		DEBUG_ERR_MSG("Can not get %s",
				"VCONFKEY_TELEPHONY_FLIGHT_MODE");
		return FALSE;
	}

	if (flight_mode == TRUE)
	{
		DEBUG_SERVER_MSG("Flight mode!! Do Not Kill Daemon!!");
		return TRUE;
	}
	else
	{
		DEBUG_SERVER_MSG("Not any mode!!");
		return FALSE;
	}
#else
return FALSE;
#endif


}
