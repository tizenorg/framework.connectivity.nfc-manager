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

#include <glib.h>
#include <vconf.h>

#include "net_nfc_typedef.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_manager.h"
#include "net_nfc_server_se.h"
#include "net_nfc_server_route_table.h"
#include "net_nfc_server_vconf.h"

static void net_nfc_server_vconf_lock_state_changed(keynode_t *key,
						void *user_data);

static void net_nfc_server_vconf_pm_state_changed(keynode_t *key,
						void *user_data);

#ifdef ENABLE_TELEPHONY
static void net_nfc_server_vconf_flight_mode_changed(keynode_t *key,
						void *user_data);
#endif

static void net_nfc_server_vconf_lock_state_changed(keynode_t *key,
						void *user_data)
{

	gint state = 0;
	gint result;
	gint lock_state = 0;

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &state);
	if (result != 0)
		DEBUG_ERR_MSG("can not get %s", "VCONFKEY_NFC_STATE");

	if (state == false)
	{
		DEBUG_MSG("NFC off");
		return;
	}

	if (vconf_get_int(VCONFKEY_IDLE_LOCK_STATE, &lock_state) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_IDLE_LOCK_STATE");


	if (lock_state == VCONFKEY_IDLE_UNLOCK ||
		            lock_state == VCONFKEY_IDLE_LOCK)
	{
		net_nfc_server_restart_polling_loop();
	}

}

static void net_nfc_server_vconf_pm_state_changed(keynode_t *key,
						void *user_data)
{
	gint state = 0;
	gint pm_state = 0;
	gint lock_screen_set = 0;
	gint result;

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &state);

	if (result != 0)
		DEBUG_ERR_MSG("can not get %s", "VCONFKEY_NFC_STATE");

	if (state == false)
	{
		DEBUG_MSG("NFC off");
		return;
	}

	result = vconf_get_int(VCONFKEY_PM_STATE, &pm_state);

	if (result != 0)
		DEBUG_ERR_MSG("can not get %s", "VCONFKEY_PM_STATE");

	DEBUG_SERVER_MSG("pm_state : %d", pm_state);

	result = vconf_get_int(VCONFKEY_SETAPPL_SCREEN_LOCK_TYPE_INT, &lock_screen_set);

	if (result != 0)
		DEBUG_ERR_MSG("can not get %s", "VCONFKEY_SETAPPL_SCREEN_LOCK_TYPE_INT");

	DEBUG_SERVER_MSG("lock_screen_set : %d", lock_screen_set);

#if 0
	if ( lock_screen_set == SETTING_SCREEN_LOCK_TYPE_NONE &&
		(pm_state == VCONFKEY_PM_STATE_NORMAL ||
		            pm_state == VCONFKEY_PM_STATE_LCDOFF) )
#endif
	if (pm_state == VCONFKEY_PM_STATE_NORMAL ||
		pm_state == VCONFKEY_PM_STATE_LCDOFF)
	{
		net_nfc_server_restart_polling_loop();
	}
}

#ifdef ENABLE_TELEPHONY
static void net_nfc_server_vconf_flight_mode_changed(keynode_t *key,
						void *user_data)
{
	gint flight_mode = 0;
	gint nfc_state = 0;
	gint vconf_key = VCONFKEY_NFC_NONE_BY_FLIGHT;
	gint result = 0;

	result = vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &flight_mode);
	if (result != 0)
	{
		DEBUG_ERR_MSG("Can not get %s",
				"VCONFKEY_TELEPHONY_FLIGHT_MODE");
	}

	DEBUG_SERVER_MSG("flight mode %d", flight_mode);

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &nfc_state);
	if (result != 0)
	{
		DEBUG_ERR_MSG("Can not get %s",
			"VCONFKEY_NET_STATE");
	}

	DEBUG_SERVER_MSG("nfc_state %d", nfc_state);

	if (flight_mode) /* turn on flight mode */
	{
		/* nfc is already disabled ignore it */
		if (nfc_state == VCONFKEY_NFC_STATE_OFF)
			return;

		DEBUG_SERVER_MSG("Turning NFC off");
		net_nfc_server_manager_set_active(FALSE);

		vconf_key = VCONFKEY_NFC_OFF_BY_FLIGHT;

		result = vconf_set_bool(VCONFKEY_NFC_STATE_OFF_BY_FLIGHT, vconf_key);
		if (result != 0)
		{
			DEBUG_ERR_MSG("Can not set %s",
						"VCONFKEY_NFC_STATE_OFF_BY_FLIGHT");
		}
	}
	else /* turn off flight mode */
	{
		/* nfc is already enabled, ignore it */
		if (nfc_state == VCONFKEY_NFC_STATE_ON)
			return;

		result = vconf_get_bool(VCONFKEY_NFC_STATE_OFF_BY_FLIGHT, &vconf_key);
		if (result != 0)
		{
			DEBUG_ERR_MSG("Can not set %s",
						"VCONFKEY_NFC_STATE_OFF_BY_FLIGHT");
		}

		DEBUG_SERVER_MSG("VCONFKEY_NFC_STATE_OFF_BY_FLIGHT = [%d]" , vconf_key);

		if (vconf_key != VCONFKEY_NFC_OFF_BY_FLIGHT)
			return;

		DEBUG_SERVER_MSG("Turning NFC on");
		net_nfc_server_manager_set_active(TRUE);

		result = vconf_set_bool(VCONFKEY_NFC_STATE_OFF_BY_FLIGHT, VCONFKEY_NFC_NONE_BY_FLIGHT);
		if (result != 0)
		{
			DEBUG_ERR_MSG("Can not set %s",
						"VCONFKEY_NFC_STATE_OFF_BY_FLIGHT");
		}
	}
}
#endif

static void net_nfc_server_vconf_se_type_changed(keynode_t *key,
						void *user_data)
{
	net_nfc_server_se_policy_apply();

	net_nfc_server_route_table_do_update();
}

static void net_nfc_server_vconf_wallet_mode_changed(keynode_t *key,
						void *user_data)
{
	int wallet_mode;

	g_assert(key != NULL);

	wallet_mode = key->value.i;

	DEBUG_SERVER_MSG("wallet mode [%d]", wallet_mode);

	net_nfc_server_se_change_wallet_mode(wallet_mode);

	net_nfc_server_route_table_do_update();
}

static void __on_payment_handler_changed_func(gpointer user_data)
{
	char *package = (char *)user_data;

	DEBUG_SERVER_MSG("PAYMENT handler changed, [%s]", package);

	net_nfc_server_route_table_update_category_handler(package,
		NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT);

	if (package != NULL) {
		g_free(package);
	}
}

static void net_nfc_server_vconf_payment_handlers_changed(keynode_t *key,
	void *user_data)
{
	g_assert(key != NULL);

	net_nfc_server_controller_async_queue_push(
		__on_payment_handler_changed_func,
		g_strdup(key->value.s));
}

static void __on_other_handlers_changed_func(gpointer user_data)
{
	char *packages = (char *)user_data;

	DEBUG_SERVER_MSG("OTHER handlers changed, [%s]", packages);

	net_nfc_server_route_table_update_category_handler(packages,
		NET_NFC_CARD_EMULATION_CATEGORY_OTHER);

	if (packages != NULL) {
		g_free(packages);
	}
}

static void net_nfc_server_vconf_other_handlers_changed(keynode_t *key,
	void *user_data)
{
	g_assert(key != NULL);

	net_nfc_server_controller_async_queue_push(
		__on_other_handlers_changed_func,
		g_strdup(key->value.s));
}

void net_nfc_server_vconf_init(void)
{
	vconf_notify_key_changed(VCONFKEY_IDLE_LOCK_STATE,
			net_nfc_server_vconf_lock_state_changed,
			NULL);
#if 1
	vconf_notify_key_changed(VCONFKEY_PM_STATE,
			net_nfc_server_vconf_pm_state_changed,
			NULL);
#endif

#ifdef ENABLE_TELEPHONY
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			net_nfc_server_vconf_flight_mode_changed,
			NULL);
#endif
	vconf_notify_key_changed(VCONFKEY_NFC_SE_TYPE,
			net_nfc_server_vconf_se_type_changed,
			NULL);

	vconf_notify_key_changed(VCONFKEY_NFC_WALLET_MODE,
			net_nfc_server_vconf_wallet_mode_changed,
			NULL);

	vconf_notify_key_changed(VCONFKEY_NFC_PAYMENT_HANDLERS,
			net_nfc_server_vconf_payment_handlers_changed,
			NULL);

	vconf_notify_key_changed(VCONFKEY_NFC_OTHER_HANDLERS,
			net_nfc_server_vconf_other_handlers_changed,
			NULL);
}

void net_nfc_server_vconf_deinit(void)
{
	vconf_ignore_key_changed(VCONFKEY_IDLE_LOCK_STATE,
			net_nfc_server_vconf_lock_state_changed);

#ifdef ENABLE_TELEPHONY
	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			net_nfc_server_vconf_flight_mode_changed);
#endif
	vconf_ignore_key_changed(VCONFKEY_NFC_SE_TYPE,
			net_nfc_server_vconf_se_type_changed);

	vconf_ignore_key_changed(VCONFKEY_NFC_WALLET_MODE,
			net_nfc_server_vconf_wallet_mode_changed);

	vconf_ignore_key_changed(VCONFKEY_NFC_PAYMENT_HANDLERS,
			net_nfc_server_vconf_payment_handlers_changed);

	vconf_ignore_key_changed(VCONFKEY_NFC_OTHER_HANDLERS,
			net_nfc_server_vconf_other_handlers_changed);
}

bool net_nfc_check_csc_vconf(void)
{
	int state = 0;;
	gint result = 0;

	result = vconf_get_int(VCONFKEY_CSC_CONFIG_MODE_RUNNING , &state);
	if (result != 0)
	{
		DEBUG_ERR_MSG("Can't get %s", "VCONFKEY_CSC_CONFIG_MODE_RUNNING");
	}

	if (state == true)
	{
		DEBUG_ERR_MSG("This is CSC Booting!!");
		return true;
	}
	else
	{
		DEBUG_ERR_MSG("This is Normal Booting!!");
		return false;
	}
}

bool net_nfc_check_start_polling_vconf(void)
{
	gint lock_state = 0;
	gint lock_screen_set = 0;
	gint pm_state = 0;

	if (vconf_get_int(VCONFKEY_IDLE_LOCK_STATE, &lock_state) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_IDLE_LOCK_STATE");

	if (vconf_get_int(VCONFKEY_SETAPPL_SCREEN_LOCK_TYPE_INT, &lock_screen_set) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_SETAPPL_SCREEN_LOCK_TYPE_INT");

	if (vconf_get_int(VCONFKEY_PM_STATE, &pm_state) != 0)
		DEBUG_ERR_MSG("%s does not exist", "VCONFKEY_PM_STATE");


	DEBUG_SERVER_MSG("lock_screen_set:%d ,pm_state:%d,lock_state:%d",
		lock_screen_set , pm_state , lock_state);

	if (lock_screen_set == SETTING_SCREEN_LOCK_TYPE_NONE)
	{
		if (pm_state == VCONFKEY_PM_STATE_NORMAL)
		{
			DEBUG_SERVER_MSG("polling enable");
			return TRUE;
		}

		if (pm_state == VCONFKEY_PM_STATE_LCDOFF)
		{
			DEBUG_SERVER_MSG("polling disabled");
			return FALSE;
		}
	}
	else
	{
		if (lock_state == VCONFKEY_IDLE_UNLOCK)
		{
			DEBUG_SERVER_MSG("polling enable");
			return TRUE;
		}

		if (lock_state == VCONFKEY_IDLE_LOCK || pm_state == VCONFKEY_PM_STATE_LCDOFF)
		{
			DEBUG_SERVER_MSG("polling disabled");
			return FALSE;
		}
	}

	return FALSE;
}
