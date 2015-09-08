/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vconf.h>
#include <tapi_common.h>
#include <ITapiSim.h>

#include "net_nfc_server.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_manager.h"
#include "net_nfc_server_se.h"
#include "net_nfc_app_util_internal.h"
#include "net_nfc_server_route_table.h"

enum
{
	SE_UICC_UNAVAILABLE = -1,
	SE_UICC_ON_PROGRESS = 0,
	SE_UICC_READY = 1,
};

static NetNfcGDbusSecureElement *se_skeleton = NULL;

/* TODO : make a list for handles */
static TapiHandle *gdbus_uicc_handle;
static net_nfc_target_handle_s *gdbus_ese_handle;

static int gdbus_uicc_ready;

/* server_side */
typedef struct _ServerSeData ServerSeData;

struct _ServerSeData
{
	data_s aid;
	data_s param;
	guint event;
};

typedef struct _SeSetCardEmul SeSetCardEmul;

struct _SeSetCardEmul
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	gint mode;
};

typedef struct _SeDataSeType SeDataSeType;

struct _SeDataSeType
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	gint se_type;
};

typedef struct _SeDataTransactionFgDispatch SeDataTransactionFgDispatch;

struct _SeDataTransactionFgDispatch
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	int FgDispatch;
};

typedef struct _SeDataHandle SeDataHandle;

struct _SeDataHandle
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s* handle;
};

typedef struct _SeDataApdu SeDataApdu;

struct _SeDataApdu
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s* handle;
	GVariant *data;
};

typedef struct _ChangeCardEmulMode ChangeCardEmulMode;

struct _ChangeCardEmulMode
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	gint mode;
};

typedef struct _SeDefaultRoute
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s* handle;
	guint switch_on;
	guint switch_off;
	guint battery_off;
}
SeDefaultRoute;
TelSimApdu_t apdu_data = { 0, };
TelSimApduResp_t *resp_apdu = NULL;
TelSimAtrResp_t *resp_atr  = NULL;

typedef struct _SeDataAid
{
	NetNfcGDbusSecureElement *object;
	GDBusMethodInvocation *invocation;
	net_nfc_target_handle_s *handle;
	char *package;
	char *aid;
	guint se_type;
	guint category;
	gboolean unlock;
	guint power;
}
SeDataAid;


static void se_close_secure_element_thread_func(gpointer user_data);

static void se_get_atr_thread_func(gpointer user_data);

static void se_open_secure_element_thread_func(gpointer user_data);

static void se_send_apdu_thread_func(gpointer user_data);

static void se_set_data_thread_func(gpointer user_data);

static void se_policy_apply_thread_func(gpointer user_data);

static gboolean se_handle_close_secure_element(
			NetNfcGDbusSecureElement *object,
			GDBusMethodInvocation *invocation,
			guint arg_handle,
			GVariant *smack_privilege);

static gboolean se_handle_get_atr(
			NetNfcGDbusSecureElement *object,
			GDBusMethodInvocation *invocation,
			guint arg_handle,
			GVariant *smack_privilege);


static gboolean se_handle_open_secure_element(
			NetNfcGDbusSecureElement *object,
			GDBusMethodInvocation *invocation,
			gint arg_type,
			GVariant *smack_privilege);


static gboolean se_handle_send_apdu(
			NetNfcGDbusSecureElement *object,
			GDBusMethodInvocation *invocation,
			guint arg_handle,
			GVariant* apdudata,
			GVariant *smack_privilege);

static gboolean se_handle_set(
			NetNfcGDbusSecureElement *object,
			GDBusMethodInvocation *invocation,
			gint arg_type,
			GVariant *smack_privilege);

static net_nfc_card_emulation_mode_t __se_get_se_state(
	net_nfc_secure_element_policy_e policy);

static net_nfc_se_type_e __se_get_se_type(
	net_nfc_secure_element_policy_e policy);


static net_nfc_secure_element_policy_e current_policy;


static net_nfc_card_emulation_mode_t __se_get_se_state(
	net_nfc_secure_element_policy_e policy)
{
	net_nfc_card_emulation_mode_t state;

	switch (policy) {
	case SECURE_ELEMENT_POLICY_ESE_ON :
		state = NET_NFC_CARD_EMELATION_ENABLE;
		break;

	case SECURE_ELEMENT_POLICY_UICC_ON :
		if (gdbus_uicc_ready == SE_UICC_READY) {
			state = NET_NFC_CARD_EMELATION_ENABLE;
		} else {
			state = NET_NFC_CARD_EMULATION_DISABLE;
		}
		break;

	case SECURE_ELEMENT_POLICY_HCE_ON :
		state = NET_NFC_CARD_EMELATION_ENABLE;
		break;

	default :
		state = NET_NFC_CARD_EMULATION_DISABLE;
		break;
	}

	return state;
}

void net_nfc_server_se_policy_apply()
{
	if (se_skeleton == NULL)
	{
		DEBUG_ERR_MSG("net_nfc_server_manager is not initialized");

		return;
	}

	DEBUG_SERVER_MSG("se policy apply start");

	if (net_nfc_server_controller_async_queue_push(
					se_policy_apply_thread_func,
					NULL) == FALSE)
	{
		DEBUG_ERR_MSG("can not push to controller thread");
	}
}

net_nfc_card_emulation_mode_t net_nfc_server_se_get_se_state()
{
	net_nfc_card_emulation_mode_t state;
	int se_policy = SECURE_ELEMENT_POLICY_INVALID;

	if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_policy) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");
	}

	state = __se_get_se_state(se_policy);

	DEBUG_SERVER_MSG("se state [%s]", state ? "activated" : "deactivated");

	return state;
}

net_nfc_error_e net_nfc_server_se_set_se_state(
	net_nfc_card_emulation_mode_t state)
{
	net_nfc_error_e result;
	int se_policy = SECURE_ELEMENT_POLICY_INVALID;

	if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_policy) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");

		return NET_NFC_OPERATION_FAIL;
	}

	if (__se_get_se_type(se_policy) == NET_NFC_SE_TYPE_UICC &&
		gdbus_uicc_ready != SE_UICC_READY) {
		DEBUG_ERR_MSG("UICC not initialized, changing state not permitted");

		return NET_NFC_OPERATION_FAIL;
	}

	if (se_policy == SECURE_ELEMENT_POLICY_INVALID) {
		DEBUG_ERR_MSG("invalid se is selected, changing state not permitted");

		return NET_NFC_OPERATION_FAIL;
	}

	if (__se_get_se_state(se_policy) != state) {
		switch (__se_get_se_type(se_policy)) {
		case NET_NFC_SE_TYPE_UICC :
			if (state == NET_NFC_CARD_EMELATION_ENABLE) {
				se_policy = SECURE_ELEMENT_POLICY_UICC_ON;
			} else {
				se_policy = SECURE_ELEMENT_POLICY_UICC_OFF;
			}
			break;

		case NET_NFC_SE_TYPE_ESE :
			/* FIXME */
			if (state == NET_NFC_CARD_EMELATION_ENABLE) {
				se_policy = SECURE_ELEMENT_POLICY_ESE_ON;
			} else {
				se_policy = SECURE_ELEMENT_POLICY_ESE_OFF;
			}
			break;

		case NET_NFC_SE_TYPE_HCE :
			/* FIXME */
			if (state == NET_NFC_CARD_EMELATION_ENABLE) {
				se_policy = SECURE_ELEMENT_POLICY_HCE_ON;
			} else {
				se_policy = SECURE_ELEMENT_POLICY_HCE_OFF;
			}
			break;

		default :
			se_policy = SECURE_ELEMENT_POLICY_INVALID;
			break;
		}

		if (vconf_set_int(VCONFKEY_NFC_SE_TYPE, se_policy) == 0) {
			result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("vconf_set_int failed");

			result = NET_NFC_OPERATION_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("same state");

		result = NET_NFC_INVALID_STATE;
	}

	return result;
}

inline static const char *__se_get_se_name(net_nfc_se_type_e type)
{
	const char *name;

	switch (type) {
	case NET_NFC_SE_TYPE_UICC :
		name = "UICC";
		break;

	case NET_NFC_SE_TYPE_ESE :
		name = "eSE";
		break;

	case NET_NFC_SE_TYPE_HCE :
		name = "HCE";
		break;

	default :
		name = "unknown";
		break;
	}

	return name;
}

static net_nfc_se_type_e __se_get_se_type(
	net_nfc_secure_element_policy_e policy)
{
	net_nfc_se_type_e type;

	switch (policy)
	{
	case SECURE_ELEMENT_POLICY_UICC_ON :
	case SECURE_ELEMENT_POLICY_UICC_OFF :
		type = NET_NFC_SE_TYPE_UICC;
		break;

	case SECURE_ELEMENT_POLICY_ESE_ON :
	case SECURE_ELEMENT_POLICY_ESE_OFF :
		type = NET_NFC_SE_TYPE_ESE;
		break;

	case SECURE_ELEMENT_POLICY_HCE_ON :
	case SECURE_ELEMENT_POLICY_HCE_OFF :
		type = NET_NFC_SE_TYPE_HCE;
		break;

	default:
		type = NET_NFC_SE_TYPE_NONE;
		break;
	}

	return type;
}

net_nfc_se_type_e net_nfc_server_se_get_se_type()
{
	net_nfc_se_type_e se_type;
	int wallet_mode = 0;

	if (vconf_get_int(VCONFKEY_NFC_WALLET_MODE, &wallet_mode) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");
	}

	/*TODO : Modify the wallet mode*/
	if (wallet_mode != NET_NFC_WALLET_MODE_UICC) {
		int se_policy = SECURE_ELEMENT_POLICY_INVALID;

		if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_policy) != 0) {
			DEBUG_ERR_MSG("vconf_get_int failed");
		}

		se_type = __se_get_se_type(se_policy);
	} else {
		se_type = NET_NFC_SE_TYPE_UICC;
	}

	DEBUG_SERVER_MSG("active se [%s]", __se_get_se_name(se_type));

	return se_type;
}

net_nfc_error_e net_nfc_server_se_set_se_type(net_nfc_se_type_e type)
{
	net_nfc_error_e result;
	int se_policy = SECURE_ELEMENT_POLICY_INVALID;
	int wallet_mode = 0;

	if (vconf_get_int(VCONFKEY_NFC_WALLET_MODE, &wallet_mode) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");

		return NET_NFC_OPERATION_FAIL;
	}

	if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_policy) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");

		return NET_NFC_OPERATION_FAIL;
	}


	if (wallet_mode == NET_NFC_WALLET_MODE_UICC) {
		DEBUG_ERR_MSG("not supported in wallet mode");

		return NET_NFC_INVALID_STATE;
	}

	if (__se_get_se_type(se_policy) != type) {
		switch (type) {
		case NET_NFC_SE_TYPE_UICC :
			if (__se_get_se_state(se_policy) ==
				NET_NFC_CARD_EMELATION_ENABLE) {
				se_policy = SECURE_ELEMENT_POLICY_UICC_ON;
			} else {
				se_policy = SECURE_ELEMENT_POLICY_UICC_OFF;
			}
			break;

		case NET_NFC_SE_TYPE_ESE :
			if (__se_get_se_state(se_policy) ==
				NET_NFC_CARD_EMELATION_ENABLE) {
				se_policy = SECURE_ELEMENT_POLICY_ESE_ON;
			} else {
				se_policy = SECURE_ELEMENT_POLICY_ESE_OFF;
			}
			break;

		case NET_NFC_SE_TYPE_HCE :
			if (__se_get_se_state(se_policy) ==
				NET_NFC_CARD_EMELATION_ENABLE) {
				se_policy = SECURE_ELEMENT_POLICY_HCE_ON;
			} else {
				se_policy = SECURE_ELEMENT_POLICY_HCE_OFF;
			}
			break;

		default :
			se_policy = SECURE_ELEMENT_POLICY_INVALID;
			break;
		}

		if (vconf_set_int(VCONFKEY_NFC_SE_TYPE, se_policy) == 0) {
			result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("vconf_set_int failed");

			result = NET_NFC_OPERATION_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("activated already, [%s]", __se_get_se_name(type));

		result = NET_NFC_INVALID_STATE;
	}

	return result;
}

static net_nfc_secure_element_policy_e __se_get_se_policy()
{
	int se_policy = SECURE_ELEMENT_POLICY_INVALID;
	int wallet_mode = 0;

	if (vconf_get_int(VCONFKEY_NFC_WALLET_MODE, &wallet_mode) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");
	}

	if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_policy) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");
	}

	if (wallet_mode == NET_NFC_WALLET_MODE_UICC) {
		if (__se_get_se_state(se_policy) ==
			NET_NFC_CARD_EMELATION_ENABLE) {
			se_policy = SECURE_ELEMENT_POLICY_UICC_ON;
		} else {
			se_policy = SECURE_ELEMENT_POLICY_UICC_OFF;
		}
	}
	else if(wallet_mode == NET_NFC_WALLET_MODE_ESE) {
		if (__se_get_se_state(se_policy) ==
			NET_NFC_CARD_EMELATION_ENABLE) {
			se_policy = SECURE_ELEMENT_POLICY_ESE_ON;
		} else {
			se_policy = SECURE_ELEMENT_POLICY_ESE_OFF;
		}
	}
	else if(wallet_mode == NET_NFC_WALLET_MODE_HCE) {
		if (__se_get_se_state(se_policy) ==
			NET_NFC_CARD_EMELATION_ENABLE) {
			se_policy = SECURE_ELEMENT_POLICY_HCE_ON;
		} else {
			se_policy = SECURE_ELEMENT_POLICY_HCE_OFF;
		}
	}


	return se_policy;
}
#if 0
net_nfc_error_e net_nfc_server_se_set_se_policy(
	net_nfc_secure_element_policy_e policy)
{
	net_nfc_error_e result = NET_NFC_OK;
	int vconf_key;
	int wallet_mode = 0;
	int se_type = 0;

	DEBUG_SERVER_MSG("set se policy [%d]", policy);

	if (vconf_get_int(VCONFKEY_NFC_WALLET_MODE, &wallet_mode) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");
	}

	if (vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_type) != 0) {
		DEBUG_ERR_MSG("vconf_get_int failed");
	}

	if (wallet_mode == VCONFKEY_NFC_WALLET_MODE_MANUAL) {
		if (policy == SECURE_ELEMENT_POLICY_UICC_ON) {
			if (se_type == SECURE_ELEMENT_POLICY_ESE_ON ||
				se_type == SECURE_ELEMENT_POLICY_ESE_OFF) {
				policy = SECURE_ELEMENT_POLICY_ESE_ON;
			}
		} else if (policy == SECURE_ELEMENT_POLICY_UICC_OFF) {
			if (se_type == SECURE_ELEMENT_POLICY_ESE_ON ||
				se_type == SECURE_ELEMENT_POLICY_ESE_OFF) {
				policy = SECURE_ELEMENT_POLICY_ESE_OFF;
			}
		}
	}

	switch (policy)
	{
	case SECURE_ELEMENT_POLICY_UICC_ON :
		vconf_key = VCONFKEY_NFC_SE_POLICY_UICC_ON;
		break;

	case SECURE_ELEMENT_POLICY_UICC_OFF :
		vconf_key = VCONFKEY_NFC_SE_POLICY_UICC_OFF;
		break;

	case SECURE_ELEMENT_POLICY_ESE_ON :
		vconf_key = VCONFKEY_NFC_SE_POLICY_ESE_ON;
		break;

	case SECURE_ELEMENT_POLICY_ESE_OFF :
		vconf_key = VCONFKEY_NFC_SE_POLICY_ESE_OFF;
		break;

	default:
		vconf_key = VCONFKEY_NFC_SE_POLICY_NONE;
		break;
	}

	if (vconf_set_int(VCONFKEY_NFC_SE_TYPE, vconf_key) != 0) {
		DEBUG_ERR_MSG("vconf_set_int failed");
		result = NET_NFC_OPERATION_FAIL;
	}

	return result;
}
#endif
/* eSE functions */
static bool net_nfc_server_se_is_ese_handle(net_nfc_target_handle_s *handle)
{
	return (gdbus_ese_handle != NULL &&
		gdbus_ese_handle == handle);
}

static void net_nfc_server_se_set_current_ese_handle(
			net_nfc_target_handle_s *handle)
{
	gdbus_ese_handle = handle;
}

static net_nfc_target_handle_s *net_nfc_server_se_open_ese()
{
	if (gdbus_ese_handle == NULL) {
		net_nfc_error_e result = NET_NFC_OK;
		net_nfc_target_handle_s *handle = NULL;

		if (net_nfc_controller_secure_element_open(
			NET_NFC_SE_TYPE_ESE,
			&handle, &result) == true)
		{
			net_nfc_server_se_set_current_ese_handle(handle);

			DEBUG_SERVER_MSG("handle [%p]", handle);
		}
		else
		{
			DEBUG_ERR_MSG("net_nfc_controller_secure_element_open failed [%d]",
				result);
		}
	}

	return gdbus_ese_handle;
}

static net_nfc_error_e net_nfc_server_se_close_ese()
{
	net_nfc_error_e result = NET_NFC_OK;

	if (gdbus_ese_handle != NULL &&
		net_nfc_server_gdbus_is_server_busy() == false) {
		if (net_nfc_controller_secure_element_close(
			gdbus_ese_handle,
			&result) == false)
		{
			net_nfc_controller_exception_handler();
		}
		net_nfc_server_se_set_current_ese_handle(NULL);
	}

	return result;
}

static void _sim_apdu_cb(TapiHandle *handle, int result,
		    void *data, void *user_data)
{
    TelSimAccessResult_t access_rt = (TelSimAccessResult_t)result;
    resp_apdu = (TelSimApduResp_t *)data;
    GMainLoop *loop = (GMainLoop *)user_data;

	g_main_loop_quit(loop);
}

static void _sim_atr_cb(TapiHandle *handle, int result,
		void *data, void *user_data)
{
    TelSimAccessResult_t access_rt = (TelSimAccessResult_t)result;
	resp_atr  = (TelSimAtrResp_t *)data;
	GMainLoop *loop = (GMainLoop *)user_data;

	g_main_loop_quit(loop);
}


static bool _se_uicc_send_apdu(net_nfc_target_handle_s *handle,
	data_s *apdu, data_s **response)
{
	bool ret;
	int result;
	GMainLoop *loop = NULL;

	if (apdu == NULL || apdu->buffer == NULL || response == NULL)
		return false;

	apdu_data.apdu = apdu->buffer;
	apdu_data.apdu_len = apdu->length;
	loop = g_main_loop_new(NULL, false);

	result = tel_req_sim_apdu((TapiHandle *)handle, &apdu_data, _sim_apdu_cb, &loop);
	if (result == 0 &&
		resp_apdu->apdu_resp_len > 0) {
		data_s *temp = NULL;

		g_main_loop_run(loop);

		temp = net_nfc_util_create_data(resp_apdu->apdu_resp_len);
		if (temp != NULL) {
			memcpy(temp->buffer,
				resp_apdu->apdu_resp,
				temp->length);

			*response = temp;
			ret = true;
		} else {
			DEBUG_ERR_MSG("alloc failed");

			ret = false;
		}
	} else {
		DEBUG_ERR_MSG("tel_call_sim_sync failed, [%d]", result);

		ret = false;
	}

	return ret;
}

static bool _se_uicc_get_atr(net_nfc_target_handle_s *handle, data_s **atr)
{
	bool ret;
	int result;
	GMainLoop *loop;

	if (atr == NULL)
		return false;

	loop = g_main_loop_new(NULL, false);

	result = tel_req_sim_atr((TapiHandle *)handle, _sim_atr_cb, &loop);
	if (result == 0){
		data_s *temp = NULL;

		g_main_loop_run(loop);

		temp = net_nfc_util_create_data(resp_atr->atr_resp_len);
		if (temp != NULL) {
			memcpy(temp->buffer, resp_atr->atr_resp,
				temp->length);

			*atr = temp;
			ret = true;
		} else {
			DEBUG_ERR_MSG("alloc failed");

			ret = false;
		}
	} else {
		DEBUG_ERR_MSG("tel_call_sim_sync failed, [%d]", result);

		ret = false;
	}

	return ret;
}

#ifdef ENABLE_TELEPHONY
static void _se_uicc_prepare(void)
{
	gdbus_uicc_handle = tel_init(NULL);
}

static void _vconf_sim_status_cb(keynode_t *node, void *user_data)
{
	DEBUG_SERVER_MSG("VCONFKEY_TELEPHONY_SIM_STATUS [%d]", node->value.i);

	switch (node->value.i) {
	case VCONFKEY_TELEPHONY_SIM_STATUS_INIT_COMPLETED :
		{
			int se_policy;

			gdbus_uicc_ready = SE_UICC_READY;

			_se_uicc_prepare();

			se_policy = __se_get_se_policy();

			DEBUG_SERVER_MSG("current se policy [%d]", se_policy);

			if (se_policy == SECURE_ELEMENT_POLICY_UICC_ON) {
				net_nfc_server_se_apply_se_policy(SECURE_ELEMENT_POLICY_UICC_ON);
			}
		}
		break;
	case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_REMOVED :
	case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_ERROR :
	case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_BLOCKED :
	case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_CRASHED :
		gdbus_uicc_ready = SE_UICC_UNAVAILABLE;
#if 0
		if (__se_get_se_policy() == SECURE_ELEMENT_POLICY_UICC_ON) {
			net_nfc_server_se_set_se_policy(SECURE_ELEMENT_POLICY_UICC_OFF);
		}
#endif
		break;


	case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_NOT_PRESENT :
#if 0 		/* temp_patch_for_no_SIM_currency_issue */
	{
		int ret;
		int se_type;
		ret = vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_type);

		if (ret == 0 &&
			 se_type == VCONFKEY_NFC_SE_TYPE_UICC)
		{
			net_nfc_error_e result = NET_NFC_OK;
			DEBUG_SERVER_MSG("_vconf_sim_status_cb  VCONFKEY_NFC_SE_TYPE_UICC but VCONFKEY_TELEPHONY_SIM_STATUS_CARD_NOT_PRESENT ");

			/*turn off ESE*/
			net_nfc_controller_set_secure_element_mode(
				SECURE_ELEMENT_TYPE_ESE,
				SECURE_ELEMENT_OFF_MODE,
				&result);

			/*turn on UICC*/
			net_nfc_controller_set_secure_element_mode(
				SECURE_ELEMENT_TYPE_UICC,
				SECURE_ELEMENT_VIRTUAL_MODE,
				&result);
		}
	}
		break;
#endif
	default :
		break;
	}
}

static void _se_uicc_init(void)
{
	int status;

	vconf_notify_key_changed(VCONFKEY_TELEPHONY_SIM_STATUS,
		_vconf_sim_status_cb, NULL);

	if (vconf_get_int(VCONFKEY_TELEPHONY_SIM_STATUS, &status) == 0) {
		DEBUG_SERVER_MSG("VCONFKEY_TELEPHONY_SIM_STATUS [%d]", status);

		switch (status) {
		case VCONFKEY_TELEPHONY_SIM_STATUS_INIT_COMPLETED :
			gdbus_uicc_ready = SE_UICC_READY;

			_se_uicc_prepare();
			break;

		case VCONFKEY_TELEPHONY_SIM_STATUS_UNKNOWN :
		case VCONFKEY_TELEPHONY_SIM_STATUS_INITIALIZING :
		case VCONFKEY_TELEPHONY_SIM_STATUS_PIN_REQUIRED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_PUK_REQUIRED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_NCK_REQUIRED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_NSCK_REQUIRED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_SPCK_REQUIRED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_CCK_REQUIRED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_SIM_LOCK_REQUIRED :
			gdbus_uicc_ready = SE_UICC_ON_PROGRESS;
			break;

		case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_NOT_PRESENT :
#if 0 		/* temp_patch_for_no_SIM_currency_issue */
		{
			int ret;
			int se_type;
			ret = vconf_get_int(VCONFKEY_NFC_SE_TYPE, &se_type);

			if (ret == 0 &&
				 se_type == VCONFKEY_NFC_SE_TYPE_UICC)
			{
				net_nfc_error_e result = NET_NFC_OK;
				DEBUG_SERVER_MSG("_se_uicc_init  VCONFKEY_NFC_SE_TYPE_UICC but VCONFKEY_TELEPHONY_SIM_STATUS_CARD_NOT_PRESENT ");

				/*turn off ESE*/
				net_nfc_controller_set_secure_element_mode(
					SECURE_ELEMENT_TYPE_ESE,
					SECURE_ELEMENT_OFF_MODE,
					&result);

				/*turn on UICC*/
				net_nfc_controller_set_secure_element_mode(
					SECURE_ELEMENT_TYPE_UICC,
					SECURE_ELEMENT_VIRTUAL_MODE,
					&result);
			}
		}
			break;
#endif
		case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_ERROR :
		case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_BLOCKED :
		case VCONFKEY_TELEPHONY_SIM_STATUS_CARD_CRASHED :
		default :
			gdbus_uicc_ready = SE_UICC_UNAVAILABLE;
			break;
		}
	}
}

static void _se_uicc_deinit()
{
	if (gdbus_uicc_handle != NULL) {
		tel_deinit(gdbus_uicc_handle);

		gdbus_uicc_handle = NULL;
	}

	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_SIM_STATUS,
		_vconf_sim_status_cb);
}
#endif

static net_nfc_target_handle_s *_se_uicc_open(void)
{
	net_nfc_target_handle_s *result = NULL;

	if (gdbus_uicc_ready == SE_UICC_READY && gdbus_uicc_handle != NULL) {
		result = (net_nfc_target_handle_s *)gdbus_uicc_handle;
	}

	return result;
}

static bool _se_is_uicc_handle(net_nfc_target_handle_s *handle)
{
	return (gdbus_uicc_ready == SE_UICC_READY &&
		gdbus_uicc_handle != NULL &&
		(TapiHandle *)handle == gdbus_uicc_handle);
}

static void _se_uicc_close(net_nfc_target_handle_s *handle)
{
}

net_nfc_error_e net_nfc_server_se_apply_se_policy(
	net_nfc_secure_element_policy_e policy)
{
	net_nfc_error_e result = NET_NFC_OK;

	switch (policy)
	{
	case SECURE_ELEMENT_POLICY_UICC_ON :
		if (gdbus_uicc_ready == SE_UICC_READY)
		{
			net_nfc_controller_set_secure_element_mode(
				SECURE_ELEMENT_TYPE_ESE,
				SECURE_ELEMENT_OFF_MODE,
				&result);

			net_nfc_controller_set_secure_element_mode(
				SECURE_ELEMENT_TYPE_HCE,
				SECURE_ELEMENT_OFF_MODE,
				&result);

			net_nfc_controller_set_secure_element_mode(
				SECURE_ELEMENT_TYPE_UICC,
				SECURE_ELEMENT_VIRTUAL_MODE,
				&result);

			net_nfc_controller_secure_element_set_default_route(
				NET_NFC_SE_TYPE_UICC, NET_NFC_SE_TYPE_NONE,
				NET_NFC_SE_TYPE_UICC, &result);

			current_policy = policy;
		}
		else
		{
			current_policy = SECURE_ELEMENT_POLICY_UICC_OFF;
		}
		break;

	case SECURE_ELEMENT_POLICY_ESE_ON :
		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_HCE,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_VIRTUAL_MODE,
			&result);

		net_nfc_controller_secure_element_set_default_route(
			NET_NFC_SE_TYPE_ESE, NET_NFC_SE_TYPE_NONE,
			NET_NFC_SE_TYPE_ESE, &result);

		current_policy = policy;
		break;

	case SECURE_ELEMENT_POLICY_HCE_ON :
		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_HCE,
			SECURE_ELEMENT_VIRTUAL_MODE,
			&result);

		net_nfc_controller_secure_element_set_default_route(
			NET_NFC_SE_TYPE_HCE, NET_NFC_SE_TYPE_NONE,
			NET_NFC_SE_TYPE_HCE, &result);

		current_policy = policy;
		break;

	case SECURE_ELEMENT_POLICY_UICC_OFF :
	case SECURE_ELEMENT_POLICY_ESE_OFF :
	case SECURE_ELEMENT_POLICY_HCE_OFF :
	default :
		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_set_secure_element_mode(
			SECURE_ELEMENT_TYPE_HCE,
			SECURE_ELEMENT_OFF_MODE,
			&result);

		net_nfc_controller_secure_element_set_default_route(
			NET_NFC_SE_TYPE_NONE, NET_NFC_SE_TYPE_NONE,
			NET_NFC_SE_TYPE_NONE, &result);

		current_policy = policy;
		break;
	}

	return result;
}

net_nfc_error_e net_nfc_server_se_apply_se_current_policy()
{
	net_nfc_secure_element_policy_e policy;

	policy = __se_get_se_policy();

	DEBUG_SERVER_MSG("current se policy [%d]", policy);

	return net_nfc_server_se_apply_se_policy(policy);
}

net_nfc_error_e net_nfc_server_se_change_wallet_mode(
	net_nfc_wallet_mode_e wallet_mode)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_secure_element_policy_e new_policy;
	bool is_type_changed = false;
	bool is_card_mode_changed = false;

	new_policy = __se_get_se_policy();

	DEBUG_SERVER_MSG("current policy [%d], new policy [%d]", current_policy, new_policy);

	if (__se_get_se_type(current_policy) != __se_get_se_type(new_policy)) {
		is_type_changed = true;
	}

	if (__se_get_se_state(current_policy) != __se_get_se_state(new_policy)) {
		is_card_mode_changed = true;
	}

	if (is_type_changed == true || is_card_mode_changed == true) {
		result = net_nfc_server_se_apply_se_current_policy();
	}

	if (is_type_changed == true) {
		net_nfc_gdbus_secure_element_emit_se_type_changed(NULL,
			__se_get_se_type(new_policy));
	}

	if (is_card_mode_changed == true) {
		net_nfc_gdbus_secure_element_emit_card_emulation_mode_changed(
			NULL, __se_get_se_state(new_policy));
	}

	return result;
}

static void se_policy_apply_thread_func(gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_server_se_apply_se_current_policy();
}

static void se_close_secure_element_thread_func(gpointer user_data)
{
	SeDataHandle *detail = (SeDataHandle *)user_data;
	net_nfc_error_e result;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	if (_se_is_uicc_handle(detail->handle) == true)
	{
		_se_uicc_close(detail->handle);

		result = NET_NFC_OK;
	}
	else if (net_nfc_server_se_is_ese_handle(detail->handle) == true)
	{
		/* decrease client reference count */
		net_nfc_server_gdbus_decrease_se_count(
			g_dbus_method_invocation_get_sender(
				detail->invocation));

		result = net_nfc_server_se_close_ese();
	}
	else
	{
		result = NET_NFC_INVALID_HANDLE;
	}

	net_nfc_gdbus_secure_element_complete_close_secure_element(
		detail->object, detail->invocation, result);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);

#if 0 /* it causes some problems when user repeats open/close */
	/* shutdown process if it doesn't need */
	if (net_nfc_server_manager_get_active() == false &&
		net_nfc_server_gdbus_is_server_busy() == false) {
		net_nfc_server_controller_deinit();
	}
#endif
}

static gboolean se_handle_close_secure_element(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	GVariant *smack_privilege)
{
	SeDataHandle *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataHandle, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->handle = (net_nfc_target_handle_s *)arg_handle;

	if (net_nfc_server_controller_async_queue_push_force(
		se_close_secure_element_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_close_secure_element(
		object, invocation, result);

	return TRUE;
}

static void se_get_atr_thread_func(gpointer user_data)
{
	SeDataHandle *detail = (SeDataHandle *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	data_s *atr = NULL;
	GVariant *data;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	if (_se_is_uicc_handle(detail->handle) == true)
	{
		if (_se_uicc_get_atr(detail->handle, &atr) == true) {
			result = NET_NFC_OK;
		} else {
			result = NET_NFC_OPERATION_FAIL;
		}
	}
	else if (net_nfc_server_se_is_ese_handle(detail->handle) == true)
	{
		net_nfc_controller_secure_element_get_atr(detail->handle, &atr,
			&result);
	}
	else
	{
		DEBUG_ERR_MSG("invalid se handle");

		result = NET_NFC_INVALID_HANDLE;
	}

	data = net_nfc_util_gdbus_data_to_variant(atr);

	net_nfc_gdbus_secure_element_complete_get_atr(
		detail->object,
		detail->invocation,
		result,
		data);

	if (atr != NULL) {
		net_nfc_util_free_data(atr);
	}

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}

static gboolean se_handle_get_atr(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	GVariant *smack_privilege)
{
	SeDataHandle *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataHandle, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->handle = (net_nfc_target_handle_s *)arg_handle;

	if (net_nfc_server_controller_async_queue_push_force(
		se_get_atr_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_get_atr(object, invocation,
		result, net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static void se_open_secure_element_thread_func(gpointer user_data)
{
	SeDataSeType *detail = (SeDataSeType *)user_data;
	net_nfc_target_handle_s *handle = NULL;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	if (detail->se_type == NET_NFC_SE_TYPE_UICC)
	{
		handle = (net_nfc_target_handle_s *)_se_uicc_open();
		if (handle != NULL)
		{
			result = NET_NFC_OK;
		}
		else
		{
			result = NET_NFC_INVALID_STATE;
			handle = NULL;
		}
	}
	else if (detail->se_type == NET_NFC_SE_TYPE_ESE)
	{
		handle = net_nfc_server_se_open_ese();
		if (handle != NULL)
		{
			result = NET_NFC_OK;

			DEBUG_SERVER_MSG("handle [%p]", handle);

			/* increase client reference count */
			net_nfc_server_gdbus_increase_se_count(
				g_dbus_method_invocation_get_sender(
					detail->invocation));
		}
		else
		{
			result = NET_NFC_INVALID_STATE;
			handle = NULL;
		}
	}
	else
	{
		result = NET_NFC_INVALID_PARAM;
		handle = NULL;
	}

	net_nfc_gdbus_secure_element_complete_open_secure_element(
		detail->object,
		detail->invocation,
		result,
		(guint)handle);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}

static gboolean se_handle_open_secure_element(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	gint arg_type,
	GVariant *smack_privilege)
{
	SeDataSeType *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataSeType, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type= arg_type;

	if (net_nfc_server_controller_async_queue_push_force(
		se_open_secure_element_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_open_secure_element(
		object, invocation, result, 0);

	return TRUE;
}

static void se_send_apdu_thread_func(gpointer user_data)
{
	SeDataApdu *detail = (SeDataApdu *)user_data;
	data_s apdu_data = { NULL, 0 };
	data_s *response = NULL;
	net_nfc_error_e result = NET_NFC_OK;
	GVariant *rspdata = NULL;
	bool ret;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	net_nfc_util_gdbus_variant_to_data_s(detail->data, &apdu_data);

	if (_se_is_uicc_handle(detail->handle) == true)
	{
		ret = _se_uicc_send_apdu(detail->handle, &apdu_data, &response);
		if (ret == false) {
			DEBUG_ERR_MSG("_se_uicc_send_apdu failed");

			result = NET_NFC_OPERATION_FAIL;
		} else {
			result = NET_NFC_OK;
		}
	}
	else if (net_nfc_server_se_is_ese_handle(detail->handle) == true)
	{
		ret = net_nfc_controller_secure_element_send_apdu(
			detail->handle, &apdu_data, &response, &result);
	}
	else
	{
		result = NET_NFC_INVALID_HANDLE;
	}

	rspdata = net_nfc_util_gdbus_data_to_variant(response);

	net_nfc_gdbus_secure_element_complete_send_apdu(
		detail->object,
		detail->invocation,
		result,
		rspdata);

	if (response != NULL)
	{
		net_nfc_util_free_data(response);
	}

	net_nfc_util_clear_data(&apdu_data);

	g_variant_unref(detail->data);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}

static gboolean se_handle_send_apdu(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint arg_handle,
	GVariant *apdudata,
	GVariant *smack_privilege)
{
	SeDataApdu *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataApdu, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->handle = (net_nfc_target_handle_s *)arg_handle;
	data->data = g_variant_ref(apdudata);

	if (net_nfc_server_controller_async_queue_push_force(
		se_send_apdu_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_variant_unref(data->data);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_send_apdu(object, invocation,
		result, net_nfc_util_gdbus_buffer_to_variant(NULL, 0));

	return TRUE;
}

static void se_set_data_thread_func(gpointer user_data)
{
	SeDataSeType *data = (SeDataSeType *)user_data;
	gboolean isTypeChanged = FALSE;
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	result = net_nfc_server_se_set_se_type(data->se_type);

	if (result == NET_NFC_OK)
		isTypeChanged = TRUE;

	net_nfc_gdbus_secure_element_complete_set(data->object,
		data->invocation, result);

	if (isTypeChanged) {
		net_nfc_gdbus_secure_element_emit_se_type_changed(data->object,
			data->se_type);
	}

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_set(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	gint arg_type,
	GVariant *smack_privilege)
{
	SeDataSeType *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"w") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataSeType, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = arg_type;

	if (net_nfc_server_controller_async_queue_push(
		se_set_data_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_set(object, invocation, result);

	return TRUE;
}

static void se_get_data_thread_func(gpointer user_data)
{
	SeDataSeType *data = (SeDataSeType *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	net_nfc_gdbus_secure_element_complete_get(data->object,
		data->invocation,
		result,
		net_nfc_server_se_get_se_type());

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_get(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege)
{
	SeDataSeType *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataSeType, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		se_get_data_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_get(object, invocation,
		result, 0);

	return TRUE;
}

static void _se_change_card_emulation_mode_thread_func(gpointer user_data)
{
	ChangeCardEmulMode *data = (ChangeCardEmulMode *)user_data;
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	result = net_nfc_server_se_set_se_state(data->mode);

	net_nfc_gdbus_secure_element_complete_set_card_emulation(
		data->object, data->invocation, result);

	if (result == NET_NFC_OK) {
		net_nfc_gdbus_secure_element_emit_card_emulation_mode_changed(
			data->object, data->mode);
	}

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_change_card_emulation_mode(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	gint arg_mode,
	GVariant *smack_privilege)
{
	ChangeCardEmulMode *data = NULL;
	gboolean result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"w") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(ChangeCardEmulMode, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		g_dbus_method_invocation_return_dbus_error(invocation,
			"org.tizen.NetNfcService.AllocationError",
			"Can not allocate memory");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->mode = arg_mode;

	result = net_nfc_server_controller_async_queue_push(
		_se_change_card_emulation_mode_thread_func, data);
	if (result == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_set_card_emulation(object,
		invocation, result);

	return TRUE;

}

static void se_get_secure_element_mode_thread_func(gpointer user_data)
{
	SeDataSeType *data = (SeDataSeType *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_card_emulation_mode_t card_emulation_state;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	card_emulation_state = net_nfc_server_se_get_se_state();

	net_nfc_gdbus_secure_element_complete_get_card_emulation(data->object,
		data->invocation,
		result,
		card_emulation_state);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static void se_enable_transaction_fg_dispatch(gpointer user_data)
{
	SeDataTransactionFgDispatch *data = (SeDataTransactionFgDispatch *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	result = net_nfc_server_gdbus_set_transaction_fg_dispatch(
		g_dbus_method_invocation_get_sender(data->invocation),
		data->FgDispatch);

	net_nfc_gdbus_secure_element_complete_set_transaction_fg_dispatch (
		data->object,
		data->invocation,
		result);
}

static gboolean se_handle_get_card_emulation_mode(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	GVariant *smack_privilege)
{
	SeDataSeType *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataSeType, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);

	if (net_nfc_server_controller_async_queue_push(
		se_get_secure_element_mode_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_get_card_emulation(object, invocation,
		result, 0);

	return TRUE;
}

static gboolean se_handle_set_transaction_fg_dispatch(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	gint arg_mode,
	GVariant *smack_privilege)
{
	SeDataTransactionFgDispatch *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataTransactionFgDispatch, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->FgDispatch= arg_mode;

	if (net_nfc_server_controller_async_queue_push(
		se_enable_transaction_fg_dispatch, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_get_card_emulation(object, invocation,
		result, 0);

	return TRUE;
}

static void se_check_transaction_permission(gpointer user_data)
{
	SeDataApdu *data = (SeDataApdu *)user_data;
	net_nfc_error_e result;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	result = NET_NFC_OK;

	net_nfc_gdbus_secure_element_complete_check_transaction_permission(
		data->object,
		data->invocation,
		result);

	g_variant_unref(data->data);
	g_object_unref(data->invocation);
	g_object_unref(data->object);
}

static gboolean se_handle_check_transaction_permission(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	GVariant *arg_aid,
	GVariant *smack_privilege)
{
	SeDataApdu *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"r") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataApdu, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->data = g_variant_ref(arg_aid);

	if (net_nfc_server_controller_async_queue_push(
		se_check_transaction_permission, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->data);
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_check_transaction_permission(
		object, invocation, result);

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////

static void se_set_default_route_thread_func(gpointer user_data)
{
	SeDefaultRoute *detail = (SeDefaultRoute *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	INFO_MSG(">>> Call se_set_default_route_thread_func");

	net_nfc_controller_secure_element_set_default_route(detail->switch_on,
		detail->switch_off, detail->battery_off, &result);

	net_nfc_gdbus_secure_element_complete_set_default_route(
		detail->object,
		detail->invocation,
		result);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}

static gboolean se_handle_set_default_route(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint switch_on,
	guint switch_off,
	guint battery_off,
	GVariant *smack_privilege)
{
	SeDefaultRoute *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDefaultRoute, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->switch_on = switch_on;
	data->switch_off = switch_off;
	data->battery_off = battery_off;

	if (net_nfc_server_controller_async_queue_push_force(
		se_set_default_route_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_set_default_route(
		object, invocation, result);

	return TRUE;
}



static void se_is_activated_aid_handler_thread_func(gpointer user_data)
{
	SeDataAid *data = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *handler;
	gboolean activated = false;
	const char *id;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> Call se_is_activated_aid_handler_thread_func");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	handler = net_nfc_server_route_table_find_handler_by_id(id);
	if (handler != NULL) {
		activated = handler->activated;
	}

	net_nfc_gdbus_secure_element_complete_is_activated_aid_handler(
		data->object, data->invocation, result, activated);

	g_free(data->aid);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_is_activated_aid_handler(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint se_type,
	const gchar *aid,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = se_type;
	data->aid = g_strdup(aid);

	if (net_nfc_server_controller_async_queue_push_force(
		se_is_activated_aid_handler_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->aid);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_is_activated_aid_handler(
		object, invocation, result, false);

	return TRUE;
}

static void se_is_activated_category_handler_thread_func(gpointer user_data)
{
	SeDataAid *data = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *handler;
	gboolean activated = false;
	const char *id;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> Call se_is_activated_category_handler_thread_func");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	handler = net_nfc_server_route_table_find_handler_by_id(id);
	if (handler != NULL) {
		activated = handler->activated;
	}

	net_nfc_gdbus_secure_element_complete_is_activated_category_handler(
		data->object, data->invocation, result, activated);

	g_free(data->aid);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_is_activated_category_handler(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint se_type,
	guint category,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = se_type;
	data->category = category;

	if (net_nfc_server_controller_async_queue_push_force(
		se_is_activated_category_handler_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_is_activated_category_handler(
		object, invocation, result, false);

	return TRUE;
}

static bool __get_aids_iter_cb(const char *package,
	route_table_handler_t *handler, aid_info_t *aid, void *user_data)
{
	gpointer* params = (gpointer *)user_data;

	if (aid->category == (net_nfc_card_emulation_category_t)params[0]) {
		g_variant_builder_add((GVariantBuilder *)params[1],
			"(sb)", aid->aid, (gboolean)aid->manifest);
	}

	return true;
}

static void se_get_registered_aids_thread_func(gpointer user_data)
{
	SeDataAid *data = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	const char *id;
	GVariantBuilder builder;
	GVariant *aids;
	gpointer params[2];

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> Call se_get_registered_aids_thread_func");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	g_variant_builder_init(&builder, G_VARIANT_TYPE("a(sb)"));

	params[0] = (gpointer)data->category;
	params[1] = &builder;

	net_nfc_server_route_table_iterate_aid_by_id(id, __get_aids_iter_cb,
		params);

	aids = g_variant_builder_end(&builder);

	net_nfc_gdbus_secure_element_complete_get_registered_aids(
		data->object, data->invocation, result, aids);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_get_registered_aids(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint se_type,
	guint category,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = se_type;
	data->category = category;

	if (net_nfc_server_controller_async_queue_push_force(
		se_get_registered_aids_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	GVariantBuilder builder;
	GVariant *aids;

	g_variant_builder_init(&builder, G_VARIANT_TYPE("a(s)"));
	aids = g_variant_builder_end(&builder);

	net_nfc_gdbus_secure_element_complete_get_registered_aids(
		object, invocation, result, aids);

	return TRUE;
}

static void se_register_aid_thread_func(gpointer user_data)
{
	SeDataAid *data = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *handler;
	const char *id;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> Call se_register_aid_thread_func");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	handler = net_nfc_server_route_table_find_handler_by_id(id);
	if (handler == NULL) {
		result = net_nfc_server_route_table_add_handler_by_id(id);
		if (result == NET_NFC_OK) {
			handler = net_nfc_server_route_table_find_handler_by_id(id);
		}
	}

	if (handler != NULL) {
		result = net_nfc_server_route_table_add_aid_by_id(id,
			data->se_type, data->category, false, data->aid);
	}

	net_nfc_gdbus_secure_element_complete_register_aid(
		data->object, data->invocation, result);

	g_free(data->aid);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_register_aid(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint se_type,
	guint category,
	const gchar *aid,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = se_type;
	data->category = category;
	data->aid = g_strdup(aid);

	if (net_nfc_server_controller_async_queue_push_force(
		se_register_aid_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->aid);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_register_aid(
		object, invocation, result);

	return TRUE;
}

static void se_unregister_aid_thread_func(gpointer user_data)
{
	SeDataAid *data = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *handler;
	const char *id;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> Call se_unregister_aid_thread_func");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	handler = net_nfc_server_route_table_find_handler_by_id(id);
	if (handler != NULL) {
		net_nfc_server_route_table_del_aid_by_id(id, data->aid, false);

		result = NET_NFC_OK;
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	net_nfc_gdbus_secure_element_complete_unregister_aid(
		data->object, data->invocation, result);

	g_free(data->aid);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_unregister_aid(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint se_type,
	guint category,
	const gchar *aid,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = se_type;
	data->category = category;
	data->aid = g_strdup(aid);

	if (net_nfc_server_controller_async_queue_push_force(
		se_unregister_aid_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->aid);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_unregister_aid(
		object, invocation, result);

	return TRUE;
}

static void se_unregister_aids_thread_func(gpointer user_data)
{
	SeDataAid *data = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *handler;
	const char *id;

	g_assert(data != NULL);
	g_assert(data->object != NULL);
	g_assert(data->invocation != NULL);

	INFO_MSG(">>> Call se_unregister_aids_thread_func");

	id = g_dbus_method_invocation_get_sender(data->invocation);

	handler = net_nfc_server_route_table_find_handler_by_id(id);
	if (handler != NULL) {
		result = net_nfc_server_route_table_del_handler_by_id(id);
	} else {
		result = NET_NFC_NO_DATA_FOUND;
	}

	net_nfc_gdbus_secure_element_complete_unregister_aids(
		data->object, data->invocation, result);

	g_object_unref(data->invocation);
	g_object_unref(data->object);

	g_free(data);
}

static gboolean se_handle_unregister_aids(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	guint se_type,
	guint category,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));

	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager::card_emul",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}

	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->se_type = se_type;
	data->category = category;

	if (net_nfc_server_controller_async_queue_push_force(
		se_unregister_aids_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_unregister_aids(
		object, invocation, result);

	return TRUE;
}

static void se_add_route_aid_thread_func(gpointer user_data)
{
	SeDataAid *detail = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	INFO_MSG(">>> Call se_add_route_aid_thread_func");

	result = net_nfc_server_route_table_insert_aid_into_db(detail->package,
		detail->se_type, detail->category, detail->aid,
		detail->unlock, detail->power);

	net_nfc_gdbus_secure_element_complete_add_route_aid(
		detail->object, detail->invocation, result);

	g_free(detail->aid);
	g_free(detail->package);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}

static gboolean se_handle_add_route_aid(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	const gchar *package,
	const gchar *aid,
	guint se_type,
	guint category,
	gboolean unlock,
	guint power,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));
#if 0
	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}
#endif
	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->package = g_strdup(package);
	data->aid = g_strdup(aid);
	data->se_type = se_type;
	data->category = category;
	data->unlock = unlock;
	data->power = power;

	INFO_MSG(">>> hce_add_aid_thread_func");

	if (net_nfc_server_controller_async_queue_push_force(
		se_add_route_aid_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->aid);
		g_free(data->package);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_add_route_aid(object, invocation,
		result);

	return TRUE;
}

static void se_remove_route_aid_thread_func(gpointer user_data)
{
	SeDataAid *detail = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	INFO_MSG(">>> Call se_remove_route_aid_thread_func");

	result = net_nfc_server_route_table_delete_aid_from_db(detail->package,
		detail->aid);

	net_nfc_gdbus_secure_element_complete_remove_route_aid(
		detail->object, detail->invocation, result);

	g_free(detail->aid);
	g_free(detail->package);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}


static gboolean se_handle_remove_route_aid(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	const gchar *package,
	const gchar *aid,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));
#if 0
	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}
#endif
	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->package = g_strdup(package);
	data->aid = g_strdup(aid);

	if (net_nfc_server_controller_async_queue_push_force(
		se_remove_route_aid_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->aid);
		g_free(data->package);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_remove_route_aid(
		object, invocation, result);

	return TRUE;
}

static void se_remove_package_aids_thread_func(gpointer user_data)
{
	SeDataAid *detail = (SeDataAid *)user_data;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(detail != NULL);
	g_assert(detail->object != NULL);
	g_assert(detail->invocation != NULL);

	INFO_MSG(">>> Call se_remove_package_aids_thread_func");

	result = net_nfc_server_route_table_delete_aids_from_db(detail->package);

	net_nfc_gdbus_secure_element_complete_remove_package_aids(
		detail->object, detail->invocation, result);

	g_free(detail->package);

	g_object_unref(detail->invocation);
	g_object_unref(detail->object);

	g_free(detail);
}

static gboolean se_handle_remove_package_aids(
	NetNfcGDbusSecureElement *object,
	GDBusMethodInvocation *invocation,
	const gchar *package,
	const gchar *aid,
	GVariant *smack_privilege)
{
	SeDataAid *data = NULL;
	gint result;

	INFO_MSG(">>> REQUEST from [%s]",
		g_dbus_method_invocation_get_sender(invocation));
#if 0
	/* check privilege and update client context */
	if (net_nfc_server_gdbus_check_privilege(invocation,
		smack_privilege,
		"nfc-manager",
		"rw") == false) {
		DEBUG_ERR_MSG("permission denied, and finished request");
		result = NET_NFC_PERMISSION_DENIED;

		goto ERROR;
	}
#endif
	data = g_try_new0(SeDataAid, 1);
	if (data == NULL)
	{
		DEBUG_ERR_MSG("Memory allocation failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	data->object = g_object_ref(object);
	data->invocation = g_object_ref(invocation);
	data->package = g_strdup(package);

	if (net_nfc_server_controller_async_queue_push_force(
		se_remove_package_aids_thread_func, data) == FALSE)
	{
		/* return error if queue was blocked */
		DEBUG_SERVER_MSG("controller is processing important message..");
		result = NET_NFC_BUSY;

		goto ERROR;
	}

	return TRUE;

ERROR :
	if (data != NULL) {
		g_free(data->package);

		g_object_unref(data->invocation);
		g_object_unref(data->object);

		g_free(data);
	}

	net_nfc_gdbus_secure_element_complete_remove_package_aids(
		object, invocation, result);

	return TRUE;
}

gboolean net_nfc_server_se_init(GDBusConnection *connection)
{
	GError *error = NULL;
	gboolean result;

	if (se_skeleton)
		g_object_unref(se_skeleton);

	net_nfc_server_route_table_init();

#ifdef ENABLE_TELEPHONY
	/* initialize UICC */
	_se_uicc_init();
#endif
	se_skeleton = net_nfc_gdbus_secure_element_skeleton_new();

	g_signal_connect(se_skeleton,
		"handle-set",
		G_CALLBACK(se_handle_set),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-get",
		G_CALLBACK(se_handle_get),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-set-card-emulation",
		G_CALLBACK(se_handle_change_card_emulation_mode),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-get-card-emulation",
		G_CALLBACK(se_handle_get_card_emulation_mode),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-open-secure-element",
		G_CALLBACK(se_handle_open_secure_element),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-close-secure-element",
		G_CALLBACK(se_handle_close_secure_element),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-get-atr",
		G_CALLBACK(se_handle_get_atr),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-send-apdu",
		G_CALLBACK(se_handle_send_apdu),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-set-transaction-fg-dispatch",
		G_CALLBACK(se_handle_set_transaction_fg_dispatch),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-check-transaction-permission",
		G_CALLBACK(se_handle_check_transaction_permission),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-set-default-route",
		G_CALLBACK(se_handle_set_default_route),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-is-activated-aid-handler",
		G_CALLBACK(se_handle_is_activated_aid_handler),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-is-activated-category-handler",
		G_CALLBACK(se_handle_is_activated_category_handler),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-get-registered-aids",
		G_CALLBACK(se_handle_get_registered_aids),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-register-aid",
		G_CALLBACK(se_handle_register_aid),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-unregister-aid",
		G_CALLBACK(se_handle_unregister_aid),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-unregister-aids",
		G_CALLBACK(se_handle_unregister_aids),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-add-route-aid",
		G_CALLBACK(se_handle_add_route_aid),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-remove-route-aid",
		G_CALLBACK(se_handle_remove_route_aid),
		NULL);

	g_signal_connect(se_skeleton,
		"handle-remove-package-aids",
		G_CALLBACK(se_handle_remove_package_aids),
		NULL);

	result = g_dbus_interface_skeleton_export(
		G_DBUS_INTERFACE_SKELETON(se_skeleton),
		connection,
		"/org/tizen/NetNfcService/SecureElement",
		&error);
	if (result == FALSE)
	{
		DEBUG_ERR_MSG("can not skeleton_export %s", error->message);

		g_error_free(error);

		net_nfc_server_se_deinit();
	}

	return result;
}

void net_nfc_server_se_deinit(void)
{
	if (se_skeleton)
	{
		g_object_unref(se_skeleton);
		se_skeleton = NULL;

#ifdef ENABLE_TELEPHONY
		/* de-initialize UICC */
		_se_uicc_deinit();
#endif
	}
}

static void se_detected_thread_func(gpointer user_data)
{
	net_nfc_target_handle_s *handle = NULL;
	uint32_t devType = 0;
	GVariant *data = NULL;
	net_nfc_error_e result = NET_NFC_OK;

	g_assert(user_data != NULL);

	if (se_skeleton == NULL)
	{
		DEBUG_ERR_MSG("se skeleton is not initialized");

		g_variant_unref((GVariant *)user_data);

		return;
	}

	g_variant_get((GVariant *)user_data,
		"uu@a(y)",
		(guint *)&handle,
		&devType,
		&data);

	net_nfc_server_se_set_current_ese_handle(handle);

	DEBUG_SERVER_MSG("trying to connect to ESE = [0x%p]", handle);

	if (!net_nfc_controller_connect(handle, &result))
	{
		DEBUG_SERVER_MSG("connect failed = [%d]", result);
	}

	net_nfc_gdbus_secure_element_emit_ese_detected(
		se_skeleton,
		GPOINTER_TO_UINT(handle),
		devType,
		data);

	g_variant_unref((GVariant *)user_data);
}

static void se_transcation_thread_func(gpointer user_data)
{
	ServerSeData *detail = (ServerSeData *)user_data;
	bool fg_dispatch;
	pid_t focus_app_pid;

	g_assert(user_data != NULL);

	if (detail->event == NET_NFC_MESSAGE_SE_START_TRANSACTION) {
		GVariant *aid = NULL;
		GVariant *param = NULL;
		uint8_t se_type;

		aid = net_nfc_util_gdbus_data_to_variant(&(detail->aid));
		param = net_nfc_util_gdbus_data_to_variant(&(detail->param));
		se_type = net_nfc_server_se_get_se_type();
		focus_app_pid = net_nfc_app_util_get_focus_app_pid();
		fg_dispatch = net_nfc_app_util_check_transaction_fg_dispatch();

		DEBUG_SERVER_MSG("TRANSACTION event fg dispatch [%d]", fg_dispatch);

		/* TODO : check access control */
		net_nfc_gdbus_secure_element_emit_transaction_event(
			se_skeleton,
			se_type,
			aid,
			param,
			fg_dispatch,
			focus_app_pid);

		if (fg_dispatch != true) {
			net_nfc_app_util_launch_se_transaction_app(
				se_type,
				detail->aid.buffer,
				detail->aid.length,
				detail->param.buffer,
				detail->param.length);
		}

		DEBUG_SERVER_MSG("launch se app end");
	}

	net_nfc_util_clear_data(&detail->param);
	net_nfc_util_clear_data(&detail->aid);

	g_free(detail);
}

static void se_rf_field_thread_func(gpointer user_data)
{
	DEBUG_SERVER_MSG("check se_skeleton = [0x%p]", se_skeleton);

	if (se_skeleton == NULL)
	{
		DEBUG_ERR_MSG("se skeleton is not initialized");
		return;
	}

	net_nfc_gdbus_secure_element_emit_rf_detected(
		se_skeleton);
}

void net_nfc_server_se_detected(void *info)
{
	net_nfc_request_target_detected_t *se_target =
		(net_nfc_request_target_detected_t *)info;
	GVariant *parameter;
	GVariant *data;

	data = net_nfc_util_gdbus_buffer_to_variant(
		se_target->target_info_values.buffer,
		se_target->target_info_values.length);

	parameter = g_variant_new("uu@a(y)",
		GPOINTER_TO_UINT(se_target->handle),
		se_target->devType,
		data);
	if (parameter != NULL) {
		if (net_nfc_server_controller_async_queue_push_force(
			se_detected_thread_func,
			parameter) == FALSE) {
			DEBUG_ERR_MSG("can not push to controller thread");

			g_variant_unref(parameter);
		}
	} else {
		DEBUG_ERR_MSG("g_variant_new failed");
	}

	/* FIXME : should be removed when plugins would be fixed*/
	_net_nfc_util_free_mem(info);
}

void net_nfc_server_se_transaction_received(void *info)
{
	net_nfc_request_se_event_t *se_event =
		(net_nfc_request_se_event_t *)info;
	ServerSeData *detail;

	detail = g_try_new0(ServerSeData, 1);
	if (detail != NULL) {
		detail->event = se_event->request_type;

		if (se_event->aid.buffer != NULL && se_event->aid.length > 0) {
			if (net_nfc_util_init_data(&detail->aid,
				se_event->aid.length) == true) {
				memcpy(detail->aid.buffer, se_event->aid.buffer,
					se_event->aid.length);
			}
		}

		if (se_event->param.buffer != NULL &&
			se_event->param.length > 0) {
			if (net_nfc_util_init_data(&detail->param,
				se_event->param.length) == true) {
				memcpy(detail->param.buffer,
					se_event->param.buffer,
					se_event->param.length);
			}
		}

		if (net_nfc_server_controller_async_queue_push_force(
			se_transcation_thread_func, detail) == FALSE) {
			DEBUG_ERR_MSG("can not push to controller thread");

			net_nfc_util_clear_data(&detail->param);
			net_nfc_util_clear_data(&detail->aid);

			g_free(detail);
		}
	} else {
		DEBUG_ERR_MSG("g_new0 failed");
	}

	/* FIXME : should be removed when plugins would be fixed*/
	net_nfc_util_clear_data(&se_event->param);
	net_nfc_util_clear_data(&se_event->aid);

	_net_nfc_util_free_mem(info);
}

void net_nfc_server_se_rf_field_on(void *info)
{
	DEBUG_SERVER_MSG("net_nfc_server_se_rf_field_on");

	if (net_nfc_server_controller_async_queue_push_force(
		se_rf_field_thread_func,
		NULL) == FALSE) {
		DEBUG_ERR_MSG("can not push to controller thread");
	}

	/* FIXME : should be removed when plugins would be fixed*/
	_net_nfc_util_free_mem(info);
}
