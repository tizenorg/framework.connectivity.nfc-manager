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

#include <pthread.h>
#include <glib.h>
#include <malloc.h>

#include "vconf.h"
#include "tapi_common.h"
#include "ITapiSim.h"

#include "net_nfc_controller_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_typedef.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_service_private.h"
#include "net_nfc_app_util_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_service_se_private.h"
#include "net_nfc_server_context_private.h"

/* define */

/* static variable */
static uint8_t g_se_prev_type = SECURE_ELEMENT_TYPE_INVALID;
static uint8_t g_se_prev_mode = SECURE_ELEMENT_OFF_MODE;

/* For ESE*/
static net_nfc_se_setting_t g_se_setting;

/* For UICC */
static struct tapi_handle *uicc_handle = NULL;
static bool net_nfc_service_check_sim_state(void);
static void _uicc_transmit_apdu_cb(TapiHandle *handle, int result, void *data, void *user_data);
static void _uicc_get_atr_cb(TapiHandle *handle, int result, void *data, void *user_data);
static void _uicc_status_noti_cb(TapiHandle *handle, const char *noti_id, void *data, void *user_data);

net_nfc_se_setting_t *net_nfc_service_se_get_se_setting()
{
	return &g_se_setting;
}

net_nfc_target_handle_s *net_nfc_service_se_get_current_ese_handle()
{
	return g_se_setting.current_ese_handle;
}

void net_nfc_service_se_set_current_ese_handle(net_nfc_target_handle_s *handle)
{
	g_se_setting.current_ese_handle = handle;
}

uint8_t net_nfc_service_se_get_se_type()
{
	return g_se_setting.type;
}

void net_nfc_service_se_set_se_type(uint8_t type)
{
	g_se_setting.return_type = g_se_setting.type;
	g_se_setting.type = type;
}

uint8_t net_nfc_service_se_get_return_se_mode()
{
    return g_se_setting.return_type;
}

uint8_t net_nfc_service_se_get_se_mode()
{
	return g_se_setting.mode;
}

void net_nfc_service_se_set_se_mode(uint8_t mode)
{
	g_se_setting.mode = mode;
}

net_nfc_error_e net_nfc_service_se_disable_card_emulation()
{
    net_nfc_error_e result;

    net_nfc_service_se_set_se_type(SECURE_ELEMENT_TYPE_INVALID);
    net_nfc_service_se_set_se_mode(SECURE_ELEMENT_OFF_MODE);

    /*turn off ESE*/
    net_nfc_controller_set_secure_element_mode(
        SECURE_ELEMENT_TYPE_ESE,
        SECURE_ELEMENT_OFF_MODE,
        &result);

    /*turn off UICC*/
    net_nfc_controller_set_secure_element_mode(
        SECURE_ELEMENT_TYPE_UICC,
        SECURE_ELEMENT_OFF_MODE,
        &result);

    return NET_NFC_OK;
}

net_nfc_error_e net_nfc_service_se_change_se(uint8_t type)
{
	net_nfc_error_e result = NET_NFC_OK;

	switch (type)
	{
	case SECURE_ELEMENT_TYPE_UICC :
		/*turn off ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE, SECURE_ELEMENT_OFF_MODE, &result);

		/*turn on UICC*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC, SECURE_ELEMENT_VIRTUAL_MODE, &result);
		if (result == NET_NFC_OK)
		{
			DEBUG_SERVER_MSG("changed to SECURE_ELEMENT_TYPE_UICC");

			net_nfc_service_se_set_se_type(SECURE_ELEMENT_TYPE_UICC);
			net_nfc_service_se_set_se_mode(SECURE_ELEMENT_VIRTUAL_MODE);

			if (vconf_set_int(VCONFKEY_NFC_SE_TYPE, VCONFKEY_NFC_SE_TYPE_UICC) != 0)
			{
				DEBUG_ERR_MSG("vconf_set_int failed");
			}
		}
		else
		{
			DEBUG_ERR_MSG("SECURE_ELEMENT_TYPE_UICC, SECURE_ELEMENT_VIRTUAL_MODE failed [%d]", result);
		}
		break;

	case SECURE_ELEMENT_TYPE_ESE :
		/*turn off UICC*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC, SECURE_ELEMENT_OFF_MODE, &result);

		/*turn on ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE, SECURE_ELEMENT_VIRTUAL_MODE, &result);
		if (result == NET_NFC_OK)
		{
			DEBUG_SERVER_MSG("changed to SECURE_ELEMENT_TYPE_ESE");

			net_nfc_service_se_set_se_type(SECURE_ELEMENT_TYPE_ESE);
			net_nfc_service_se_set_se_mode(SECURE_ELEMENT_VIRTUAL_MODE);

			if (vconf_set_int(VCONFKEY_NFC_SE_TYPE, VCONFKEY_NFC_SE_TYPE_ESE) != 0)
			{
				DEBUG_ERR_MSG("vconf_set_int failed");
			}
		}
		else
		{
			DEBUG_ERR_MSG("SECURE_ELEMENT_TYPE_ESE, SECURE_ELEMENT_VIRTUAL_MODE failed [%d]", result);
		}
		break;

	default :
		{
			net_nfc_error_e result_ese, result_uicc;

			net_nfc_service_se_set_se_type(SECURE_ELEMENT_TYPE_INVALID);
			net_nfc_service_se_set_se_mode(SECURE_ELEMENT_OFF_MODE);

			/*turn off ESE*/
			net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE, SECURE_ELEMENT_OFF_MODE, &result_ese);

			/*turn off UICC*/
			net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC, SECURE_ELEMENT_OFF_MODE, &result_uicc);
			if (result_ese != NET_NFC_INVALID_HANDLE && result_uicc != NET_NFC_INVALID_HANDLE)
			{
				DEBUG_SERVER_MSG("SE off all");
				if (vconf_set_int(VCONFKEY_NFC_SE_TYPE, VCONFKEY_NFC_SE_TYPE_NONE) != 0)
				{
					DEBUG_ERR_MSG("vconf_set_int failed");
				}
				result = NET_NFC_OK;
			}
			else
			{
				DEBUG_ERR_MSG("ALL OFF failed, ese [%d], uicc [%d]", result_ese, result_uicc);
				result = NET_NFC_INVALID_HANDLE;
			}
		}
		break;
	}

	return result;
}

void net_nfc_service_se_detected(net_nfc_request_msg_t *msg)
{
	net_nfc_request_target_detected_t *detail_msg = (net_nfc_request_target_detected_t *)(msg);
	net_nfc_target_handle_s *handle = NULL;
	net_nfc_error_e state = NET_NFC_OK;
	net_nfc_response_open_internal_se_t resp = { 0 };

	if (detail_msg == NULL)
	{
		return;
	}

	handle = detail_msg->handle;
	g_se_setting.current_ese_handle = handle;

	DEBUG_SERVER_MSG("trying to connect to ESE = [0x%p]", handle);

	if (!net_nfc_controller_connect(handle, &state))
	{
		DEBUG_SERVER_MSG("connect failed = [%d]", state);
		resp.result = state;
	}

#ifdef BROADCAST_MESSAGE
	net_nfc_server_set_server_state(NET_NFC_SE_CONNECTED);
#endif

	resp.handle = handle;
	resp.trans_param = g_se_setting.open_request_trans_param;
	resp.se_type = SECURE_ELEMENT_TYPE_ESE;

	DEBUG_SERVER_MSG("trans param = [%p]", resp.trans_param);

	net_nfc_send_response_msg(detail_msg->client_fd, NET_NFC_MESSAGE_OPEN_INTERNAL_SE,
		&resp, sizeof(net_nfc_response_open_internal_se_t), NULL);

	g_se_setting.open_request_trans_param = NULL;
}

net_nfc_error_e net_nfc_service_se_close_ese()
{
	net_nfc_error_e result = NET_NFC_OK;

	if (g_se_setting.current_ese_handle != NULL)
	{
		if (net_nfc_controller_secure_element_close(g_se_setting.current_ese_handle, &result) == false)
		{
			net_nfc_controller_exception_handler();
		}
		net_nfc_service_se_set_current_ese_handle(NULL);
	}

	return result;
}

bool net_nfc_service_tapi_init(void)
{
	char **cpList = NULL;

	DEBUG_SERVER_MSG("tapi init");

	cpList = tel_get_cp_name_list();

	uicc_handle = tel_init(cpList[0]);
	if (uicc_handle == NULL)
	{
		int error;

		error = tel_register_noti_event(uicc_handle, TAPI_NOTI_SIM_STATUS, _uicc_status_noti_cb, NULL);
	}
	else
	{
		DEBUG_SERVER_MSG("tel_init() failed");
		return false;
	}

	DEBUG_SERVER_MSG("tel_init() is success");

	return net_nfc_service_check_sim_state();
}

void net_nfc_service_tapi_deinit(void)
{
	DEBUG_SERVER_MSG("deinit tapi");

	tel_deregister_noti_event(uicc_handle, TAPI_NOTI_SIM_STATUS);

	tel_deinit(uicc_handle);
}

bool net_nfc_service_transfer_apdu(int client_fd, data_s *apdu, void *trans_param)
{
	net_nfc_request_msg_t *param = NULL;
	TelSimApdu_t apdu_data = { 0 };
	int result;

	DEBUG_SERVER_MSG("tranfer apdu");

	if (apdu == NULL)
		return false;

	apdu_data.apdu = apdu->buffer;
	apdu_data.apdu_len = apdu->length;

	/* make param */
	_net_nfc_util_alloc_mem(param, sizeof(net_nfc_request_msg_t));
	if (param != NULL)
	{
		param->client_fd = client_fd;
		param->user_param = (uint32_t)trans_param;

		result = tel_req_sim_apdu(uicc_handle, &apdu_data, _uicc_transmit_apdu_cb, param);
		if (result == 0)
		{
			DEBUG_SERVER_MSG("sim apdu request is success");
		}
		else
		{
			DEBUG_ERR_MSG("request sim apdu is failed with error = [%d]", result);
			return false;
		}
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
		return false;
	}

	return true;
}

bool net_nfc_service_request_atr(int client_fd, void *trans_param)
{
	int result;
	net_nfc_request_msg_t *param = NULL;

	/* make param */
	_net_nfc_util_alloc_mem(param, sizeof(net_nfc_request_msg_t));
	if (param != NULL)
	{
		param->client_fd = client_fd;
		param->user_param = (uint32_t)trans_param;

		result = tel_req_sim_atr(uicc_handle, _uicc_get_atr_cb, param);
		if (result == 0)
		{
			DEBUG_SERVER_MSG("request is success");
		}
		else
		{
			DEBUG_SERVER_MSG("failed to request ATR  = [%d]", result);
			return false;
		}
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_manager_util_alloc_mem failed");
		return false;
	}

	return true;
}

static bool net_nfc_service_check_sim_state(void)
{
	TelSimCardStatus_t state = (TelSimCardStatus_t)0;
	int b_card_changed = 0;
	int error;

	DEBUG_SERVER_MSG("check sim state");

	error = tel_get_sim_init_info(uicc_handle, &state, &b_card_changed);

	DEBUG_SERVER_MSG("current sim init state = [%d]", state);

	if (error != 0)
	{
		DEBUG_SERVER_MSG("error = [%d]", error);
		return false;
	}
	else if (state == TAPI_SIM_STATUS_SIM_INIT_COMPLETED || state == TAPI_SIM_STATUS_SIM_INITIALIZING)
	{
		DEBUG_SERVER_MSG("sim is initialized");
	}
	else
	{
		DEBUG_SERVER_MSG("sim is not initialized");
		return false;
	}

	return true;
}

void _uicc_transmit_apdu_cb(TapiHandle *handle, int result, void *data, void *user_data)
{
	TelSimApduResp_t *apdu = (TelSimApduResp_t *)data;
	net_nfc_response_send_apdu_t resp = { 0 };
	net_nfc_request_msg_t *param = (net_nfc_request_msg_t *)user_data;

	DEBUG_SERVER_MSG("_uicc_transmit_apdu_cb");

	if (result == 0)
	{
		resp.result = NET_NFC_OK;
	}
	else
	{
		resp.result = NET_NFC_OPERATION_FAIL;
	}

	resp.trans_param = (void *)param->user_param;

	if (apdu != NULL && apdu->apdu_resp_len > 0)
	{
		resp.data.length = apdu->apdu_resp_len;

		DEBUG_MSG("send response send apdu msg");
		net_nfc_send_response_msg(param->client_fd, NET_NFC_MESSAGE_SEND_APDU_SE,
			(void *)&resp, sizeof(net_nfc_response_send_apdu_t), apdu->apdu_resp, apdu->apdu_resp_len, NULL);
	}
	else
	{
		DEBUG_MSG("send response send apdu msg");
		net_nfc_send_response_msg(param->client_fd, NET_NFC_MESSAGE_SEND_APDU_SE,
			(void *)&resp, sizeof(net_nfc_response_send_apdu_t), NULL);
	}

	_net_nfc_util_free_mem(param);
}

void _uicc_get_atr_cb(TapiHandle *handle, int result, void *data, void *user_data)
{
	net_nfc_request_msg_t *param = (net_nfc_request_msg_t *)user_data;

	/* TODO : response message */

	DEBUG_SERVER_MSG("_uicc_get_atr_cb");

	_net_nfc_util_free_mem(param);
}

void _uicc_status_noti_cb(TapiHandle *handle, const char *noti_id, void *data, void *user_data)
{
	TelSimCardStatus_t *status = (TelSimCardStatus_t *)data;

	/* TODO :  */
	DEBUG_SERVER_MSG("_uicc_status_noti_cb");

	switch (*status)
	{
	case TAPI_SIM_STATUS_SIM_INIT_COMPLETED :
		DEBUG_SERVER_MSG("TAPI_SIM_STATUS_SIM_INIT_COMPLETED");
		break;

	case TAPI_SIM_STATUS_CARD_REMOVED :
		DEBUG_SERVER_MSG("TAPI_SIM_STATUS_CARD_REMOVED");
		break;

	default :
		DEBUG_SERVER_MSG("unknown status [%d]", *status);
		break;
	}
}

bool net_nfc_service_se_transaction_receive(net_nfc_request_msg_t* msg)
{
	bool res = true;
	bool fg_dispatch;
	pid_t focus_app_pid;
	net_nfc_secure_element_type_e se_type;
	net_nfc_request_se_event_t *se_event = (net_nfc_request_se_event_t *)msg;

	if (se_event->request_type == NET_NFC_MESSAGE_SE_START_TRANSACTION)
	{
		DEBUG_SERVER_MSG("launch se app");

		se_type = net_nfc_service_se_get_se_type();
		fg_dispatch = net_nfc_app_util_check_launch_state();
		focus_app_pid = net_nfc_app_util_get_focus_app_pid();

		res = net_nfc_app_util_launch_se_transaction_app(se_type, se_event->aid.buffer,
			se_event->aid.length, se_event->param.buffer, se_event->param.length);

		DEBUG_SERVER_MSG("launch se app end");

		if (net_nfc_server_check_client_is_running(msg->client_fd))
		{
			net_nfc_response_se_event_t resp = { 0 };

			resp.length = sizeof(net_nfc_response_se_event_t);
			resp.flags = se_event->flags;
			resp.result = res;
			resp.aid = se_event->aid;
			resp.param = se_event->param;
			resp.fg_dispatch = fg_dispatch;
			resp.focus_app_pid = focus_app_pid;
			resp.se_type = se_type;

			net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_SE_START_TRANSACTION,
				(void *)&resp, sizeof(net_nfc_response_se_event_t), NULL);
		}
	}

	return res;
}

void net_nfc_service_se_send_apdu(net_nfc_request_msg_t *msg)
{
	net_nfc_request_send_apdu_t *detail = (net_nfc_request_send_apdu_t *)msg;

	if (detail->handle == (net_nfc_target_handle_s *)UICC_TARGET_HANDLE)
	{
		data_s apdu_data = { NULL, 0 };

		if (net_nfc_util_duplicate_data(&apdu_data, &detail->data) == false)
			return;

		net_nfc_service_transfer_apdu(msg->client_fd, &apdu_data, detail->trans_param);

		net_nfc_util_free_data(&apdu_data);
	}
	else if (detail->handle == net_nfc_service_se_get_current_ese_handle())
	{
		bool success;
		data_s command;
		data_s *response = NULL;
		net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;

		if (net_nfc_util_duplicate_data(&command, &detail->data) == false)
		{
			DEBUG_ERR_MSG("alloc failed");
			return;
		}

		if ((success = net_nfc_controller_secure_element_send_apdu(detail->handle, &command, &response, &result)) == true)
		{
			if (response != NULL)
			{
				DEBUG_SERVER_MSG("transceive data received, len [%d]", response->length);
			}
		}
		else
		{
			DEBUG_ERR_MSG("transceive failed = [%d]", result);
		}
		net_nfc_util_free_data(&command);

		if (net_nfc_server_check_client_is_running(msg->client_fd))
		{
			net_nfc_response_send_apdu_t resp = { 0, };

			DEBUG_SERVER_MSG("send response send_apdu");

			resp.length = sizeof(net_nfc_response_send_apdu_t);
			resp.flags = detail->flags;
			resp.user_param = detail->user_param;
			resp.trans_param = detail->trans_param;
			resp.result = result;

			if (response != NULL)
			{
				resp.data.length = response->length;
				net_nfc_send_response_msg(msg->client_fd, msg->request_type,
					(void *)&resp, sizeof(net_nfc_response_send_apdu_t),
					response->buffer, response->length, NULL);
			}
			else
			{
				net_nfc_send_response_msg(msg->client_fd, msg->request_type,
					(void *)&resp, sizeof(net_nfc_response_send_apdu_t), NULL);
			}
		}
	}
	else
	{
		DEBUG_SERVER_MSG("invalid se handle");

		if (net_nfc_server_check_client_is_running(msg->client_fd))
		{
			net_nfc_response_send_apdu_t resp = { 0 };

			resp.length = sizeof(net_nfc_response_send_apdu_t);
			resp.flags = detail->flags;
			resp.trans_param = detail->trans_param;
			resp.result = NET_NFC_INVALID_PARAM;

			net_nfc_send_response_msg(msg->client_fd, msg->request_type,
				(void *)&resp, sizeof(net_nfc_response_send_apdu_t), NULL);
		}
	}
}

void net_nfc_service_se_get_atr(net_nfc_request_msg_t *msg)
{
	net_nfc_request_get_atr_t *detail = (net_nfc_request_get_atr_t *)msg;

	if (detail->handle == (net_nfc_target_handle_s *)UICC_TARGET_HANDLE)
	{
		net_nfc_service_request_atr(msg->client_fd, (void *)detail->user_param);
	}
	else if (detail->handle == net_nfc_service_se_get_current_ese_handle())
	{
		net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;

		if (net_nfc_server_check_client_is_running(msg->client_fd))
		{
			net_nfc_response_get_atr_t resp = { 0, };

			resp.length = sizeof(net_nfc_response_get_atr_t);
			resp.flags = detail->flags;
			resp.user_param = detail->user_param;
			resp.result = result;

			DEBUG_SERVER_MSG("send response send apdu msg");
			net_nfc_send_response_msg(msg->client_fd, msg->request_type,
				(void *)&resp, sizeof(net_nfc_response_get_atr_t), NULL);
		}
	}
	else
	{
		DEBUG_SERVER_MSG("invalid se handle");

		if (net_nfc_server_check_client_is_running(msg->client_fd))
		{
			net_nfc_response_get_atr_t resp = { 0 };

			resp.length = sizeof(net_nfc_response_get_atr_t);
			resp.flags = detail->flags;
			resp.user_param = detail->user_param;
			resp.result = NET_NFC_INVALID_PARAM;

			net_nfc_send_response_msg(msg->client_fd, msg->request_type,
				(void *)&resp, sizeof(net_nfc_response_get_atr_t), NULL);
		}
	}
}

void net_nfc_service_se_close_se(net_nfc_request_msg_t *msg)
{
	net_nfc_request_close_internal_se_t *detail = (net_nfc_request_close_internal_se_t *)msg;
	net_nfc_error_e result = NET_NFC_OK;

	if (detail->handle == (net_nfc_target_handle_s *)UICC_TARGET_HANDLE)
	{
		/*deinit TAPI*/
		DEBUG_SERVER_MSG("UICC is current secure element");
		net_nfc_service_tapi_deinit();

	}
	else if (detail->handle == net_nfc_service_se_get_current_ese_handle())
	{
		result = net_nfc_service_se_close_ese();
#ifdef BROADCAST_MESSAGE
		net_nfc_server_unset_server_state(NET_NFC_SE_CONNECTED);
#endif
	}
	else
	{
		DEBUG_ERR_MSG("invalid se handle received handle = [0x%p] and current handle = [0x%p]",
			detail->handle, net_nfc_service_se_get_current_ese_handle());
	}

	if ((g_se_prev_type != net_nfc_service_se_get_se_type()) || (g_se_prev_mode != net_nfc_service_se_get_se_mode()))
	{
		/*return back se mode*/
		net_nfc_controller_set_secure_element_mode(g_se_prev_type, g_se_prev_mode, &result);

		net_nfc_service_se_set_se_type(g_se_prev_type);
		net_nfc_service_se_set_se_mode(g_se_prev_mode);
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_close_internal_se_t resp = { 0 };

		resp.length = sizeof(net_nfc_response_close_internal_se_t);
		resp.flags = detail->flags;
		resp.trans_param = detail->trans_param;
		resp.result = result;

		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_close_internal_se_t), NULL);
	}

}

void net_nfc_service_se_open_se(net_nfc_request_msg_t *msg)
{
	net_nfc_request_open_internal_se_t *detail = (net_nfc_request_open_internal_se_t *)msg;
	net_nfc_target_handle_s *handle = NULL;
	net_nfc_error_e result = NET_NFC_OK;

	g_se_prev_type = net_nfc_service_se_get_se_type();
	g_se_prev_mode = net_nfc_service_se_get_se_mode();

	if (detail->se_type == SECURE_ELEMENT_TYPE_UICC)
	{
		/*off ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE, SECURE_ELEMENT_OFF_MODE, &result);

		/*Off UICC. UICC SHOULD not be detected by external reader when being communicated in internal process*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC, SECURE_ELEMENT_OFF_MODE, &result);

		net_nfc_service_se_set_se_type(SECURE_ELEMENT_TYPE_UICC);
		net_nfc_service_se_set_se_mode(SECURE_ELEMENT_OFF_MODE);

		/*Init tapi api and return back response*/
		if (net_nfc_service_tapi_init() != true)
		{
			net_nfc_service_tapi_deinit();
			result = NET_NFC_INVALID_STATE;
			handle = NULL;
		}
		else
		{
			result = NET_NFC_OK;
			handle = (net_nfc_target_handle_s *)UICC_TARGET_HANDLE;
		}
	}
	else if (detail->se_type == SECURE_ELEMENT_TYPE_ESE)
	{
		/*off UICC*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC, SECURE_ELEMENT_OFF_MODE, &result);

		if (net_nfc_controller_secure_element_open(SECURE_ELEMENT_TYPE_ESE, &handle, &result) == true)
		{
			net_nfc_service_se_set_se_type(SECURE_ELEMENT_TYPE_ESE);
			net_nfc_service_se_set_se_mode(SECURE_ELEMENT_WIRED_MODE);

			net_nfc_service_se_get_se_setting()->open_request_trans_param = detail->trans_param;
			net_nfc_service_se_set_current_ese_handle(handle);

			DEBUG_ERR_MSG("handle [%p]", handle);
		}
		else
		{
			DEBUG_ERR_MSG("net_nfc_controller_secure_element_open failed [%d]", result);
		}
	}
	else
	{
		result = NET_NFC_INVALID_STATE;
		handle = NULL;
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_open_internal_se_t resp = { 0 };

		resp.length = sizeof(net_nfc_response_open_internal_se_t);
		resp.flags = detail->flags;
		resp.user_param = detail->user_param;
		resp.trans_param = detail->trans_param;
		resp.result = result;
		resp.se_type = detail->se_type;
		resp.handle = handle;

		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_open_internal_se_t), NULL);
	}
}

void net_nfc_service_se_change_card_emulation_mode(net_nfc_request_msg_t *msg)
{
   bool isModeChange = false;
   uint8_t current_mode, return_mode;
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_request_se_change_card_emulation_t *detail
		= (net_nfc_request_se_change_card_emulation_t *)msg;

	current_mode = net_nfc_service_se_get_se_mode();

	if(detail->se_mode == SECURE_ELEMENT_ACTIVE_STATE
			&& current_mode == SECURE_ELEMENT_TYPE_INVALID)
	{
		return_mode = net_nfc_service_se_get_return_se_mode();
		result = net_nfc_service_se_change_se(return_mode);
		isModeChange = true;
	}
	else if(detail->se_mode == SECURE_ELEMENT_INACTIVE_STATE
			&& current_mode != SECURE_ELEMENT_TYPE_INVALID)
	{
		result = net_nfc_service_se_disable_card_emulation();
		isModeChange = true;
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_se_change_card_emulation_t resp = { 0 };

		resp.length = sizeof(net_nfc_response_se_change_card_emulation_t);
		resp.flags = detail->flags;
		resp.user_param = detail->user_param;
		resp.trans_param = detail->trans_param;
		resp.result = result;
		resp.se_mode = detail->se_mode;

		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_se_change_card_emulation_t), NULL);
	}

	if(isModeChange)
	{
		net_nfc_response_notify_t noti_se = { 0, };

		net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED,
			(void *)&noti_se, sizeof(net_nfc_response_notify_t), NULL);
	}
}

void net_nfc_service_se_set_se(net_nfc_request_msg_t *msg)
{
#if 1
	net_nfc_request_set_se_t *detail = (net_nfc_request_set_se_t *)msg;
	net_nfc_error_e result = NET_NFC_OK;
	bool isTypeChange = false;

	if (detail->se_type != net_nfc_service_se_get_se_type())
	{
		result = net_nfc_service_se_change_se(detail->se_type);
		isTypeChange = true;
	}

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_set_se_t resp = { 0 };

		resp.length = sizeof(net_nfc_response_set_se_t);
		resp.flags = detail->flags;
		resp.trans_param = detail->trans_param;
		resp.se_type = detail->se_type;
		resp.result = result;

		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_set_se_t), NULL);
	}

	if (isTypeChange)
	{
		net_nfc_response_notify_t noti_se = { 0, };

		net_nfc_broadcast_response_msg(NET_NFC_MESSAGE_SE_TYPE_CHANGED,
			(void *)&noti_se, sizeof(net_nfc_response_notify_t), NULL);
	}

#else
	net_nfc_request_set_se_t *detail = (net_nfc_request_set_se_t *)msg;
	net_nfc_error_e result = NET_NFC_OK;
	int mode;

	mode = (int)detail->se_type;

	if (mode == NET_NFC_SE_CMD_UICC_ON)
	{
		/*turn on UICC*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_VIRTUAL_MODE, &result);

		/*turn off ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_OFF_MODE, &result);
	}
	else if (mode == NET_NFC_SE_CMD_ESE_ON)
	{
		/*turn off UICC*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_OFF_MODE, &result);

		/*turn on ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_VIRTUAL_MODE, &result);
	}
	else if (mode == NET_NFC_SE_CMD_ALL_OFF)
	{
		/*turn off both*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_OFF_MODE, &result);

		/*turn on ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_OFF_MODE, &result);
	}
	else
	{
		/*turn off both*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_UICC,
			SECURE_ELEMENT_VIRTUAL_MODE, &result);

		/*turn on ESE*/
		net_nfc_controller_set_secure_element_mode(SECURE_ELEMENT_TYPE_ESE,
			SECURE_ELEMENT_VIRTUAL_MODE, &result);
	}
#endif
}

void net_nfc_service_se_get_se(net_nfc_request_msg_t *msg)
{
	net_nfc_request_get_se_t *detail = (net_nfc_request_get_se_t *)msg;

	if (net_nfc_server_check_client_is_running(msg->client_fd))
	{
		net_nfc_response_get_se_t resp = { 0 };

		resp.length = sizeof(net_nfc_request_get_se_t);
		resp.flags = detail->flags;
		resp.trans_param = detail->trans_param;
		resp.result = NET_NFC_OK;
		resp.se_type = net_nfc_service_se_get_se_type();

		net_nfc_send_response_msg(msg->client_fd, msg->request_type,
			(void *)&resp, sizeof(net_nfc_response_get_se_t), NULL);
	}
}

void net_nfc_service_se_cleanup()
{
	DEBUG_SERVER_MSG("client is terminated abnormally");

	if (g_se_prev_type == SECURE_ELEMENT_TYPE_ESE)
	{
		net_nfc_error_e result = NET_NFC_OK;
		net_nfc_target_handle_s *ese_handle = net_nfc_service_se_get_current_ese_handle();

		if (ese_handle != NULL)
		{
			DEBUG_SERVER_MSG("ese_handle was not freed and disconnected");

			net_nfc_service_se_close_ese();
#ifdef BROADCAST_MESSAGE
			net_nfc_server_set_server_state(NET_NFC_SERVER_IDLE);
#endif
		}

		if ((g_se_prev_type != net_nfc_service_se_get_se_type()) || (g_se_prev_mode != net_nfc_service_se_get_se_mode()))
		{
			net_nfc_controller_set_secure_element_mode(g_se_prev_type, g_se_prev_mode, &result);

			net_nfc_service_se_set_se_type(g_se_prev_type);
			net_nfc_service_se_set_se_mode(g_se_prev_mode);
		}
	}
	else if (g_se_prev_type == SECURE_ELEMENT_TYPE_UICC)
	{
		net_nfc_service_tapi_deinit();
	}
	else
	{
		DEBUG_SERVER_MSG("SE type is not valid");
	}
}
