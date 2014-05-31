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


#include <vconf.h>
#include <glib.h>
#include <string.h>
#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_app_util_private.h"
#include "aul.h"



/////////////////////////////////////////////////////////////////////////

static void net_nfc_service_airplane_mode_cb(keynode_t* key, void* data)
{
	int flight_mode = 0;
	int nfc_state, sbeam_state, predefined_state = 0;
	static gboolean powered_off_by_flightmode = FALSE;
	int result;

	if ((result= vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &flight_mode)) == 0)
	{
		DEBUG_SERVER_MSG("vconf_get_bool success \n");
	}
	else
	{
		DEBUG_ERR_MSG("vconf_get_bool failed \n");
	}
	if ((result= vconf_get_bool(VCONFKEY_NFC_STATE, &nfc_state)) == 0)
	{
		DEBUG_SERVER_MSG("vconf_get_bool success \n");
	}
	else
	{
		DEBUG_ERR_MSG("vconf_get_bool failed \n");
	}
	if ((result= vconf_get_bool(VCONFKEY_NFC_SBEAM, &sbeam_state)) == 0)
	{
		DEBUG_SERVER_MSG("vconf_get_bool success \n");
	}
	else
	{
		DEBUG_ERR_MSG("vconf_get_bool failed \n");
	}
	if ((result= vconf_get_bool(VCONFKEY_NFC_PREDEFINED_ITEM_STATE, &predefined_state)) == 0)
	{
		DEBUG_SERVER_MSG("vconf_get_bool success \n");
	}
	else
	{
		DEBUG_ERR_MSG("vconf_get_bool failed \n");
	}

	DEBUG_SERVER_MSG("flight mode %s \n", flight_mode > 0 ? "ON" : "OFF");
	DEBUG_SERVER_MSG("nfc_state %d, sbeam_state %d, predefined_state %d NFC was off by flight mode %s \n",
			nfc_state, sbeam_state, predefined_state, powered_off_by_flightmode == TRUE ? "Yes" : "No");

	if (flight_mode > 0) /* turn flight mode on */
	{
		/* flight mode enabled */
		if (nfc_state == VCONFKEY_NFC_STATE_OFF)
			return;

		DEBUG_SERVER_MSG("Turning NFC off \n");

		/* nfc off */
		net_nfc_request_msg_t *req_msg = NULL;

		_net_nfc_util_alloc_mem(req_msg, sizeof(net_nfc_request_msg_t));
		if (req_msg == NULL)
			return;

		req_msg->length = sizeof(net_nfc_request_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_DEINIT;

		net_nfc_dispatcher_queue_push(req_msg);

		/* set internal flag */
		powered_off_by_flightmode = TRUE;

		/* sbeam off */
		if ((result = vconf_set_bool(VCONFKEY_NFC_SBEAM, FALSE)) == 0)
		{
			DEBUG_SERVER_MSG("vconf_set_bool success \n");
		}
		else
		{
			DEBUG_ERR_MSG("vconf_set_bool failed \n");
		}

		/* predefined item off */
		if ((result = vconf_set_bool(VCONFKEY_NFC_PREDEFINED_ITEM_STATE, FALSE)) == 0)
		{
			DEBUG_SERVER_MSG("vconf_set_bool success \n");
		}
		else
		{
			DEBUG_ERR_MSG("vconf_set_bool failed \n");
		}
	}
	else if (flight_mode == 0) /* turn flight mode off */
	{
		/* flight mode disabled */
		if (nfc_state > VCONFKEY_NFC_STATE_OFF)
			return;

		if (powered_off_by_flightmode != TRUE)
			return;

		DEBUG_SERVER_MSG("Turning NFC on \n");

		/* nfc on */
		net_nfc_request_msg_t *req_msg = NULL;

		_net_nfc_util_alloc_mem(req_msg, sizeof(net_nfc_request_msg_t));
		if (req_msg == NULL)
			return;

		req_msg->length = sizeof(net_nfc_request_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_INIT;

		net_nfc_dispatcher_queue_push(req_msg);

		/* unset internal flag */
		powered_off_by_flightmode = FALSE;

		/* sbeam on */
		if ((result = vconf_set_bool(VCONFKEY_NFC_SBEAM, TRUE)) == 0)
		{
			DEBUG_SERVER_MSG("vconf_set_bool success \n");
		}
		else
		{
			DEBUG_ERR_MSG("vconf_set_bool failed \n");
		}

		/* predefined item on */
		if ((result = vconf_set_bool(VCONFKEY_NFC_PREDEFINED_ITEM_STATE, TRUE)) == 0)
		{
			DEBUG_SERVER_MSG("vconf_set_bool success \n");
		}
		else
		{
			DEBUG_ERR_MSG("vconf_set_bool failed \n");
		}
	}
	else
	{
		DEBUG_SERVER_MSG("Invalid Vconf value \n");
	}
}



void net_nfc_service_vconf_register_notify_listener()
{
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE, net_nfc_service_airplane_mode_cb, NULL);
}

void net_nfc_service_vconf_unregister_notify_listener()
{
	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE, net_nfc_service_airplane_mode_cb);
}
