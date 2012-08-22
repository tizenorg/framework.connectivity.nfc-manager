/*
  * Copyright 2012  Samsung Electronics Co., Ltd
  *
  * Licensed under the Flora License, Version 1.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://www.tizenopensource.org/license
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */


#include "net_nfc_controller_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_typedef.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_service_private.h"
#include "net_nfc_app_util_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_manager_util_private.h"

#include <pthread.h>
#include <malloc.h>

/* define */


/* static variable */


/* static callback function */


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void net_nfc_service_watch_dog(net_nfc_request_msg_t* req_msg)
{
	net_nfc_request_watch_dog_t *detail_msg = NULL;
	net_nfc_error_e result = NET_NFC_OK;
	bool isPresentTarget = true;

	if (req_msg == NULL)
	{
		return;
	}

	detail_msg = (net_nfc_request_watch_dog_t *)req_msg;

	//DEBUG_SERVER_MSG("connection type = [%d]", detail_msg->handle->connection_type);

	if ((detail_msg->handle->connection_type == NET_NFC_P2P_CONNECTION_TARGET) || (detail_msg->handle->connection_type == NET_NFC_TAG_CONNECTION))
	{
		isPresentTarget = net_nfc_controller_check_target_presence(detail_msg->handle, &result);
	}
	else
	{
		isPresentTarget = false;
	}

	if (isPresentTarget == true)
	{
		/* put message again */
		net_nfc_dispatcher_queue_push(req_msg);
	}
	else
	{
		//DEBUG_SERVER_MSG("try to disconnect target = [%d]", detail_msg->handle);

		if((NET_NFC_NOT_INITIALIZED != result) && (NET_NFC_INVALID_HANDLE != result))
		{
			if (net_nfc_controller_disconnect(detail_msg->handle, &result) == false)
			{

				DEBUG_SERVER_MSG("try to disconnect result = [%d]", result);
				net_nfc_controller_exception_handler();
			}
		}
#ifdef BROADCAST_MESSAGE
		net_nfc_server_set_server_state( NET_NFC_SERVER_IDLE);
#endif

		if (_net_nfc_check_client_handle())
		{
			int request_type = NET_NFC_MESSAGE_TAG_DETACHED;

			net_nfc_response_target_detached_t target_detached = { 0, };
			memset(&target_detached, 0x00, sizeof(net_nfc_response_target_detached_t));

			target_detached.devType = detail_msg->devType;
			target_detached.handle = detail_msg->handle;

			_net_nfc_send_response_msg(request_type, (void*)&target_detached, sizeof(net_nfc_response_target_detached_t), NULL);
		}

		_net_nfc_manager_util_free_mem(req_msg);

		net_nfc_dispatcher_cleanup_queue();
	}
}

void net_nfc_service_clean_tag_context(net_nfc_request_target_detected_t* stand_alone, net_nfc_error_e result)
{
	if(result == NET_NFC_OK)
	{
		bool isPresentTarget = true;
		net_nfc_error_e result = NET_NFC_OK;

		while(isPresentTarget)
		{
			isPresentTarget = net_nfc_controller_check_target_presence (stand_alone->handle, &result);
		}

		if (net_nfc_controller_disconnect (stand_alone->handle, &result) == false)
		{
			net_nfc_controller_exception_handler();
		}
	}
	else
	{

		net_nfc_error_e result = NET_NFC_OK;

		if(result != NET_NFC_TARGET_IS_MOVED_AWAY && result != NET_NFC_OPERATION_FAIL)
		{
			bool isPresentTarget = true;

			while(isPresentTarget)
			{
				isPresentTarget = net_nfc_controller_check_target_presence (stand_alone->handle, &result );
			}
		}

		DEBUG_SERVER_MSG("try to disconnect target = [%d]", stand_alone->handle->connection_id);

		if (net_nfc_controller_disconnect (stand_alone->handle, &result) == false)
		{
			net_nfc_controller_exception_handler();
		}
	}

#ifdef BROADCAST_MESSAGE
	net_nfc_server_set_server_state(	NET_NFC_SERVER_IDLE);
#endif

}


data_s* net_nfc_service_tag_process(net_nfc_target_handle_s* handle, int devType, net_nfc_error_e* result)
{
	net_nfc_error_e status = NET_NFC_OK;
	data_s* recv_data = NULL;
	*result = NET_NFC_OK;

	DEBUG_SERVER_MSG("trying to connect to tag = [0x%x]", handle);

	if (!net_nfc_controller_connect (handle, &status))
	{
		DEBUG_SERVER_MSG("connect failed");
		*result = status;
		return NULL;
	}

#ifdef BROADCAST_MESSAGE
	net_nfc_server_set_server_state(NET_NFC_TAG_CONNECTED);
#endif

	DEBUG_SERVER_MSG("read ndef from tag");

	if(net_nfc_controller_read_ndef (handle, &recv_data, &status) == true)
	{
		return recv_data;
	}
	else
	{
		DEBUG_SERVER_MSG("can not read card");
		*result = status;
		return NULL;
	}

}
