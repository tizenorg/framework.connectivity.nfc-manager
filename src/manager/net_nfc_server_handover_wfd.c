/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*for wifi-direct*/
#include <wifi-direct.h>

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_util_handover.h"
#include "net_nfc_server_handover_internal.h"
#include "net_nfc_server_llcp.h"

/*For Wifi-direct*/
#define Size_of_MAC_Address 18

typedef struct _net_nfc_handover_wfd_process_context_t
{
	bool already_on;
	net_nfc_error_e result;
	net_nfc_server_handover_process_carrier_cb cb;
	net_nfc_carrier_config_s *config;
	void *user_param;
	char *mac_address;
}
net_nfc_handover_wfd_process_context_t;

typedef struct _device_type_t
{
	uint16_t cat_id;
	uint32_t oui;
	uint16_t sub_cat_id;
}
__attribute__((packed)) device_type_t;

typedef struct _device_info_attr_t
{
	uint8_t address[6];
	uint16_t config_methods;
	device_type_t primary_device;
	uint16_t secondary_devices_num;
	device_type_t secondary_devices[0];
}
__attribute__((packed)) device_info_attr_t;

static void set_mac_address(char *data, uint8_t *origin_data)
{
	int i, len = 0;

	for (i = 0; i < 6; i++)
	{
		len += sprintf(data + len, "%02x", origin_data[i]);

		//DEBUG_SERVER_MSG("check temp [%s]", data);

		if (i != 5)
			len += sprintf(data + len, ":");
	}

	DEBUG_SERVER_MSG("check mac_address [%s]", data);
}

static bool _cb_discovered_peers(wifi_direct_discovered_peer_info_s *peer,
	void *user_data)
{
	net_nfc_handover_wfd_process_context_t *context =
		(net_nfc_handover_wfd_process_context_t *)user_data;
	bool result = true;

	if (peer->mac_address != NULL && context->mac_address != NULL)
	{
		DEBUG_SERVER_MSG("mac_address [%s]", context->mac_address);
		DEBUG_SERVER_MSG("peer->mac_address [%s]", peer->mac_address);

		/* Check mac address */
		if (strncasecmp(peer->mac_address, context->mac_address,
			strlen(context->mac_address)) == 0)
		{
			DEBUG_SERVER_MSG("wifi_direct_connect");
			wifi_direct_connect(context->mac_address);

			context->cb(context->result,
				NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P,
				NULL, context->user_param);

			g_free(context->mac_address);

			if (context->config != NULL)
			{
				net_nfc_util_free_carrier_config(context->config);
			}

			_net_nfc_util_free_mem(context);

			result = false; /* break iterate */
		}
		else
		{
			DEBUG_SERVER_MSG("I have to find other wifi direct");
		}
	}

	return result;
}

static void _cb_activation(int error_code,
	wifi_direct_device_state_e device_state, void *user_data)
{
	int result;

	DEBUG_SERVER_MSG("Call _cb_activation [%p]", user_data);

	switch (device_state)
	{
	case WIFI_DIRECT_DEVICE_STATE_ACTIVATED :
		{
			DEBUG_SERVER_MSG("event -WIFI_DIRECT_DEVICE_STATE_ACTIVATED");

			result = wifi_direct_start_discovery_specific_channel(
				FALSE, 0, WIFI_DIRECT_DISCOVERY_FULL_SCAN);
			if (WIFI_DIRECT_ERROR_NOT_PERMITTED == result)
			{
				DEBUG_SERVER_MSG("WIFI_DIRECT_ERROR_NOT_PERMITTED");

				result = wifi_direct_foreach_discovered_peers(
					_cb_discovered_peers, (void*)user_data);
			}
		}
		break;

	case WIFI_DIRECT_DEVICE_STATE_DEACTIVATED :
		{
			DEBUG_SERVER_MSG("event - WIFI_DIRECT_DEVICE_STATE_DEACTIVATED");
		}
		break;

	default:
		break;
	}
}

static void _cb_discovery(int error_code,
	wifi_direct_discovery_state_e discovery_state, void *user_data)
{
	int result;

	DEBUG_SERVER_MSG("Call _cb_discovery");

	switch (discovery_state)
	{
	case WIFI_DIRECT_DISCOVERY_STARTED :
		DEBUG_SERVER_MSG("event - WIFI_DIRECT_DISCOVERY_STARTED");
		break;

	case WIFI_DIRECT_DISCOVERY_FOUND :
		{
			DEBUG_SERVER_MSG("event - WIFI_DIRECT_DISCOVERY_FOUND");

			result = wifi_direct_foreach_discovered_peers(
				_cb_discovered_peers, (void*)user_data);

			DEBUG_SERVER_MSG("wifi_direct_foreach_discovered_peers() result=[0x%x]", result);
		}
		break;

	default:
		break;
	}
}

static int handover_wfd_init(net_nfc_handover_wfd_process_context_t *user_data)
{
	int result;

	DEBUG_SERVER_MSG("handover_wfd_init");

	result = wifi_direct_initialize();
	if (WIFI_DIRECT_ERROR_ALREADY_INITIALIZED == result)
	{
		DEBUG_SERVER_MSG("WIFI_DIRECT_ERROR_ALREADY_INITIALIZED!!");
		return NET_NFC_OK;
	}

	if (WIFI_DIRECT_ERROR_NONE != result)
	{
		DEBUG_SERVER_MSG("wifi_direct_initialize failed [0x%x]!!", result);
		return NET_NFC_UNKNOWN_ERROR;
	}

	/* set callback for active*/
	wifi_direct_set_device_state_changed_cb(_cb_activation, user_data);

	wifi_direct_set_discovery_state_changed_cb(_cb_discovery, user_data);

	/* wifi-direct initialize */
	result = wifi_direct_activate();

	DEBUG_SERVER_MSG("wifi_direct_activate");

	/*we need to check wifi state??*/
	//wifi_direct_set_connection_state_changed_cb(_cb_connection, ad);
	return NET_NFC_OK;
}

net_nfc_error_e _net_nfc_server_handover_wifi_direct_pairing(
	net_nfc_handover_wfd_process_context_t *context)
{
	net_nfc_error_e result = NET_NFC_OK;
	uint16_t len = 0;
	uint8_t *data = NULL;

	result = net_nfc_util_get_carrier_config_property(context->config,
		NET_NFC_WIFI_P2P_ATTRIBUTE_DEVICE_INFO, &len, &data);
	if (result == NET_NFC_OK) {
		device_info_attr_t *info = (device_info_attr_t *)data;

		context->mac_address = (char *)malloc(Size_of_MAC_Address * sizeof(char));
		if(context->mac_address == NULL)
			return NET_NFC_ALLOC_FAIL;

		set_mac_address(context->mac_address, info->address);

		DEBUG_SERVER_MSG("mac address= [%s]", context->mac_address);

		handover_wfd_init(context);
	} else {
		DEBUG_ERR_MSG("net_nfc_util_get_carrier_config_property failed, [%d]", result);
	}

	return result;
}

net_nfc_error_e net_nfc_server_handover_wfd_do_pairing(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_handover_wfd_process_context_t *context = NULL;

	INFO_MSG("Call this function for connecting wifi-direct");

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context != NULL)
	{
		context->cb = cb;
		context->user_param = user_param;

		result = net_nfc_util_create_carrier_config_from_config_record(
			&context->config, carrier->carrier_record);
		if (result == NET_NFC_OK) {
			g_idle_add((GSourceFunc)_net_nfc_server_handover_wifi_direct_pairing,
				(gpointer)context);
		} else {
			DEBUG_ERR_MSG("net_nfc_util_create_carrier_config_from_config_record failed, [%d]", result);

			_net_nfc_util_free_mem(context);
		}
	}
	else
	{
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
