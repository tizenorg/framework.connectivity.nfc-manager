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

#include "net_nfc_test_util.h"
#include "net_nfc_client_llcp.h"
#include "net_nfc_test_llcp.h"
#include "net_nfc_data.h"
#include "net_nfc_target_info.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_util_internal.h"


static net_nfc_llcp_socket_t server_test_socket;
static net_nfc_llcp_socket_t client_test_socket;

static net_nfc_llcp_config_info_h llcp_config = NULL;
static net_nfc_llcp_config_info_h llcp_config_sync = NULL;
static net_nfc_llcp_config_info_h llcp_config_default = NULL;
static net_nfc_llcp_config_info_h llcp_config_default_sync = NULL;


/*********************************** utility Calls *************************************/

static void run_next_callback(gpointer user_data);

static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);
		callback();
	}
}

/*********************************** Callbacks *************************************/

static void llcp_default_config_cb(net_nfc_error_e result,
		void *user_data)
{
	g_print(" llcp_default_config_cb Completed %d\n", result);

	run_next_callback(user_data);
}

static void llcp_custom_config_cb(net_nfc_error_e result,
		void *user_data)
{
	g_print("llcp_custom_config_cb Completed %d\n", result);

	run_next_callback(user_data);
}

static void llcp_listen_socket_cb(net_nfc_error_e result,
				net_nfc_llcp_socket_t client_socket,
				void *user_data)
{

	g_print("llcp_listen_socket_cb  Completed %d\n", client_socket);
	g_print("llcp_listen_socket_cb  Completed %d\n", result);

	run_next_callback(user_data);
}

static void llcp_receive_socket_cb(net_nfc_error_e result,
				data_h data,
				void *user_data)
{
	data_h received_data = data;

	print_received_data(received_data);

	g_print("llcp_listen_socket_cb	Completed %d\n", result);

	run_next_callback(user_data);
}

static void llcp_receive_from_socket_cb(net_nfc_error_e result,
						sap_t sap,
						data_h data,
						void *user_data)
{
	data_h received_data = data;

	print_received_data(received_data);

	g_print("llcp_receive_from_socket_cb	Completed %d\n", sap);

	g_print("llcp_receive_from_socket_cb	Completed %d\n", result);

	run_next_callback(user_data);
}


static void llcp_connect_socket_cb(net_nfc_error_e result,
				net_nfc_llcp_socket_t client_socket,
				void *user_data)
{
	g_print("llcp_connect_socket_cb	Completed %d\n", client_socket);
	g_print("llcp_connect_socket_cb	Completed %d\n", result);

	run_next_callback(user_data);
}


static void llcp_connect_sap_cb(net_nfc_error_e result,
				net_nfc_llcp_socket_t client_socket,
				void *user_data)
{
	g_print("llcp_connect_socket_cb Completed %d\n", client_socket);
	g_print("llcp_connect_socket_cb Completed %d\n", result);

	run_next_callback(user_data);
}


static void llcp_send_socket_cb(net_nfc_error_e result,
				void *user_data)
{
	g_print("llcp_send_socket_cb	Completed %d\n", result);

	run_next_callback(user_data);

}

static void llcp_send_to_socket_cb(net_nfc_error_e result,
				void *user_data)
{
	g_print("llcp_send_to_socket_cb Completed %d\n", result);

	run_next_callback(user_data);

}

static void llcp_disconnect_socket_cb(net_nfc_error_e result,
				void *user_data)
{
	g_print("llcp_send_to_socket_cb Completed %d\n", result);

	run_next_callback(user_data);

}


/*********************************** Function Calls *************************************/

void net_nfc_test_llcp_default_config(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_llcp_create_config_default(&llcp_config_default);

	if(result != NET_NFC_OK)
	{
		g_print(" llcp create default config failed: %d\n", result);
		run_next_callback(user_data);
		return;

	}
	result = net_nfc_client_llcp_config(llcp_config_default,
					llcp_default_config_cb,
					user_data);

}

void net_nfc_test_llcp_default_config_sync(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_llcp_create_config_default(&llcp_config_default_sync);

	if(result != NET_NFC_OK)
	{
		g_print(" llcp create default config failed: %d\n", result);
		run_next_callback(user_data);
		return;

	}

	result = net_nfc_client_llcp_config_sync(llcp_config_default_sync);
	if(result == NET_NFC_OK)
	{
		g_print(" llcp create default config (sync) success: %d\n", result);
	}

}


void net_nfc_test_llcp_custom_config(gpointer data,
			gpointer user_data)
{

	net_nfc_error_e result;

	result = net_nfc_client_llcp_create_config(&llcp_config,128, 1, 10, 0);

	if(result != NET_NFC_OK)
	{
		g_print(" llcp create custom config failed: %d\n", result);
		run_next_callback(user_data);
		return;

	}
	result = net_nfc_client_llcp_config(llcp_config,
					llcp_custom_config_cb,
					user_data);

}



void net_nfc_test_llcp_custom_config_sync(gpointer data,
			gpointer user_data)
{

	net_nfc_error_e result;

	result = net_nfc_client_llcp_create_config(&llcp_config_sync,128, 1, 10, 0);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_custom_config_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;

	}
	result = net_nfc_client_llcp_config_sync(llcp_config_sync);

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_custom_config_sync (sync) success: %d\n", result);
	}

}

void net_nfc_test_llcp_get_local_config(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_config_info_h local_config;
	net_nfc_error_e result;

	result = net_nfc_client_llcp_get_local_config(&local_config);

	if(result != NET_NFC_OK)
	{
		g_print(" llcp create custom config failed: %d\n", result);
		run_next_callback(user_data);
		return;

	}

	g_print(" net_nfc_test_llcp_get_local_config: %d\n", local_config->miu);
	g_print("net_nfc_test_llcp_get_local_config: %d\n", local_config->wks);
	g_print(" net_nfc_test_llcp_get_local_config: %d\n", local_config->lto);
	g_print("net_nfc_test_llcp_get_local_config: %d\n", local_config->option);

}


/*commented because remote config API is not available*/
/*
void net_nfc_test_llcp_get_remote_config(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_config_info_h local_config;
	net_nfc_error_e result;

	result = net_nfc_client_llcp_get_local_config(&local_config);

	if(result != NET_NFC_OK)
	{
		g_print(" llcp create custom config failed: %d\n", result);
		run_next_callback(user_data);
		return;

	}

	g_print(" net_nfc_test_llcp_get_local_config: %d\n", local_config->miu);
	g_print("net_nfc_test_llcp_get_local_config: %d\n", local_config->wks);
	g_print(" net_nfc_test_llcp_get_local_config: %d\n", local_config->lto);
	g_print("net_nfc_test_llcp_get_local_config: %d\n", local_config->option);

}
*/

void net_nfc_test_llcp_get_config_miu(gpointer data,
			gpointer user_data)
{

	net_nfc_error_e result;
	uint16_t miu;

	result = net_nfc_client_llcp_get_config_miu(llcp_config,&miu);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_miu failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_miu ->: %d\n", miu);
	}

	run_next_callback(user_data);

}


void net_nfc_test_llcp_get_config_wks(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	uint16_t wks;

	result = net_nfc_client_llcp_get_config_wks(llcp_config,&wks);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_wks failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_wks -> %d\n",wks);
	}

	run_next_callback(user_data);
}

void net_nfc_test_llcp_get_config_lto(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	uint8_t lto;

	result = net_nfc_client_llcp_get_config_lto(llcp_config,&lto);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_client_llcp_get_config_lto failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_client_llcp_get_config_lto -> %d\n",lto);
	}

	run_next_callback(user_data);

}


void net_nfc_test_llcp_get_config_option(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	uint8_t option;

	result = net_nfc_client_llcp_get_config_option(llcp_config,&option);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_option failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_option -> %d\n",option);
	}

	run_next_callback(user_data);

}


void net_nfc_test_llcp_set_config_miu(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	uint16_t miu = 128;

	result = net_nfc_client_llcp_set_config_miu(llcp_config,miu);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_config_miu failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_miu successfull \n");
	}

	run_next_callback(user_data);

}


void net_nfc_test_llcp_set_config_wks(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	uint16_t wks = 1;

	result = net_nfc_client_llcp_set_config_wks(llcp_config,wks);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_wks failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_wks successfull \n");
	}

	run_next_callback(user_data);

}


void net_nfc_test_llcp_set_config_lto(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	uint16_t lto = 10;

	result = net_nfc_client_llcp_set_config_lto(llcp_config,lto);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_lto failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_lto successfull \n");
	}
	run_next_callback(user_data);

}


void net_nfc_test_llcp_set_config_option(gpointer data,
			gpointer user_data)
{

	net_nfc_error_e result;
	uint8_t option = 0;

	result = net_nfc_client_llcp_set_config_lto(llcp_config,option);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_option failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_config_option successfull \n");
	}
	run_next_callback(user_data);
}


void net_nfc_test_llcp_free_config(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_llcp_free_config(llcp_config);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_free_config failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	if(result == NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_free_config successfull \n");
	}
	run_next_callback(user_data);
}


void net_nfc_test_llcp_create_custom_socket_option(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_h option;
	net_nfc_error_e result;

	result = net_nfc_client_llcp_create_socket_option(&option,
						128,
						1,
						NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED);

	if(result != NET_NFC_OK)
		g_print(" net_nfc_client_llcp_create_socket_option failed: %d\n", result);
	else
		g_print(" net_nfc_client_llcp_create_socket_option : %d\n", result);

	_net_nfc_util_free_mem(option);
	run_next_callback(user_data);
}

void net_nfc_test_llcp_create_default_socket_option(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_h option;
	net_nfc_error_e result;

	result = net_nfc_client_llcp_create_socket_option_default(&option);

	if(result != NET_NFC_OK)
		g_print(" net_nfc_test_llcp_create_default_socket_option failed: %d\n", result);
	else
		g_print(" net_nfc_test_llcp_create_default_socket_option : %d\n", result);

	_net_nfc_util_free_mem(option);
	run_next_callback(user_data);
}

void net_nfc_test_llcp_get_local_socket_option(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_llcp_socket_option_h option;

	result = net_nfc_client_llcp_get_local_socket_option(client_test_socket,&option);

if(result != NET_NFC_OK)
{
	g_print(" net_nfc_test_llcp_get_local_socket_option failed: %d\n", result);
	run_next_callback(user_data);
	return;
}

g_print(" net_nfc_test_llcp_get_local_socket_option: %d\n", option->miu);
g_print("net_nfc_test_llcp_get_local_socket_option: %d\n", option->rw);
g_print(" net_nfc_test_llcp_get_local_socket_option: %d\n", option->type);

run_next_callback(user_data);


}

void net_nfc_test_llcp_get_socket_option_miu(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;
	uint16_t miu;

	result = net_nfc_client_llcp_get_socket_option_miu(&option,&miu);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_client_llcp_get_socket_option_miu failed: %d\n", result);
		run_next_callback(user_data);

		return;
	}

	g_print(" net_nfc_test_llcp_get_socket_option_miu : %d\n", miu);
	run_next_callback(user_data);
}


void net_nfc_test_llcp_set_socket_option_miu(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;
	uint16_t miu = 128;

	result = net_nfc_client_llcp_set_socket_option_miu(&option,miu);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_socket_option_miu failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_set_socket_option_miu : %d\n", miu);
	run_next_callback(user_data);
}

void net_nfc_test_llcp_get_socket_option_rw(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;
	uint8_t rw;

	result = net_nfc_client_llcp_get_socket_option_rw(&option,&rw);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_socket_option_rw failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_get_socket_option_rw : %d\n", rw);
	run_next_callback(user_data);
}


void net_nfc_test_llcp_set_socket_option_rw(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;
	uint8_t rw = 1;

	result = net_nfc_client_llcp_set_socket_option_rw(&option,rw);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_socket_option_rw failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_set_socket_option_rw : %d\n", rw);
	run_next_callback(user_data);
}

void net_nfc_test_llcp_get_socket_option_type(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;
	net_nfc_socket_type_e type;

	result = net_nfc_client_llcp_get_socket_option_type(&option,&type);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_get_socket_option_type failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_get_socket_option_type : %d\n", type);
	run_next_callback(user_data);
}


void net_nfc_test_llcp_set_socket_option_type(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;
	net_nfc_socket_type_e type = NET_NFC_LLCP_SOCKET_TYPE_CONNECTIONORIENTED;

	result = net_nfc_client_llcp_set_socket_option_type(&option,type);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_set_socket_option_type failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_set_socket_option_type : %d\n", type);
	run_next_callback(user_data);
}

void net_nfc_test_llcp_free_socket_option(gpointer data,
			gpointer user_data)
{
	net_nfc_llcp_socket_option_s option;
	net_nfc_error_e result;

	result = net_nfc_client_llcp_free_socket_option(&option);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_free_socket_option failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_free_socket_option : %d\n", result);
	run_next_callback(user_data);
}


void net_nfc_test_llcp_listen(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;

	net_nfc_client_llcp_create_socket(&server_test_socket,NULL);

	result = net_nfc_client_llcp_listen(server_test_socket,
				"urn:nfc:xsn:samsung.com:testllcp" ,
				16 ,
				llcp_listen_socket_cb,
				NULL);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_client_llcp_listen failed: %d\n", result);
		return;
	}
}

void net_nfc_test_llcp_listen_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_llcp_socket_t out_socket;

	net_nfc_client_llcp_create_socket(&server_test_socket,NULL);

	result = net_nfc_client_llcp_listen_sync(server_test_socket,
				"urn:nfc:xsn:samsung.com:testllcp" ,
				16 ,
				&out_socket);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_listen_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_listen_sync : out_socket %d\n", out_socket);
	run_next_callback(user_data);

}


void net_nfc_test_llcp_receive(gpointer data,
				gpointer user_data)
{

	net_nfc_error_e result;


	result = net_nfc_client_llcp_receive(server_test_socket,
				512,
				llcp_receive_socket_cb,
				NULL);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_client_llcp_listen failed: %d\n", result);
		return;
	}
}


void net_nfc_test_llcp_receive_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	data_h out_data;


	result = net_nfc_client_llcp_receive_sync(server_test_socket,
				512,
				&out_data);

	if(result != NET_NFC_OK)
		g_print(" net_nfc_client_llcp_listen failed: %d\n", result);
	else
		print_received_data(out_data);

	_net_nfc_util_free_mem(out_data);
	run_next_callback(user_data);
}



void net_nfc_test_llcp_receive_from(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;


	result = net_nfc_client_llcp_receive_from(server_test_socket,
				512,
				llcp_receive_from_socket_cb,
				NULL);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_receive_from failed: %d\n", result);
		return;
	}
}

void net_nfc_test_llcp_receive_from_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	data_h out_data;
	sap_t sap_data;

	result = net_nfc_client_llcp_receive_from_sync(server_test_socket,
				512,
				&sap_data,
				&out_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_receive_from_sync failed: %d\n", result);
		return;
	}

	print_received_data(out_data);
	g_print(" net_nfc_test_llcp_receive_from_sync : %d\n", result);
	g_print(" net_nfc_test_llcp_receive_from_sync : %d\n", sap_data);

	_net_nfc_util_free_mem(out_data);
	run_next_callback(user_data);
}



void net_nfc_test_llcp_connect(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	net_nfc_client_llcp_create_socket(&client_test_socket, NULL);

	result = net_nfc_client_llcp_connect(client_test_socket,
				"urn:nfc:xsn:samsung.com:testllcp",
				llcp_connect_socket_cb,
				user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_connect failed: %d\n", result);
		return;
	}

}

void net_nfc_test_llcp_connect_sync(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_llcp_socket_t out_socket;

	net_nfc_client_llcp_create_socket(&client_test_socket, NULL);

	result = net_nfc_client_llcp_connect_sync(client_test_socket,
				"urn:nfc:xsn:samsung.com:testllcp",
				&out_socket);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_connect_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_connect_sync : out_socket %d\n", out_socket);
	run_next_callback(user_data);
}

void net_nfc_test_llcp_connect_sap(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	net_nfc_client_llcp_create_socket(&client_test_socket, NULL);

	result = net_nfc_client_llcp_connect_sap(client_test_socket,
				16,
				llcp_connect_sap_cb,
				user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_connect_sap failed: %d\n", result);
		return;
	}

}

void net_nfc_test_llcp_connect_sap_sync(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_llcp_socket_t out_socket;

	net_nfc_client_llcp_create_socket(&client_test_socket, NULL);

	result = net_nfc_client_llcp_connect_sap_sync(client_test_socket,
				16,
				&out_socket);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_connect_sap_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_connect_sap_sync : out_socket %d\n", out_socket);
	run_next_callback(user_data);
}



void net_nfc_test_llcp_send(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;
	data_h data;
	char * str = "Client message: Hello, server!";

	net_nfc_create_data (&data, (const uint8_t*)str ,strlen (str) + 1);

	result = net_nfc_client_llcp_send(client_test_socket,
				data,
				llcp_send_socket_cb,
				user_data);

	net_nfc_free_data(data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_send failed: %d\n", result);
		return;
	}

}


void net_nfc_test_llcp_send_sync(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;
	data_h data;
	char * str = "Client message: Hello, server!";

	net_nfc_create_data (&data, (const uint8_t*)str ,strlen (str) + 1);

	result = net_nfc_client_llcp_send_sync(client_test_socket,
				data);

	if(result != NET_NFC_OK)
		g_print(" net_nfc_test_llcp_connect failed: %d\n", result);
	else
		g_print(" net_nfc_test_llcp_send_sync success\n");

	net_nfc_free_data(data);
	run_next_callback(user_data);

}


void net_nfc_test_llcp_send_to(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;
	data_h data;
	char * str = "Client message: Hello, server!";

	net_nfc_create_data (&data, (const uint8_t*)str ,strlen (str) + 1);

	result = net_nfc_client_llcp_send_to(client_test_socket,
				16,
				data,
				llcp_send_to_socket_cb,
				user_data);

	net_nfc_free_data(data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_send_to failed: %d\n", result);
		return;
	}

}


void net_nfc_test_llcp_send_to_sync(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;
	data_h data;
	char * str = "Client message: Hello, server!";

	net_nfc_create_data (&data, (const uint8_t*)str ,strlen (str) + 1);

	result = net_nfc_client_llcp_send_to_sync(client_test_socket,
				16,
				data);

	if(result != NET_NFC_OK)
		g_print(" net_nfc_test_llcp_send_to_sync failed: %d\n", result);
	else
		g_print(" net_nfc_test_llcp_send_to_sync success\n");

	net_nfc_free_data(data);
	run_next_callback(user_data);

}


void net_nfc_test_llcp_disconnect(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_llcp_disconnect(client_test_socket,
				llcp_disconnect_socket_cb,
				user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_disconnect failed: %d\n", result);
		return;
	}

}

void net_nfc_test_llcp_disconnect_server(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_llcp_disconnect(server_test_socket,
				llcp_disconnect_socket_cb,
				user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_disconnect accepted_socket failed: %d\n", result);
		return;
	}
}


void net_nfc_test_llcp_disconnect_sync(gpointer func_data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_llcp_disconnect_sync(client_test_socket);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_llcp_disconnect_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_llcp_disconnect_sync success\n");
	run_next_callback(user_data);
}
