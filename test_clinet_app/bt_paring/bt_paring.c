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


#include <stdio.h>
#include <stdlib.h>

#include <bluetooth-api.h>
#include <glib.h>

#include <net_nfc.h>

#include <pthread.h>

void bt_event_callback(int event, bluetooth_event_param_t* param, void *user_data);
void bt_test_bond_device(bluetooth_device_address_t* bt_address);
GMainLoop* main_loop = NULL;

void initialize()
{
	if(!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	dbus_g_thread_init();
	g_type_init();
}


int main()
{
	initialize();

	//bluetooth_enable_adapter();

        //main_loop = g_main_loop_new(NULL, FALSE);
	//g_main_loop_run(main_loop);

#if 1

	ndef_message_h ndef_message = NULL;
	net_nfc_conn_handover_info_h conn_handover_info = NULL;


	if(net_nfc_retrieve_current_ndef_message(&ndef_message) == NET_NFC_OK)
	{
		printf("retrieve ndef message from nfc storage \n");

		int count = 0;

		net_nfc_get_ndef_message_record_count(ndef_message, &count);

		int i = 0;
		while(i < count){

			ndef_record_h record = NULL;
			net_nfc_get_record_by_index(ndef_message, i++, &record);

			if(record != NULL){

				net_nfc_record_tnf_e TNF = NET_NFC_RECORD_EMPTY;
				data_h record_type = NULL;

				if((net_nfc_get_record_tnf(record, &TNF) == NET_NFC_OK) && (net_nfc_get_record_type(record, &record_type) == NET_NFC_OK ) ){

					uint8_t* buffer = net_nfc_get_data_buffer(record_type);
					int buffer_length = net_nfc_get_data_length(record_type);

					 // record is WTK and Hs
					if((TNF == NET_NFC_RECORD_WELL_KNOWN_TYPE) && (buffer != NULL) && (buffer_length > 1) && (buffer[0] == 'H') && (buffer[1] == 's')){
						printf("record is found \n");
						net_nfc_parse_connection_handover_ndef_message(ndef_message, &conn_handover_info);

						if(conn_handover_info != NULL){
							uint8_t carrier_count = 0;
							net_nfc_get_connection_handover_alternative_carrier_count(conn_handover_info, &carrier_count);

							int j = 0;
							while(j < carrier_count){

								net_nfc_conn_handover_carrier_info_h carrier_info = NULL;
								net_nfc_get_connection_handover_carrier_handle_by_index(conn_handover_info, j++, &carrier_info);

								if(carrier_info != NULL){
									data_h configuration = NULL;
									net_nfc_get_carrier_configuration(carrier_info, &configuration);

									if(configuration != NULL)
									{
										uint8_t* buffer = net_nfc_get_data_buffer(configuration);
										if(buffer != NULL)
										{
											printf("bt addr [%X][%X][%X][%X][%X][%X] \n", buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);
											bluetooth_device_address_t bt_address = {{buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]}};
											bt_test_bond_device(&bt_address);
										}
										else
											printf("buffer is NULL");
									}
								}

							}
						}
					}
				}
			}
		}

	}

#endif
	return 0;
}

void bt_test_bond_device(bluetooth_device_address_t* bt_address)
{
	int ret_val;

        ret_val = bluetooth_register_callback(bt_event_callback, NULL);

	if (ret_val >= BLUETOOTH_ERROR_NONE)
        {
                printf("bluetooth_register_callback returned Success");
        }
        else
        {
                printf("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
                return ;
        }

        ret_val = bluetooth_check_adapter();

        if (ret_val < BLUETOOTH_ERROR_NONE)
        {
                printf("bluetooth_check_adapter returned failiure [0x%04x]", ret_val);
        }
        else
        {
                printf("BT state [0x%04x]", ret_val);
        }

	int error = 0;

        if((error = bluetooth_bond_device(bt_address)) < 0)
        {
        	printf("Api failed: %d", error);
        }
        else
        {
        	main_loop = g_main_loop_new(NULL, FALSE);
		g_main_loop_run(main_loop);
        }

}

void bt_event_callback(int event, bluetooth_event_param_t* param, void *user_data)
{
	switch(event)
	{
		case BLUETOOTH_EVENT_ENABLED:
			printf("BLUETOOTH_EVENT_ENABLED:\n");
		break;
		case BLUETOOTH_EVENT_DISABLED:
			printf("BLUETOOTH_EVENT_DISABLED:\n");
		break;
		case BLUETOOTH_EVENT_LOCAL_NAME_CHANGED:
			printf("BLUETOOTH_EVENT_LOCAL_NAME_CHANGED:\n");
		break;
		case BLUETOOTH_EVENT_DISCOVERY_STARTED:
			printf("BLUETOOTH_EVENT_DISCOVERY_STARTED:\n");
		break;
		case BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND:
			printf("BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND:\n");
		break;
		case BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED:
			printf("BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED:\n");
		break;
		case BLUETOOTH_EVENT_DISCOVERY_FINISHED:
			printf("BLUETOOTH_EVENT_DISCOVERY_FINISHED:\n");
		break;
		case BLUETOOTH_EVENT_BONDING_FINISHED:
			printf("BLUETOOTH_EVENT_BONDING_FINISHED:\n");

			if (param->result >= BLUETOOTH_ERROR_NONE)
                        {
                                bluetooth_device_info_t *device_info = NULL;
                                device_info  = (bluetooth_device_info_t *)param->param_data;
                                printf("dev [%s] [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X] mjr[%#x] min[%#x] srv[%#x] \n", device_info->device_name.name, \
                                        device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
                                        device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5], \
                                        device_info->device_class.major_class, device_info->device_class.minor_class, device_info->device_class.service_class);
                        }

			g_main_loop_quit (main_loop);

		break;
		default:
			printf("BLUETOOTH_EVENT = [%d]:\n", event);
		break;
	}
}
