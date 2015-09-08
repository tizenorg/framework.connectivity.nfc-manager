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
#include "net_nfc_test_client.h"
#include "net_nfc_client_context.h"
#include "net_nfc_test_client.h"
#include "net_nfc_typedef_internal.h"


void net_nfc_test_initialize()
{
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_initialize();

	g_print("Client Initialization Completed & Return value is %d\n", result);
}

void net_nfc_test_deinitialize()
{
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_deinitialize();

	g_print("Client Deinitialization Completed & Return value is %d\n", result);
}

void net_nfc_test_is_nfc_supported()
{
	int state = 0;
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_is_nfc_supported(&state);

	g_print("is nfc supported completed %d\n", result);
	g_print("state value is %d\n", state);
}

void net_nfc_test_get_nfc_state()
{
	int state = 0;
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_get_nfc_state(&state);

	g_print("get nfc state completed %d\n", result);
	g_print("state value is %d\n", state);
}
