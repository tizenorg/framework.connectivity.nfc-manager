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


void print_received_data(data_h data)
{
	guint8 *buffer = NULL;
	gint i;
	gint len = 0;

	buffer = (guint8 *)net_nfc_get_data_buffer(data);
	if (buffer == NULL)
	{
		g_print("Payload: Empty\n");
		return;
	}

	len = net_nfc_get_data_length(data);

	g_print ("Payload:\n");

	for (i = 0; i < len; i++)
	{
		g_print("%02x", buffer[i]);
		if ((i + 1) % 16 == 0)
			g_print("\n");
		else
			g_print(" ");
	}

	g_print("\n");
}

