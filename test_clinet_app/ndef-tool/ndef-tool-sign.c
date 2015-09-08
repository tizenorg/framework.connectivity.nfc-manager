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


#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "net_nfc.h"
#include "net_nfc_sign_record.h"
#include "ndef-tool.h"

bool ndef_tool_sign_message_from_file(const char *file_name, int begin_index, int end_index, char *cert_file, char *password)
{
	bool result = false;
	ndef_message_h msg = NULL;
	int32_t count = 0;

	if (ndef_tool_read_ndef_message_from_file(file_name, &msg) > 0)
	{
		net_nfc_get_ndef_message_record_count(msg, &count);

		if (count > end_index)
		{
			fprintf(stdout, "count : %d\n", count);

			net_nfc_sign_records(msg, begin_index, end_index, cert_file, password);

			ndef_tool_write_ndef_message_to_file(file_name, msg);

			result = true;
		}

		net_nfc_free_ndef_message(msg);
	}

	return result;
}

bool ndef_tool_verify_message_from_file(const char *file_name)
{
	bool result = false;
	ndef_message_h msg = NULL;

	if (ndef_tool_read_ndef_message_from_file(file_name, &msg) > 0)
	{
		result = (net_nfc_verify_signature_ndef_message(msg) == 0);

		net_nfc_free_ndef_message(msg);
	}

	return result;
}
