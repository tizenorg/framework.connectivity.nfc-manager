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
#include <glib.h>

#include "net_nfc.h"
#include "ndef-tool.h"

static GMainLoop *main_loop = NULL;

void _activation_complete_cb(net_nfc_message_e message, net_nfc_error_e result, void *data, void *user_param, void *trans_data)
{
	switch (message)
	{
	case NET_NFC_MESSAGE_INIT :
		if (result == NET_NFC_OK)
			fprintf(stdout, "power on success\n\n");
		else
			fprintf(stdout, "failed to power on (%d)\n\n", result);

		net_nfc_unset_response_callback();
		net_nfc_deinitialize();
		g_main_loop_quit(main_loop);
		break;

	case NET_NFC_MESSAGE_DEINIT :
		if (result == NET_NFC_OK)
			fprintf(stdout, "power off success\n\n");
		else
			fprintf(stdout, "failed to power off (%d)\n\n", result);

		net_nfc_unset_response_callback();
		net_nfc_deinitialize();
		g_main_loop_quit(main_loop);
		break;

	default :
		break;
	}
}

int ndef_tool_read_ndef_message_from_file(const char *file_name, ndef_message_h *msg)
{
	int result = -1;
	FILE *file = NULL;

	file = fopen(file_name, "rb");
	if (file != NULL)
	{
		long int file_size = 0;
		size_t read = 0;

		fseek(file, 0, SEEK_END);
		file_size = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (file_size > 0)
		{
			data_h data;

			net_nfc_create_data(&data, NULL, file_size);
			if (data != NULL)
			{
				read = fread((void *)net_nfc_get_data_buffer(data), 1, file_size, file);

				net_nfc_create_ndef_message_from_rawdata(msg, data);

				net_nfc_free_data(data);

				result = file_size;
			}
		}

		fclose(file);
	}

	return result;
}

int ndef_tool_write_ndef_message_to_file(const char *file_name, ndef_message_h msg)
{
	int result = -1;
	FILE *file = NULL;
	data_h data = NULL;

	net_nfc_create_rawdata_from_ndef_message(msg, &data);
	if (data != NULL)
	{
		file = fopen(file_name, "wb");
		if (file != NULL)
		{
			fwrite((void *)net_nfc_get_data_buffer(data), 1, net_nfc_get_data_length(data), file);
			fflush(file);
			fclose(file);

			result = 0;
		}

		net_nfc_free_data(data);
	}

	return result;
}

static void print_usage(char *file_name)
{
	fprintf(stdout, "Usage : %s OPERATION [OPTION]... FILE\n", file_name);
	fprintf(stdout, "\n");
	fprintf(stdout, "  Operation\n");
	fprintf(stdout, "    -a, --append-record          Append a record to file\n");
	fprintf(stdout, "    Options\n");
	fprintf(stdout, "      -t, --tnf tnf              Input TNF value\n");
	fprintf(stdout, "                                 (WKT : Well-known, EXT : External, \n");
	fprintf(stdout, "                                  MIME : MIME-type, URI : Absolute-URI)\n");
	fprintf(stdout, "      -T, --type-data data       Input Type-field data\n");
	fprintf(stdout, "      -I, --id-data data         Input ID-field data\n");
	fprintf(stdout, "      -P, --payload-data data    Input Payload-field data. You can input hexa-style data using '%%' prefix\n");
	fprintf(stdout, "                                    ex) (0x20)abc  : %%20abc\n");
	fprintf(stdout, "                                  it is possible to input '%%' by using '%%%%'\n");
	fprintf(stdout, "                                    ex) 120%%20  : 120%%%%20\n");
	fprintf(stdout, "          --payload-file file    Input Payload-field data from binary file\n");
	fprintf(stdout, "      -E, --encoding data        Input encoding method of Well-known Text type record\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "    -r, --remove-record          Remove a specific record from file\n");
	fprintf(stdout, "    Options\n");
	fprintf(stdout, "      -i, --index value          Input a record index\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "    -d, --display                Display all records in file\n");
	fprintf(stdout, "    -s, --sign-records           Sign some continuous records in file\n");
	fprintf(stdout, "    Options\n");
	fprintf(stdout, "      -b, --begin-index value    Input a beginning record index\n");
	fprintf(stdout, "      -e, --end-index value      Input a last record index\n");
	fprintf(stdout, "      -c, --cert-file file       Input a PKCS #12 certificate file (DER file, not PEM file)\n");
	fprintf(stdout, "      -p, --password pass        Input a password of PKCS #12 certificate file\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "    -v, --verify-signed-records  Verify signature in file\n");
	fprintf(stdout, "        --read-tag               Read a ndef from tag and store to file\n");
	fprintf(stdout, "        --write-tag              Write a ndef file to tag\n");
	fprintf(stdout, "        --receive-ndef           Receive a ndef from target device and store to file\n");
	fprintf(stdout, "        --send-ndef              Send a ndef file to target device\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "    -h, --help                   Show this help messages\n");
	fprintf(stdout, "\n");
}

static net_nfc_record_tnf_e _parse_tnf_string(const char *tnf)
{
	net_nfc_record_tnf_e result = -1;

	if (tnf == NULL)
		return result;

	if (strncasecmp(tnf, "EMT", 3) == 0)
	{
		result = NET_NFC_RECORD_EMPTY;
	}
	else if (strncasecmp(tnf, "WKT", 3) == 0)
	{
		result = NET_NFC_RECORD_WELL_KNOWN_TYPE;
	}
	else if (strncasecmp(tnf, "MIME", 4) == 0)
	{
		result = NET_NFC_RECORD_MIME_TYPE;
	}
	else if (strncasecmp(tnf, "URI", 3) == 0)
	{
		result = NET_NFC_RECORD_URI;
	}
	else if (strncasecmp(tnf, "EXT", 3) == 0)
	{
		result = NET_NFC_RECORD_EXTERNAL_RTD;
	}
	else if (strncasecmp(tnf, "UNK", 3) == 0)
	{
		result = NET_NFC_RECORD_UNKNOWN;
	}
	else if (strncasecmp(tnf, "UNC", 3) == 0)
	{
		result = NET_NFC_RECORD_UNCHAGNED;
	}

	return result;
}

static int _append_record_to_file(const char *file_name, ndef_record_h record)
{
	int result = -1;
	ndef_message_h msg = NULL;

	if (ndef_tool_read_ndef_message_from_file(file_name, &msg) <= 0)
	{
		net_nfc_create_ndef_message(&msg);
	}

	net_nfc_append_record_to_ndef_message(msg, record);

	ndef_tool_write_ndef_message_to_file(file_name, msg);

	net_nfc_free_ndef_message(msg);

	result = 0;

	return result;
}

ndef_record_h _create_record(net_nfc_record_tnf_e tnf, data_h type, data_h id , data_h payload, char *encoding)
{
	ndef_record_h result = NULL;

	switch (tnf)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		if (net_nfc_get_data_length(type) == 1 && memcmp((void *)net_nfc_get_data_buffer(type), "T", 1) == 0)
		{
			if (encoding == NULL)
			{
				fprintf(stdout, "encoding type is not present.\n");
				return result;
			}

			char *temp_str = calloc(1, net_nfc_get_data_length(payload) + 1);
			memcpy(temp_str, (void *)net_nfc_get_data_buffer(payload), net_nfc_get_data_length(payload));

			net_nfc_create_text_type_record(&result, temp_str, encoding, NET_NFC_ENCODE_UTF_8);
			free(temp_str);

			if (id != NULL)
			{
				net_nfc_set_record_id(result, id);
			}
		}
		else if (net_nfc_get_data_length(type) == 1 && memcmp((void *)net_nfc_get_data_buffer(type), "U", 1) == 0)
		{
			char *temp_str = calloc(1, net_nfc_get_data_length(payload) + 1);
			memcpy(temp_str, (void *)net_nfc_get_data_buffer(payload), net_nfc_get_data_length(payload));

			net_nfc_create_uri_type_record(&result, temp_str, 0);
			free(temp_str);

			if (id != NULL)
			{
				net_nfc_set_record_id(result, id);
			}
		}
		else
		{
			net_nfc_create_record(&result, tnf, type, id, payload);
		}
		break;

	default :
		net_nfc_create_record(&result, tnf, type, id, payload);
		break;
	}

	return result;
}

bool _remove_record_from_file(const char *file_name, int index)
{
	bool result = false;
	ndef_message_h msg = NULL;

	if (ndef_tool_read_ndef_message_from_file(file_name, &msg) > 0)
	{
		net_nfc_remove_record_by_index(msg, index);

		ndef_tool_write_ndef_message_to_file(file_name, msg);

		net_nfc_free_ndef_message(msg);

		result = true;
	}

	return result;
}

#define __IS_SHORT_OPTION(__dst) ((strlen(__dst) == 2) && ((__dst)[0] == '-'))
#define __IS_LONG_OPTION(__dst) ((strlen(__dst) > 2) && ((__dst)[0] == '-') && ((__dst)[1] == '-'))
#define __IS_OPTION(__dst) (__IS_SHORT_OPTION(__dst) || __IS_LONG_OPTION(__dst))

#define __COMPARE_OPTION(__dst, __s, __l) \
	((__IS_SHORT_OPTION(__dst) && ((__dst)[1] == (__s))) || \
	(__IS_LONG_OPTION(__dst) && (strcmp((__dst) + 2, (__l)) == 0)))

#define __DO_NEXT_ARG \
		if (++i >= argc || __IS_OPTION(argv[i]) == true) \
		{ \
			operation = OPERATION_ERROR; \
			break; \
		}

int main(int argc, char *argv[])
{
	int remove_index = -1;
	int begin_index = -1;
	int end_index = -1;
	int operation = OPERATION_ERROR;
	net_nfc_record_tnf_e tnf = -1;
	data_h type = NULL;
	data_h id = NULL;
	data_h payload = NULL;
	char *file_name = NULL;
	char *cert_file = NULL;
	char *password = NULL;
	char *encoding = NULL;
	ndef_record_h record = NULL;

	int i = 1;
	int len = 0;

	for (i = 1; i < argc; i++)
	{
		if (__COMPARE_OPTION(argv[i], 'a', "append-record"))
		{
			operation = OPERATION_APPEND;
		}
		else if (__COMPARE_OPTION(argv[i], 's', "sign-records"))
		{
			operation = OPERATION_SIGN;
		}
		else if (__COMPARE_OPTION(argv[i], 'd', "display-record"))
		{
			operation = OPERATION_DISPLAY;
		}
		else if (__COMPARE_OPTION(argv[i], 'v', "verify-signed-records"))
		{
			operation = OPERATION_VERIFY;
		}
		else if (__COMPARE_OPTION(argv[i], 'r', "remove-record"))
		{
			operation = OPERATION_REMOVE;
		}
		else if (__COMPARE_OPTION(argv[i], 0, "read-tag"))
		{
			operation = OPERATION_READ_TAG;
		}
		else if (__COMPARE_OPTION(argv[i], 0, "write-tag"))
		{
			operation = OPERATION_WRITE_TAG;
		}
		else if (__COMPARE_OPTION(argv[i], 0, "receive-ndef"))
		{
			operation = OPERATION_RECEIVE_NDEF;
		}
		else if (__COMPARE_OPTION(argv[i], 0, "send-ndef"))
		{
			operation = OPERATION_SEND_NDEF;
		}
		else if (__COMPARE_OPTION(argv[i], 0, "off")) /* hidden operation */
		{
			operation = OPERATION_OFF;
		}
		else if (__COMPARE_OPTION(argv[i], 0, "on")) /* hidden operation */
		{
			operation = OPERATION_ON;
		}
		else if (__COMPARE_OPTION(argv[i], 'i', "record-index"))
		{
			__DO_NEXT_ARG;
			remove_index = atoi(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 'c', "cert-file"))
		{
			__DO_NEXT_ARG;
			cert_file = strdup(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 'p', "password"))
		{
			__DO_NEXT_ARG;
			password = strdup(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 'b', "begin-index"))
		{
			__DO_NEXT_ARG;
			begin_index = atoi(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 'e', "end-index"))
		{
			__DO_NEXT_ARG;
			end_index = atoi(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 't', "tnf"))
		{
			__DO_NEXT_ARG;
			tnf = _parse_tnf_string(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 'T', "type-data"))
		{
			__DO_NEXT_ARG;
			len = strlen(argv[i]);
			if (len > 0)
			{
				net_nfc_create_data(&type, (const uint8_t *)argv[i], len);
			}
		}
		else if (__COMPARE_OPTION(argv[i], 'I', "id-data"))
		{
			__DO_NEXT_ARG;
			len = strlen(argv[i]);
			if (len > 0)
			{
				net_nfc_create_data(&id, (const uint8_t *)argv[i], len);
			}
		}
		else if (__COMPARE_OPTION(argv[i], 'P', "payload-data"))
		{
			__DO_NEXT_ARG;
			len = strlen(argv[i]);
			if (len > 0)
			{
				uint8_t *buffer = NULL;

				buffer = calloc(1, len);
				if (buffer != NULL)
				{
					int j, current = 0;

					for (j = 0; j < len; j++)
					{
						if (argv[i][j] == '%')
						{
							if (j + 2 < len)
							{
								if (argv[i][j + 1] != '%')
								{
									char temp[3] = { 0, };

									temp[0] = argv[i][j + 1];
									temp[1] = argv[i][j + 2];

									buffer[current++] = (uint8_t)strtol(temp, NULL, 16);
									j += 2;
								}
								else
								{
									buffer[current++] = '%';
									j++;
								}
							}
							else if (j + 1 < len)
							{
								if (argv[i][j + 1] == '%')
								{
									buffer[current++] = '%';
									j++;
								}
								else
								{
									buffer[current++] = argv[i][j];
								}
							}
							else
							{
								/* invalid param. error? */
							}
						}
						else
						{
							buffer[current++] = argv[i][j];
						}
					}

					net_nfc_create_data(&payload, buffer, current);

					free(buffer);
				}
			}
		}
		else if (__COMPARE_OPTION(argv[i], 0, "payload-file"))
		{
			__DO_NEXT_ARG;
			len = strlen(argv[i]);
			if (len > 0)
			{
				FILE *file = NULL;

				file = fopen(argv[i], "rb");
				if (file != NULL)
				{
					long int file_size = 0;
					size_t read = 0;

					fseek(file, 0, SEEK_END);
					file_size = ftell(file);
					fseek(file, 0, SEEK_SET);

					if (file_size > 0)
					{
						uint8_t *buffer = NULL;

						buffer = calloc(1, file_size);
						if (buffer != NULL)
						{
							read = fread(buffer, 1, file_size, file);

							net_nfc_create_data(&payload, buffer, read);

							free(buffer);
						}
					}

					fclose(file);
				}
			}
		}
		else if (__COMPARE_OPTION(argv[i], 'E', "encoding"))
		{
			__DO_NEXT_ARG;
			encoding = strdup(argv[i]);
		}
		else if (__COMPARE_OPTION(argv[i], 'h', "help"))
		{
			operation = OPERATION_ERROR;
			break;
		}
		else
		{
			if (file_name == NULL)
			{
				file_name = strdup(argv[i]);
			}
			else
			{
				operation = OPERATION_ERROR;
				break;
			}
		}
	}

	if (operation != OPERATION_ON && operation != OPERATION_OFF && file_name == NULL)
		operation = OPERATION_ERROR;

	switch (operation)
	{
	case OPERATION_DISPLAY :
		ndef_tool_display_ndef_message_from_file(file_name);
		break;

	case OPERATION_APPEND :
		if (tnf >= 0 && type != NULL)
		{
			record = _create_record(tnf, type, id, payload, encoding);

			if (record != NULL)
			{
				_append_record_to_file(file_name, record);

				ndef_tool_display_ndef_message_from_file(file_name);
			}
			else
			{
				print_usage(argv[0]);
			}
		}
		else
		{
			print_usage(argv[0]);
		}
		break;

	case OPERATION_REMOVE :
		_remove_record_from_file(file_name, remove_index);
		ndef_tool_display_ndef_message_from_file(file_name);
		break;

	case OPERATION_SIGN :
		if (begin_index < 0 || end_index < 0 || begin_index > end_index || cert_file == NULL || password == NULL)
		{
			print_usage(argv[0]);
		}
		else
		{
			fprintf(stdout, "file : %s\ncert file : %s\npassword : %s\nbegin index : %d\nend index : %d\n", file_name, cert_file, password, begin_index, end_index);
			ndef_tool_sign_message_from_file(file_name, begin_index, end_index, cert_file, password);
			ndef_tool_display_ndef_message_from_file(file_name);
		}
		break;

	case OPERATION_VERIFY :
		fprintf(stdout, "verify %s\n", ndef_tool_verify_message_from_file(file_name) ? "success" : "failed");
		break;

	case OPERATION_READ_TAG :
		ndef_tool_read_ndef_from_tag(file_name);
		break;

	case OPERATION_WRITE_TAG :
		ndef_tool_write_ndef_to_tag(file_name);
		break;

	case OPERATION_RECEIVE_NDEF :
		ndef_tool_receive_ndef_via_p2p(file_name);
		break;

	case OPERATION_SEND_NDEF :
		ndef_tool_send_ndef_via_p2p(file_name);
		break;

	case OPERATION_ON :
		{
			int state = 0;

			net_nfc_get_state(&state);

			if (state == 0)
			{
				fprintf(stdout, "Power on....\n\n");

				if(!g_thread_supported())
				{
					g_thread_init(NULL);
				}

				main_loop = g_main_new(true);

				net_nfc_initialize();
				net_nfc_set_response_callback(_activation_complete_cb, NULL);
				net_nfc_set_state(true, NULL);

				g_main_loop_run(main_loop);
			}
			else
			{
				fprintf(stdout, "Already power is on.\n\n");
			}
		}
		break;

	case OPERATION_OFF :
		{
			int state = 0;

			net_nfc_get_state(&state);

			if (state == 1)
			{
				fprintf(stdout, "Power off....\n\n");

				if(!g_thread_supported())
				{
					g_thread_init(NULL);
				}

				main_loop = g_main_new(true);

				net_nfc_initialize();
				net_nfc_set_response_callback(_activation_complete_cb, NULL);
				net_nfc_set_state(false, NULL);

				g_main_loop_run(main_loop);
			}
			else
			{
				fprintf(stdout, "Already power is off.\n\n");
			}
		}
		break;

	case OPERATION_ERROR :
	default :
		print_usage(argv[0]);
		break;
	}

	return 0;
}

