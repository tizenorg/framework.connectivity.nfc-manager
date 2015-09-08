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

// libc header
#include <glib.h>

// platform header

// nfc-manager header
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_hce.h"

typedef struct _apdu_header_t
{
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t data[0];
}
__attribute__((packed)) apdu_header_t;

net_nfc_apdu_data_t *net_nfc_util_hce_create_apdu_data()
{
	net_nfc_apdu_data_t *apdu_data;

	apdu_data = g_new0(net_nfc_apdu_data_t, 1);

	apdu_data->cla = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->ins = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->p1 = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->p2 = NET_NFC_HCE_INVALID_VALUE;

	apdu_data->lc = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->le = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->data = NULL;

	return apdu_data;
}

void net_nfc_util_hce_free_apdu_data(net_nfc_apdu_data_t *apdu_data)
{
	if (apdu_data != NULL) {
		if (apdu_data->data != NULL) {
			g_free(apdu_data->data);
		}

		g_free(apdu_data);
	}
}

net_nfc_error_e net_nfc_util_hce_extract_parameter(data_s *apdu,
	net_nfc_apdu_data_t *apdu_data)
{
	net_nfc_error_e result;
	apdu_header_t *header;
	size_t l = sizeof(*header);

	if (apdu == NULL || apdu->buffer == NULL || apdu_data == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (apdu->length < l) {
		DEBUG_ERR_MSG("wrong length");

		return NET_NFC_INVALID_PARAM;
	}

	header = (apdu_header_t *)apdu->buffer;

	apdu_data->cla = header->cla;
	apdu_data->ins = header->ins;
	apdu_data->p1 = header->p1;
	apdu_data->p2 = header->p2;

	apdu_data->lc = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->le = NET_NFC_HCE_INVALID_VALUE;
	apdu_data->data = NULL;

	DEBUG_SERVER_MSG("[%02X][%02X][%02X][%02X]", header->cla, header->ins, header->p1, header->p2);

	if (apdu->length > l) {
		if (apdu->length == l + 1) {
			apdu_data->le = header->data[0];

			result = NET_NFC_OK;
		} else if (header->data[0] > 0) {
			l += header->data[0] + 1;

			if (l == apdu->length || l + 1 == apdu->length) {
				apdu_data->lc = header->data[0];

				apdu_data->data = g_malloc0(apdu_data->lc);
				if(apdu_data->data == NULL)
				{
					DEBUG_ERR_MSG("malloc failed");
					result = NET_NFC_ALLOC_FAIL;
				}
				else
				{
					memcpy(apdu_data->data, header->data + 1, apdu_data->lc);

					if (l + 1 == apdu->length) 
						apdu_data->le = header->data[apdu_data->lc + 1];

					result = NET_NFC_OK;
				}
			} else {
				DEBUG_ERR_MSG("l == len || l + 1 == len, [%d/%d]", apdu->length, l);

				result = NET_NFC_INVALID_PARAM;
			}
		} else {
			DEBUG_ERR_MSG("header->data[0] == %d", header->data[0]);

			result = NET_NFC_INVALID_PARAM;
		}
	} else if (apdu->length == l) {
		result = NET_NFC_OK;
	} else {
		DEBUG_ERR_MSG("len > l, [%d/%d]", apdu->length, l);

		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}

net_nfc_error_e net_nfc_util_hce_generate_apdu(net_nfc_apdu_data_t *apdu_data,
	data_s **apdu)
{
	return NET_NFC_NOT_SUPPORTED;
}
