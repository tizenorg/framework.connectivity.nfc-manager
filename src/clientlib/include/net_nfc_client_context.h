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
#ifndef __NET_NFC_CLIENT_CONTEXT_H__
#define __NET_NFC_CLIENT_CONTEXT_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NET_NFC_SERVICE_EMPTY_TYPE	\
	"http://tizen.org/appcontrol/operation/nfc/empty"
#define NET_NFC_SERVICE_WELL_KNOWN_TYPE	\
	"http://tizen.org/appcontrol/operation/nfc/wellknown"
#define NET_NFC_SERVICE_EXTERNAL_TYPE	\
	"http://tizen.org/appcontrol/operation/nfc/external"
#define NET_NFC_SERVICE_MIME_TYPE	\
	"http://tizen.org/appcontrol/operation/nfc/mime"
#define NET_NFC_SERVICE_URI_TYPE	\
	"http://tizen.org/appcontrol/operation/nfc/uri"


net_nfc_error_e net_nfc_client_initialize();

net_nfc_error_e net_nfc_client_deinitialize();

net_nfc_error_e net_nfc_client_is_nfc_supported(int *state);

net_nfc_error_e net_nfc_client_get_nfc_state(int *state);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_CONTEXT_H__
