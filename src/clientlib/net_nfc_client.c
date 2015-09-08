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

#include <glib.h>
#include <gio/gio.h>

#ifdef SECURITY_SERVER
#include "security-server.h"
#endif

#include "net_nfc_typedef.h"
#include "net_nfc_util_gdbus_internal.h"
#include "net_nfc_client_se.h"
#include "net_nfc_client.h"
#include "net_nfc_client_manager.h"
#include "net_nfc_client_tag.h"
#include "net_nfc_client_ndef.h"
#include "net_nfc_client_transceive.h"
#include "net_nfc_client_llcp.h"
#include "net_nfc_client_snep.h"
#include "net_nfc_client_p2p.h"
#include "net_nfc_client_test.h"
#include "net_nfc_client_system_handler.h"
#include "net_nfc_client_handover.h"
#include "net_nfc_client_hce.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

void __attribute__ ((constructor)) lib_init()
{
	g_type_init();
}

void __attribute__ ((destructor)) lib_fini()
{
}

#ifdef SECURITY_SERVER
static uint8_t *cookie;
static size_t cookie_len;

static void _init_smack()
{
	if (cookie == NULL) {
		cookie_len = security_server_get_cookie_size();
		if (cookie_len > 0) {
			cookie = g_new0(uint8_t, cookie_len);
			if (cookie != NULL) {
				if (security_server_request_cookie(
					(char *)cookie,
					cookie_len) < 0) {
					g_free(cookie);
					cookie = NULL;
				}
			}
		}
	}
}

static void _deinit_smack()
{
	if (cookie != NULL) {
		g_free(cookie);
		cookie = NULL;
	}
}
#endif

GVariant *net_nfc_client_gdbus_get_privilege()
{
#ifdef SECURITY_SERVER
	return net_nfc_util_gdbus_buffer_to_variant(cookie, cookie_len);
#else
	return net_nfc_util_gdbus_buffer_to_variant(NULL, 0);
#endif
}

void net_nfc_client_gdbus_init(void)
{
#ifdef SECURITY_SERVER
	_init_smack();
#endif

#if 0		/* change gdbus init time */
	if (net_nfc_client_manager_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_tag_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_ndef_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_transceive_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_llcp_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_snep_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_p2p_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_sys_handler_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_se_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_test_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_handover_init() != NET_NFC_OK)
		return;
	if (net_nfc_client_hce_init() != NET_NFC_OK)
		return;
#endif
}

void net_nfc_client_gdbus_deinit(void)
{
	net_nfc_client_hce_deinit();
	net_nfc_client_handover_deinit();
	net_nfc_client_test_deinit();
	net_nfc_client_se_deinit();
	net_nfc_client_sys_handler_deinit();
	net_nfc_client_p2p_deinit();
	net_nfc_client_snep_deinit();
	net_nfc_client_llcp_deinit();
	net_nfc_client_transceive_deinit();
	net_nfc_client_ndef_deinit();
	net_nfc_client_tag_deinit();
	net_nfc_client_manager_deinit();
#ifdef SECURITY_SERVER
	_deinit_smack();
#endif
}
