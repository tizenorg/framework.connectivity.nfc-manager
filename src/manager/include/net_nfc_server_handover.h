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
#ifndef __NET_NFC_SERVER_HANDOVER_H__
#define __NET_NFC_SERVER_HANDOVER_H__

#include <gio/gio.h>
#include "net_nfc_gdbus.h"
#include "net_nfc_typedef_internal.h"


typedef struct _HandoverRequestData HandoverRequestData;

struct _HandoverRequestData
{
	NetNfcGDbusHandover *handoverobj;
	GDBusMethodInvocation *invocation;
	guint32 handle;
	gint32 type;
	data_s *data;
};

net_nfc_error_e net_nfc_server_handover_emit_started_signal();

net_nfc_error_e net_nfc_server_handover_emit_finished_signal();

gboolean net_nfc_server_handover_init(GDBusConnection *connection);

void net_nfc_server_handover_deinit(void);


#endif //__NET_NFC_SERVER_HANDOVER_H__
