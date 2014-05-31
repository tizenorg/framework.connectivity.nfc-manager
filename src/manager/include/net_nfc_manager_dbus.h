/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MANAGERDBUS_H_
#define MANAGERDBUS_H_

/* standard library header */
#include <glib-object.h>

/* SLP library header */

/* local header */

typedef struct _Nfc_Service Nfc_Service;
typedef struct _Nfc_ServiceClass Nfc_ServiceClass;

#define NFC_SERVICE_NAME "org.tizen.nfc_service"
#define NFC_SERVICE_PATH "/org/tizen/nfc_service"

GType nfc_service_get_type(void);

struct _Nfc_Service
{
	GObject parent;
	int status;
};

struct _Nfc_ServiceClass
{
	GObjectClass parent;
};

#define NFC_SERVICE_TYPE		(nfc_service_get_type ())
#define NFC_SERVICE(object)		(G_TYPE_CHECK_INSTANCE_CAST ((object), NFC_SERVICE_TYPE, Nfc_Service))
#define NFC_SERVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass), NFC_SERVICE_TYPE, Nfc_Service_Class))
#define IS_NFC_SERVICE(object)		(G_TYPE_CHECK_INSTANCE_TYPE ((object), NFC_SERVICE_TYPE))
#define IS_NFC_SERVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass), NFC_SERVICE_TYPE))
#define NFC_SERVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj), NFC_SERVICE_TYPE, Nfc_Service_Class))

typedef enum
{
	NFC_SERVICE_ERROR_INVALID_PRAM
} Nfc_Service_Error;

GQuark nfc_service_error_quark(void);
#define NFC_SERVICE_ERROR nfc_service_error_quark ()

/**
 *     launch the nfc-manager
 */
gboolean nfc_service_launch (Nfc_Service *nfc_service, const pid_t pid, guint *result_val, GError **error);
gboolean nfc_service_terminate (Nfc_Service *nfc_service, guint *result_val, GError **error);

#endif /* MANAGERDBUS_H_ */
