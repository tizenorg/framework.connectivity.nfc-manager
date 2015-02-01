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
#ifndef __NET_NFC_UTIL_OPENSSL_INTERNAL_H__
#define __NET_NFC_UTIL_OPENSSL_INTERNAL_H__

#include <openssl/x509.h>

enum
{
	OPENSSL_FORMAT_UNDEF,
	OPENSSL_FORMAT_ASN1,
	OPENSSL_FORMAT_TEXT,
	OPENSSL_FORMAT_PEM,
	OPENSSL_FORMAT_NETSCAPE,
	OPENSSL_FORMAT_PKCS12,
	OPENSSL_FORMAT_SMIME,
	OPENSSL_FORMAT_ENGINE,
	OPENSSL_FORMAT_IISSGC,
	OPENSSL_FORMAT_PEMRSA,
	OPENSSL_FORMAT_ASN1RSA,
	OPENSSL_FORMAT_MSBLOB,
	OPENSSL_FORMAT_PVK,
};

typedef struct _net_nfc_openssl_verify_context_s
{
	X509 *signer_cert;
	X509_STORE *store;
	X509_STORE_CTX *store_ctx;
}
net_nfc_openssl_verify_context_s;

typedef net_nfc_openssl_verify_context_s *net_nfc_openssl_verify_context_h;

net_nfc_openssl_verify_context_h net_nfc_util_openssl_init_verify_certificate(void);
bool net_nfc_util_openssl_add_certificate_of_signer(net_nfc_openssl_verify_context_h context, uint8_t *buffer, uint32_t length);
bool net_nfc_util_openssl_add_certificate_of_ca(net_nfc_openssl_verify_context_h context, uint8_t *buffer, uint32_t length);
int net_nfc_util_openssl_verify_certificate(net_nfc_openssl_verify_context_h context);
void net_nfc_util_openssl_release_verify_certificate(net_nfc_openssl_verify_context_h context);

int net_nfc_util_openssl_sign_buffer(uint32_t type, uint8_t *buffer, uint32_t length, char *key_file, char *password, uint8_t *sign, uint32_t *sign_len);
int net_nfc_util_openssl_verify_signature(uint32_t type, uint8_t *buffer, uint32_t length, uint8_t *cert, uint32_t cert_len, uint8_t *sign, uint32_t sign_len);
int net_nfc_util_get_cert_list_from_file(char *file_name, char *password, uint8_t **buffer, uint32_t *length, uint32_t *cert_count);


bool net_nfc_util_openssl_encode_base64(const uint8_t *buffer, const uint32_t buf_len, char *result, uint32_t max_len, bool new_line_char);
bool net_nfc_util_openssl_decode_base64(const char *buffer, uint8_t *result, uint32_t *out_len, bool new_line_char);
bool net_nfc_util_openssl_digest(const char *algorithm, const uint8_t *buffer, const uint32_t buf_len, uint8_t *result, uint32_t *out_len);

#endif //__NET_NFC_UTIL_OPENSSL_INTERNAL_H__
