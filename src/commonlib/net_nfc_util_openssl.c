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


#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_openssl_internal.h"

//static X509 *_load_certificate_from_file(const char *file)
//{
//	X509 *x509 = NULL;
//	BIO *cert = NULL;
//
//	cert = BIO_new(BIO_s_file());
//	if (cert != NULL)
//	{
//		if (BIO_read_filename(cert, file) > 0)
//		{
//			x509 = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
//		}
//
//		BIO_free(cert);
//	}
//
//	return x509;
//}

static X509 *_load_certificate_from_mem(int format, uint8_t *buffer, uint32_t length, char *password)
{
	X509 *x509 = NULL;
	BIO *mem = NULL;

	mem = BIO_new_mem_buf(buffer, length);
	if (mem != NULL)
	{
		switch (format)
		{
		case 0 :
			x509 = d2i_X509_bio(mem, NULL);
			break;

		case 1 :
			x509 = PEM_read_bio_X509(mem, NULL, NULL, NULL);
			break;

		case 2 :
			{
				PKCS12 *p12 = d2i_PKCS12_bio(mem, NULL);
				PKCS12_parse(p12, password, NULL, &x509, NULL);
				PKCS12_free(p12);
			}
			break;
		}

		BIO_free(mem);
	}
	else
	{
		DEBUG_ERR_MSG("X509_LOOKUP_load_file failed");
	}

	return x509;
}

//int net_nfc_util_openssl_verify_certificate(const char* certfile, const char* CAfile)
//{
//	int ret = 0;
//	X509_STORE *cert_ctx = NULL;
//	X509_LOOKUP *lookup = NULL;
//
//	cert_ctx = X509_STORE_new();
//	if (cert_ctx != NULL)
//	{
//		OpenSSL_add_all_algorithms();
//
//		lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
//		if (lookup != NULL)
//		{
//			if (X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM) == true)
//			{
//				lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
//				if (lookup != NULL)
//				{
//					X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
//
//					ret = _verify_certificate_file(cert_ctx, certfile);
//				}
//				else
//				{
//					DEBUG_ERR_MSG("X509_STORE_add_lookup failed");
//				}
//			}
//			else
//			{
//				DEBUG_ERR_MSG("X509_LOOKUP_load_file failed");
//			}
//		}
//		else
//		{
//			DEBUG_ERR_MSG("X509_STORE_add_lookup failed");
//		}
//
//		X509_STORE_free(cert_ctx);
//	}
//	else
//	{
//		DEBUG_ERR_MSG("X509_STORE_new failed");
//	}
//
//	return ret;
//}

net_nfc_openssl_verify_context_s *net_nfc_util_openssl_init_verify_certificate(void)
{
	net_nfc_openssl_verify_context_s *result = NULL;

	_net_nfc_util_alloc_mem(result, sizeof(net_nfc_openssl_verify_context_s));
	if (result != NULL)
	{
		result->store = X509_STORE_new();
		if (result->store != NULL)
		{
			OpenSSL_add_all_algorithms();
		}
		else
		{
			DEBUG_ERR_MSG("X509_STORE_new failed");
		}
	}
	else
	{
		DEBUG_ERR_MSG("alloc failed [%d]", sizeof(net_nfc_openssl_verify_context_s));
	}

	return result;
}

void net_nfc_util_openssl_release_verify_certificate(net_nfc_openssl_verify_context_s *context)
{
	if (context != NULL)
	{
		if (context->signer_cert != NULL)
			X509_free(context->signer_cert);

		if (context->store != NULL)
			X509_STORE_free(context->store);

		_net_nfc_util_free_mem(context);
	}
}

bool net_nfc_util_openssl_add_certificate_of_signer(net_nfc_openssl_verify_context_s *context, uint8_t *buffer, uint32_t length)
{
	bool result = false;

	if (context->signer_cert != NULL)
	{
		X509_free(context->signer_cert);
		context->signer_cert = NULL;
	}

	context->signer_cert = _load_certificate_from_mem(1, buffer, length, NULL);
	if (context->signer_cert != NULL)
		result = true;

	return result;
}

bool net_nfc_util_openssl_add_certificate_of_ca(net_nfc_openssl_verify_context_s *context, uint8_t *buffer, uint32_t length)
{
	bool result = false;
	X509 *x509 = NULL;

	x509 = _load_certificate_from_mem(1, buffer, length, NULL);
	if (x509 != NULL)
	{
		if (X509_STORE_add_cert(context->store, x509))
		{
			result = true;
		}
	}

	return result;
}

int net_nfc_util_openssl_verify_certificate(net_nfc_openssl_verify_context_s *context)
{
	int result = 0;
	X509_STORE_CTX *store_ctx = NULL;

	store_ctx = X509_STORE_CTX_new();
	if (store_ctx != NULL)
	{
		X509_STORE_set_flags(context->store, 0);
		if (X509_STORE_CTX_init(store_ctx, context->store, context->signer_cert, 0) == true)
		{
			result = X509_verify_cert(store_ctx);
		}
		else
		{
			DEBUG_ERR_MSG("X509_STORE_CTX_init failed");
		}

		X509_STORE_CTX_free(store_ctx);
	}
	else
	{
		DEBUG_ERR_MSG("X509_STORE_CTX_new failed");
	}

	return result;
}

int _password_callback(char *buf, int bufsiz, int verify, void *data)
{
	int res = 0;
	const char *password = (char *)data;

	if (password)
	{
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	return res;
}

static int _load_pkcs12(BIO *in, const char *password, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
	int ret = 0;
	PKCS12 *p12 = NULL;

	if ((p12 = d2i_PKCS12_bio(in, NULL)) != NULL)
	{
		if (PKCS12_verify_mac(p12, password, strlen(password)) == true)
		{
			ret = PKCS12_parse(p12, password, pkey, cert, ca);
		}
		else
		{
			DEBUG_ERR_MSG("Mac verify error (wrong password?) in PKCS12 file");
		}

		PKCS12_free(p12);
	}
	else
	{
		DEBUG_ERR_MSG("Error loading PKCS12 file");
	}

	return ret;
}

EVP_PKEY *_load_key(const char *file, int format, const char *pass, ENGINE *e)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;

	if (file == NULL)
	{
		DEBUG_ERR_MSG("no keyfile specified\n");
		return pkey;
	}

	if (format == OPENSSL_FORMAT_ENGINE)
	{
		if (e != NULL)
		{
			pkey = ENGINE_load_private_key(e, file, NULL/*ui_method*/, (void *)pass);
			if (!pkey)
			{
				DEBUG_ERR_MSG("cannot load key from engine");
			}
		}
		else
		{
			DEBUG_ERR_MSG("no engine specified");
		}
	}
	else
	{
		if ((key = BIO_new(BIO_s_file())) != NULL)
		{
			if (BIO_read_filename(key,file) > 0)
			{
				switch (format)
				{
				case OPENSSL_FORMAT_ASN1 :
					pkey = d2i_PrivateKey_bio(key, NULL);
					break;

				case OPENSSL_FORMAT_PEM :
					pkey = PEM_read_bio_PrivateKey(key, NULL, (pem_password_cb *)_password_callback, (void *)pass);
					break;

				case OPENSSL_FORMAT_PKCS12 :
					if (_load_pkcs12(key, pass, &pkey, NULL, NULL) == false)
					{
						DEBUG_ERR_MSG("_load_pkcs12 failed");
					}
					break;

				case OPENSSL_FORMAT_MSBLOB :
					pkey = b2i_PrivateKey_bio(key);
					break;

				case OPENSSL_FORMAT_PVK :
					pkey = b2i_PVK_bio(key, (pem_password_cb *)_password_callback, (void *)pass);
					break;

				default :
					DEBUG_ERR_MSG("bad input format specified for key file");
					break;
				}
			}
			else
			{
				DEBUG_ERR_MSG("Error opening %s", file);
			}

			BIO_free(key);
		}
		else
		{
			DEBUG_ERR_MSG("BIO_new failed");
		}
	}

	return pkey;
}

EVP_PKEY *_load_pubkey(const char *file, int format, const char *pass, ENGINE *e, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;

	if (file == NULL)
	{
		DEBUG_ERR_MSG("no keyfile specified");
		return pkey;
	}

	if (format == OPENSSL_FORMAT_ENGINE)
	{
		if (e != NULL)
		{
			pkey = ENGINE_load_public_key(e, file, NULL/*ui_method*/, (void *)pass);
		}
		else
		{
			DEBUG_ERR_MSG("no engine specified");
		}
	}
	else
	{
		if ((key = BIO_new(BIO_s_file())) != NULL)
		{
			if (BIO_read_filename(key,file) <= 0)
			{
				switch (format)
				{
				case OPENSSL_FORMAT_ASN1 :
					pkey = d2i_PUBKEY_bio(key, NULL);
					break;

				case OPENSSL_FORMAT_ASN1RSA :
					{
						RSA *rsa;
						rsa = d2i_RSAPublicKey_bio(key, NULL);
						if (rsa)
						{
							pkey = EVP_PKEY_new();
							if (pkey)
								EVP_PKEY_set1_RSA(pkey, rsa);
							RSA_free(rsa);
						}
						else
							pkey = NULL;
					}
					break;

				case OPENSSL_FORMAT_PEMRSA :
					{
						RSA *rsa;
						rsa = PEM_read_bio_RSAPublicKey(key, NULL, (pem_password_cb *)_password_callback, (void *)pass);
						if (rsa)
						{
							pkey = EVP_PKEY_new();
							if (pkey)
								EVP_PKEY_set1_RSA(pkey, rsa);
							RSA_free(rsa);
						}
						else
							pkey = NULL;
					}
					break;

				case OPENSSL_FORMAT_PEM :
					pkey = PEM_read_bio_PUBKEY(key, NULL, (pem_password_cb *)_password_callback, (void *)pass);
					break;

				case OPENSSL_FORMAT_MSBLOB :
					pkey = b2i_PublicKey_bio(key);
					break;

				default :
					DEBUG_ERR_MSG("bad input format specified for key file");
					break;
				}
			}
			else
			{
				DEBUG_ERR_MSG("Error opening %s %s", key_descrip, file);
			}

			BIO_free(key);
		}
		else
		{
			DEBUG_ERR_MSG("BIO_new failed");
		}
	}

	return pkey;
}

int net_nfc_util_openssl_sign_buffer(uint32_t type, uint8_t *buffer, uint32_t length, char *key_file, char *password, uint8_t *sign, uint32_t *sign_len)
{
	int result = 0;
	const EVP_MD *md = NULL;
	ENGINE *engine;
	EVP_PKEY *pkey;

	OpenSSL_add_all_algorithms();

	/* md context */
	EVP_MD_CTX ctx = { 0, };
	EVP_PKEY_CTX *pctx = NULL;

	switch (type)
	{
	case 0 :
		result = 0;
		return result;

		/* RSASSA-PSS, RSASSA-PKCS1-v1_5 */
	case 1 :
		case 2 :
		/* md */
		md = EVP_get_digestbyname("sha1");

		/* engine */
		engine = ENGINE_get_default_RSA();
		break;

		/* DSA */
	case 3 :
		/* md */
		//md = EVP_get_digestbyname("sha1");
		/* engine */
		engine = ENGINE_get_default_DSA();
		break;

		/* ECDSA */
	case 4 :
		/* md */
		md = EVP_get_digestbyname("sha1");

		/* engine */
		engine = ENGINE_get_default_ECDSA();
		break;

	default :
		result = -1;
		return result;
	}

	/* pkey */
	pkey = _load_key(key_file, OPENSSL_FORMAT_PKCS12, password, NULL);

	EVP_DigestSignInit(&ctx, &pctx, md, engine, pkey);
	EVP_DigestSignUpdate(&ctx, buffer, length);
	EVP_DigestSignFinal(&ctx, sign, sign_len);

	return result;
}

int net_nfc_util_openssl_verify_signature(uint32_t type, uint8_t *buffer, uint32_t length, uint8_t *cert, uint32_t cert_len, uint8_t *sign, uint32_t sign_len)
{
	int result = 0;
	const EVP_MD *md = NULL;
	ENGINE *engine;
	EVP_PKEY *pkey;

	OpenSSL_add_all_algorithms();

	/* md context */
	EVP_MD_CTX ctx = { 0, };
	EVP_PKEY_CTX *pctx = NULL;

	switch (type)
	{
	case 0 :
		result = 0;
		return result;

		/* RSASSA-PSS, RSASSA-PKCS1-v1_5 */
	case 1 :
	case 2 :
		/* md */
		md = EVP_get_digestbyname("sha1");

		/* engine */
		engine = ENGINE_get_default_RSA();
		break;

		/* DSA */
	case 3 :
		/* md */
		//md = EVP_get_digestbyname("sha1");
		/* engine */
		engine = ENGINE_get_default_DSA();
		break;

		/* ECDSA */
	case 4 :
		/* md */
		md = EVP_get_digestbyname("sha1");

		/* engine */
		engine = ENGINE_get_default_ECDSA();
		break;

	default :
		result = -1;
		return result;
	}

	/* pkey */
	X509 *x509 = _load_certificate_from_mem(0, cert, cert_len, NULL);
	if(x509 == NULL)
		return 0;

	pkey = X509_PUBKEY_get(X509_get_X509_PUBKEY(x509));
	X509_free(x509);

	EVP_DigestVerifyInit(&ctx, &pctx, md, engine, pkey);
	EVP_DigestVerifyUpdate(&ctx, buffer, length);
	result = EVP_DigestVerifyFinal(&ctx, sign, sign_len);

	DEBUG_MSG("EVP_DigestVerifyFinal returns %d", result);

	return result;
}

#if 0
int net_nfc_util_get_cert_list_from_file(char *file_name, char *password, uint8_t **buffer, uint32_t *length, uint32_t *cert_count)
{
	int result = 0;
	BIO *bio = NULL;

	bio = BIO_new(BIO_s_file());
	if (bio != NULL)
	{
		if (BIO_read_filename(bio, file_name) > 0)
		{
			STACK_OF(X509_INFO) *xis = NULL;

			if ((xis = PEM_X509_INFO_read_bio(bio, NULL, (pem_password_cb *)_password_callback, password)) != NULL)
			{
				X509_INFO *xi;
				int i;
				uint32_t temp_len = 0;
				uint8_t *temp_buf = NULL;
				uint32_t offset = 0;
				uint32_t count = 0;

				for (i = 0; i < sk_X509_INFO_num(xis); i++)
				{
					xi = sk_X509_INFO_value(xis, i);
					if (xi->x509)
					{
						int32_t ret = 0;

						if ((ret = i2d_X509(xi->x509, NULL)) > 0)
						{
							temp_len += (ret + 2);
						}
					}
				}

				DEBUG_MSG("count = %d, length = %d", sk_X509_INFO_num(xis), temp_len);
				*length = temp_len;
				_net_nfc_util_alloc_mem(*buffer, temp_len);

				for (i = 0; i < sk_X509_INFO_num(xis); i++)
				{
					xi = sk_X509_INFO_value(xis, i);
					if (xi->x509)
					{
						temp_buf = NULL;

						if ((temp_len = i2d_X509(xi->x509, &temp_buf)) > 0)
						{
							*(uint16_t *)(*buffer + offset) = temp_len;
							offset += sizeof(uint16_t);

							memcpy(*buffer + offset, temp_buf, temp_len);
							offset += temp_len;

							count++;
						}
					}
				}

				*cert_count = count;

				sk_X509_INFO_pop_free(xis, X509_INFO_free);
			}
			else
			{
				DEBUG_ERR_MSG("PEM_X509_INFO_read_bio failed");
			}
		}

		BIO_free(bio);
	}

	return result;
}
#endif

/* TODO : DER?? PEM?? */
int net_nfc_util_get_cert_list_from_file(char *file_name, char *password, uint8_t **buffer, uint32_t *length, uint32_t *cert_count)
{
	int result = 0;
	BIO *bio = NULL;

	bio = BIO_new(BIO_s_file());
	if (bio != NULL)
	{
		if (BIO_read_filename(bio, file_name) > 0)
		{
			EVP_PKEY *pkey = NULL;
			X509 *x509 = NULL;
			STACK_OF(X509) *ca = NULL;

			if (_load_pkcs12(bio, password, &pkey, &x509, &ca) != 0)
			{
				X509 *temp_x509;
				int i;
				uint32_t temp_len = 0;
				uint8_t *temp_buf = NULL;
				uint32_t offset = 0;
				uint32_t count = 0;
				int32_t ret = 0;

				if ((ret = i2d_X509(x509, NULL)) > 0)
				{
					temp_len += (ret + 2);
				}

				for (i = 0; i < sk_X509_num(ca); i++)
				{
					temp_x509 = sk_X509_value(ca, i);
					if (temp_x509)
					{
						if ((ret = i2d_X509(temp_x509, NULL)) > 0)
						{
							temp_len += (ret + 2);
						}
					}
				}

				DEBUG_MSG("count = %d, length = %d", sk_X509_num(ca) + 1, temp_len);
				*length = temp_len;
				_net_nfc_util_alloc_mem(*buffer, temp_len);

				if ((temp_len = i2d_X509(x509, &temp_buf)) > 0)
				{
					*(uint16_t *)(*buffer + offset) = temp_len;
					offset += sizeof(uint16_t);

					memcpy(*buffer + offset, temp_buf, temp_len);
					offset += temp_len;

					count++;
				}

				for (i = 0; i < sk_X509_num(ca); i++)
				{
					temp_x509 = sk_X509_value(ca, i);
					if (temp_x509)
					{
						temp_buf = NULL;

						if ((temp_len = i2d_X509(temp_x509, &temp_buf)) > 0)
						{
							*(uint16_t *)(*buffer + offset) = temp_len;
							offset += sizeof(uint16_t);

							memcpy(*buffer + offset, temp_buf, temp_len);
							offset += temp_len;

							count++;
						}
					}
				}

				*cert_count = count;

				sk_X509_pop_free(ca, X509_free);
			}
			else
			{
				DEBUG_ERR_MSG("PEM_X509_INFO_read_bio failed");
			}
		}

		BIO_free(bio);
	}

	return result;
}

bool net_nfc_util_openssl_encode_base64(const uint8_t *buffer, const uint32_t buf_len, char *result, uint32_t max_len, bool new_line_char)
{
	bool ret = false;
	BUF_MEM *bptr;
	BIO *b64, *bmem;

	if (buffer == NULL || buf_len == 0)
	{
		return ret;
	}

	b64 = BIO_new(BIO_f_base64());
	if(b64 == NULL)
		return false;

	bmem = BIO_new(BIO_s_mem());

	if (new_line_char == false)
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	b64 = BIO_push(b64, bmem);

	BIO_write(b64, buffer, buf_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	if (max_len >= bptr->length)
	{
		memcpy(result, bptr->data, bptr->length);
		result[bptr->length] = 0;
		ret = true;
	}
	else
	{
		DEBUG_ERR_MSG("not enough result buffer");
	}

	BIO_free_all(b64);

	return ret;
}

bool net_nfc_util_openssl_decode_base64(const char *buffer, uint8_t *result, uint32_t *out_len, bool new_line_char)
{
	bool ret = false;
	unsigned int length = 0;
	char *temp;

	if (buffer == NULL || (length = strlen(buffer)) == 0)
	{
		return ret;
	}

	_net_nfc_util_alloc_mem(temp, length);
	if (temp != NULL)
	{
		BIO *b64, *bmem;

		b64 = BIO_new(BIO_f_base64());
		if(b64 == NULL)
			return false;

		bmem = BIO_new_mem_buf((void *)buffer, length);
		if (new_line_char == false)
			BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_push(b64, bmem);

		length = BIO_read(bmem, temp, length);

		BIO_free_all(bmem);

		if (*out_len > length && length > 0)
		{
			*out_len = length;
			memcpy(result, temp, *out_len);
			ret = true;
		}
		else
		{
			DEBUG_ERR_MSG("not enough result buffer");
		}

		_net_nfc_util_free_mem(temp);
	}
	else
	{
		DEBUG_ERR_MSG("alloc failed");
	}

	return ret;
}

bool net_nfc_util_openssl_digest(const char *algorithm, const uint8_t *buffer, const uint32_t buf_len, uint8_t *result, uint32_t *out_len)
{
	const EVP_MD *md;
	unsigned char *temp;
	bool ret = false;

	if (algorithm == NULL || buffer == NULL || buf_len == 0)
	{
		return ret;
	}

	OpenSSL_add_all_digests();

	if ((md = EVP_get_digestbyname(algorithm)) != NULL)
	{
		_net_nfc_util_alloc_mem(temp, EVP_MAX_MD_SIZE);
		if (temp != NULL)
		{
			EVP_MD_CTX mdCtx;
			unsigned int resultLen = 0;

			memset(temp, 0, EVP_MAX_MD_SIZE);

			EVP_DigestInit(&mdCtx, md);
			if (EVP_DigestUpdate(&mdCtx, buffer, buf_len) != 0)
			{
				DEBUG_ERR_MSG("EVP_DigestUpdate failed");
			}
			EVP_DigestFinal(&mdCtx, temp, &resultLen);

			if (*out_len >= resultLen)
			{
				*out_len = resultLen;
				memcpy(result, temp, *out_len);
				ret = true;
			}
			else
			{
				DEBUG_ERR_MSG("not enough result buffer");
			}

			_net_nfc_util_free_mem(temp);
		}
		else
		{
			DEBUG_ERR_MSG("alloc failed");
		}
	}
	else
	{
		DEBUG_ERR_MSG("EVP_get_digestbyname(\"%s\") returns NULL", algorithm);
	}

	return ret;
}
