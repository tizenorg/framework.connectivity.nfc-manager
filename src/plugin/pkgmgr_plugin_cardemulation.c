/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pkgmgr-info.h>
#include <glib.h>
#include <string.h>
#include <libxml/parser.h>
#include <dlog.h>

#include "net_nfc.h"

#define DBG(fmt, args ...) \
	do { \
		LOGD(fmt, ## args); \
	} while (0)

#ifndef PKGMGR_MODULE_API
#define PKGMGR_MODULE_API __attribute__ ((visibility("default")))
#endif

typedef struct metadata {
	const char *key;
	const char *value;
} metadata;

int _nfc_register_aid(char *xml_path, const char *pkgid)
{
	xmlChar *key = NULL;
	int ret = 0;
	char *aid = NULL;
	net_nfc_se_type_e se_type;
	bool unlock_required;
	int power;
	net_nfc_card_emulation_category_t category;
	xmlNodePtr pRoot, pCurrentElement;

	xmlDocPtr pDocument = xmlParseFile(xml_path);
	if (pDocument == NULL) {
		DBG("xmlDocPtr conversion failed.");
		return NET_NFC_OPERATION_FAIL;
	}

	pRoot = xmlDocGetRootElement(pDocument);
	if (pRoot == NULL) {
		DBG(" Empty document");
		xmlFreeDoc(pDocument);
		return NET_NFC_OPERATION_FAIL;
	}

	for (pCurrentElement = pRoot->children; pCurrentElement; pCurrentElement = pCurrentElement->next) {
		if (pCurrentElement->type == XML_ELEMENT_NODE) {
			if (!(xmlStrcmp(pCurrentElement->name, (const xmlChar *) "wallet"))) {
				xmlNodePtr pSubElement;

				DBG("wallet element found...");

				for (pSubElement = pCurrentElement->children; pSubElement; pSubElement = pSubElement->next) {
					if (pSubElement->type == XML_ELEMENT_NODE) {
						if (!(xmlStrcmp(pSubElement->name, (const xmlChar *) "aid-group"))) {

							DBG("aid-group element found...");

							key = xmlGetProp(pSubElement, (const xmlChar*)"category");
							if (key != NULL) {
								xmlNodePtr pAidElement;

								DBG( "category : %s, ", (char *)key);

								if (strcasecmp((char*)key, "payment") == 0) {
									category = NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT;
								}
								else if (strcasecmp((char*)key, "other") == 0) {
									category = NET_NFC_CARD_EMULATION_CATEGORY_OTHER;
								}
								else {
									ret = NET_NFC_NO_DATA_FOUND;
									goto ERROR;
								}
								xmlFree(key);
								key = NULL;

								//parsing property
								for (pAidElement = pSubElement->children; pAidElement; pAidElement = pAidElement->next) {
									if (pAidElement->type == XML_ELEMENT_NODE) {
										if (!(xmlStrcmp(pAidElement->name, (const xmlChar *) "aid"))) {
											key = xmlGetProp(pAidElement, (const xmlChar*)"aid");
											if (key != NULL) {
												DBG("aid : %s, ", (char *)key);
												aid = strdup((char*)key);
												xmlFree(key);
												key = NULL;
											}
											else {
												DBG("aid is null");
												ret = NET_NFC_NO_DATA_FOUND;
												goto ERROR;
											}

											key = xmlGetProp(pAidElement, (const xmlChar*)"se_type");
											if (key != NULL) {
												DBG("se_type : %s, ", (char *)key);
												if (strcasecmp((char*)key, "ese") == 0) {
													se_type = NET_NFC_SE_TYPE_ESE;
												}
												else if (strcasecmp((char*)key, "uicc") == 0) {
													se_type = NET_NFC_SE_TYPE_UICC;
												}
												else if (strcasecmp((char*)key, "hce") == 0) {
													se_type = NET_NFC_SE_TYPE_HCE;
												}
												else {
													ret = NET_NFC_NO_DATA_FOUND;
													goto ERROR;
												}
												xmlFree(key);
												key = NULL;
											}
											else {
												DBG("se_type is null");
												ret = NET_NFC_NO_DATA_FOUND;
												goto ERROR;
											}

											key = xmlGetProp(pAidElement, (const xmlChar*)"unlock");
											if (key != NULL) {
												DBG("unlock : %s, ", (char *)key);
												if (strcasecmp((char*)key, "true") == 0) {
													unlock_required = true;
												}
												else if (strcasecmp((char*)key, "false") == 0) {
													unlock_required = false;
												}
												else {
													ret = NET_NFC_NO_DATA_FOUND;
													goto ERROR;
												}
												xmlFree(key);
												key = NULL;
											}
											else {
												DBG( "unlock is null");
												ret = NET_NFC_NO_DATA_FOUND;
												goto ERROR;
											}

											key = xmlGetProp(pAidElement, (const xmlChar*)"power");
											if (key != NULL) {
												DBG("power : %s, ", (char *)key);
												if (strcasecmp((char*)key, "on") == 0) {
													power = 0x00;
												}
												else if (strcasecmp((char*)key, "off") == 0) {
													power = 0x01;
												}
												else if (strcasecmp((char*)key, "sleep") == 0) {
													power = 0x02;
												}
												else {
													ret = NET_NFC_NO_DATA_FOUND;
													goto ERROR;
												}
												xmlFree(key);
												key = NULL;
											}
											else {
												DBG("power is null");
												ret = NET_NFC_NO_DATA_FOUND;
												goto ERROR;
											}

											ret = net_nfc_client_se_add_route_aid_sync(pkgid, se_type, category, aid, unlock_required, power);
											DBG("net_nfc_client_se_add_route_aid_sync() result : [%d]", ret);

											free(aid);
											aid = NULL;
										}
									}
								}
							}
							else {
								DBG("category is null");
								ret = NET_NFC_NO_DATA_FOUND;
								goto ERROR;
							}
						}
						else {
							DBG("cannot find aid-group element : %s", (char*)pSubElement->name);
							ret = NET_NFC_NO_DATA_FOUND;
							goto ERROR;
						}
					}
				}
			}
			else {
				DBG("cannot find wallet element : %s", (char*)pCurrentElement->name);
				ret = NET_NFC_NO_DATA_FOUND;
			}
		}
	}

	xmlUnlinkNode(pRoot);
	xmlFreeNode(pRoot);
	xmlFreeDoc(pDocument);

	return ret;

ERROR:
	net_nfc_client_se_remove_package_aids_sync(pkgid);

	if (aid != NULL) {
		free(aid);
	}

	if (key != NULL) {
		xmlFree(key);
	}

	xmlUnlinkNode(pRoot);
	xmlFreeNode(pRoot);
	xmlFreeDoc(pDocument);

	return ret;
}

static void __build_full_path(const char *prefix, const char *tail,
	char *output, size_t out_len)
{
	size_t len;

	/* add tail slash */
	len = strlen(prefix);
	if (len > 0) {
		len = snprintf(output, out_len, "%s", prefix);
		if (len > 0 && len < out_len - 1 && output[len - 1] != '/') {
			output[len] = '/';
			output[len + 1] = '\0';
			len++;
		}
	}

	if (strlen(tail) > 0) {
		if (len > 0) {
			const char *buf2;

			if (tail[0] == '/') {
				buf2 = tail + 1;
			} else {
				buf2 = tail;
			}

			strncat(output + len, buf2, out_len - len - 1);
			output[out_len - 1] = '\0';
		} else {
			snprintf(output, out_len, "%s", tail);
		}
	}
}

static int __install(const char *pkgid, const char *appid, GList *md_list)
{
	GList *list;
	pkgmgrinfo_pkginfo_h handle = NULL;
	int ret;
	char *path = NULL;
	char buf[1024] = { 0, };
	metadata *detail;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != 0) {
		DBG("pkgmgrinfo_pkginfo_get_pkginfo() [%d]", ret);
		goto END;
	}

	ret = pkgmgrinfo_pkginfo_get_root_path(handle, &path);
	if (ret != 0) {
		DBG("pkgmgrinfo_pkginfo_get_root_path() [%d]", ret);
		goto END;
	}

	DBG("pkgid [%s]", pkgid);
	DBG("root path [%s]", path);

	//get xml path from metadata
	list = g_list_first(md_list);
	detail = (metadata*)list->data;
	DBG("key = %s, value = %s", detail->key, detail->value);

	/* add tail slash */
	__build_full_path(path, detail->value, buf, sizeof(buf));
	DBG("full path = %s", buf);

	ret = _nfc_register_aid(buf, pkgid);
	DBG("_nfc_register_aid() [%d]", ret);

END :
	if (!handle) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	return ret;
}

static int __uninstall(const char *pkgid, const char *appid, GList *md_list)
{
	int ret;

	ret = net_nfc_client_se_remove_package_aids_sync(pkgid);
	DBG("net_nfc_client_se_remove_route_aid_sync() [%d]", ret);

	return ret;
}

PKGMGR_MODULE_API
int PKGMGR_MDPARSER_PLUGIN_INSTALL(const char *pkgid, const char *appid, GList *md_list)
{
	int ret;

	DBG("PKGMGR_MDPARSER_PLUGIN_INSTALL called");

	ret = net_nfc_client_initialize();
	if (ret != 0) {
		DBG("net_nfc_client_initialize() [%d]", ret);
		return ret;
	}

	ret = __install(pkgid, appid, md_list);

	net_nfc_client_deinitialize();

	return ret;
}


PKGMGR_MODULE_API
int PKGMGR_MDPARSER_PLUGIN_UNINSTALL(const char *pkgid, const char *appid, GList *md_list)
{
	int ret;

	DBG("PKGMGR_MDPARSER_PLUGIN_UNINSTALL called");

	ret = net_nfc_client_initialize();
	if (ret != 0) {
		DBG("net_nfc_client_initialize() [%d]", ret);
		return ret;
	}

	ret = __uninstall(pkgid, appid, md_list);

	net_nfc_client_deinitialize();

	return ret;
}

PKGMGR_MODULE_API
int PKGMGR_MDPARSER_PLUGIN_UPGRADE(const char *pkgid, const char *appid, GList *list)
{
	int ret;

	DBG("PKGMGR_MDPARSER_PLUGIN_UPGRADE called");

	ret = net_nfc_client_initialize();
	if (ret != 0) {
		DBG("net_nfc_client_initialize() [%d]", ret);
		return ret;
	}

	ret = __uninstall(pkgid, appid, list);
	if (ret != 0) {
		DBG("__uninstall() [%d]", ret);
	} else {
		DBG("__uninstall() success");
	}

	ret = __install(pkgid, appid, list);
	if (ret != 0) {
		DBG("__install() [%d]", ret);
	} else {
		DBG("__install() success");
	}

	net_nfc_client_deinitialize();

	return ret;
}
