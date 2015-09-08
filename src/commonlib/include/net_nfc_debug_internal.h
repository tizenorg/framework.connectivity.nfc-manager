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
#ifndef __NET_NFC_DEBUG_INTERNAL_H__
#define __NET_NFC_DEBUG_INTERNAL_H__

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <libgen.h>

// below define should define before dlog.h
#define LOG_SERVER_TAG "NET_NFC_MANAGER"
#define LOG_CLIENT_TAG "NET_NFC_CLIENT"

#include <dlog.h>

#define LOG_COLOR_RED		"\033[0;31m"
#define LOG_COLOR_GREEN		"\033[0;32m"
#define LOG_COLOR_BROWN		"\033[0;33m"
#define LOG_COLOR_BLUE		"\033[0;34m"
#define LOG_COLOR_PURPLE	"\033[0;35m"
#define LOG_COLOR_CYAN		"\033[0;36m"
#define LOG_COLOR_LIGHTBLUE	"\033[0;37m"
#define LOG_COLOR_END		"\033[0;m"

/* nfc_log_to_file */
extern FILE *nfc_log_file;
#define NFC_DLOG_FILE "/opt/usr/share/nfc_debug/nfc_mgr_dlog.txt"

/* tag */
const char *net_nfc_get_log_tag();

#define NFC_LOGD(format, arg...) LOG(LOG_DEBUG, net_nfc_get_log_tag(), format, ##arg)
#define NFC_LOGI(format, arg...) LOG(LOG_INFO, net_nfc_get_log_tag(), format, ##arg)
#define NFC_LOGW(format, arg...) LOG(LOG_WARN, net_nfc_get_log_tag(), format, ##arg)
#define NFC_LOGE(format, arg...) LOG(LOG_ERROR, net_nfc_get_log_tag(), format, ##arg)

#define DEBUG_MSG_PRINT_BUFFER(buffer, length) \
	do { \
		int i = 0, offset = 0; \
		char temp_buffer[4096] = { 0, }; \
		NFC_LOGD(LOG_COLOR_BLUE "BUFFER [%d] = {" LOG_COLOR_END, length); \
		for(; i < length && offset < sizeof(temp_buffer); i++) \
		{ \
			offset += snprintf(temp_buffer + offset, sizeof(temp_buffer) - offset, " %02x", buffer[i]); \
			if (i % 16 == 15) \
			{ \
				NFC_LOGD(LOG_COLOR_BLUE "\t%s" LOG_COLOR_END, temp_buffer); \
				offset = 0; \
			} \
		} \
		NFC_LOGD(LOG_COLOR_BLUE "\t%s" LOG_COLOR_END, temp_buffer); \
		NFC_LOGD(LOG_COLOR_BLUE "}" LOG_COLOR_END); \
	} while(0)

#define DEBUG_MSG_PRINT_BUFFER_CHAR(buffer, length) \
	do { \
		int i = 0, offset = 0; \
		char temp_buffer[4096] = { 0, }; \
		NFC_LOGD(LOG_COLOR_BLUE "BUFFER [%d] = {" LOG_COLOR_END, length); \
		for(; i < length && offset < sizeof(temp_buffer); i++) \
		{ \
			offset += snprintf(temp_buffer + offset, sizeof(temp_buffer) - offset, " %c", buffer[i]); \
			if (i % 16 == 15) \
			{ \
				NFC_LOGD(LOG_COLOR_BLUE "\t%s" LOG_COLOR_END, temp_buffer); \
				offset = 0; \
			} \
		} \
		NFC_LOGD(LOG_COLOR_BLUE "\t%s" LOG_COLOR_END, temp_buffer); \
		NFC_LOGD(LOG_COLOR_BLUE "}" LOG_COLOR_END); \
	} while(0)

#define DEBUG_MSG(format, args...) \
	do { \
		NFC_LOGD(format, ##args); \
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[D][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define DEBUG_ADDON_MSG(format, args...) \
	do { \
		NFC_LOGD(LOG_COLOR_BLUE format LOG_COLOR_END, ##args); \
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[D][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define DEBUG_SERVER_MSG(format, args...) \
	do {\
		NFC_LOGD(LOG_COLOR_PURPLE format LOG_COLOR_END, ##args);\
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[S][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define DEBUG_CLIENT_MSG(format, args...) \
	do {\
		NFC_LOGD(LOG_COLOR_CYAN format LOG_COLOR_END, ##args); \
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[C][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define DEBUG_ERR_MSG(format, args...) \
	do {\
		NFC_LOGE(LOG_COLOR_RED format LOG_COLOR_END, ##args);\
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[E][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define INFO_MSG(format, args...) \
	do {\
		NFC_LOGI(LOG_COLOR_GREEN format LOG_COLOR_END, ##args);\
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[I][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define WARN_MSG(format, args...) \
	do {\
		NFC_LOGW(LOG_COLOR_BROWN format LOG_COLOR_END, ##args);\
		if (nfc_log_file) \
		{ \
			struct tm *local_tm; \
			char timeBuf[50]; \
			time_t rawtime;   time (&rawtime); \
			local_tm = localtime(&rawtime); \
			if(local_tm != NULL) { \
				strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm); \
				fprintf(nfc_log_file, "\n%s",timeBuf); \
				fprintf(nfc_log_file, "[W][%s:%d] "format"",__func__, __LINE__,  ##args); \
				fflush(nfc_log_file);\
			} \
		}\
	} while(0)

#define PROFILING(str) \
	do{ \
		struct timeval mytime;\
		char buf[128]; = {0};\
		memset(buf, 0x00, 128);\
		gettimeofday(&mytime, NULL);\
		char time_string[128] = {0,};\
		sprintf(time_string, "%d.%4d", mytime.tv_sec, mytime.tv_usec);\
		NFC_LOGD(str); \
		NFC_LOGD("\t time = [%s]", time_string);\
	} while(0)

#endif //__NET_NFC_DEBUG_INTERNAL_H__
