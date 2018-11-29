#ifndef LIBSENC_LOGGER_H_
#define LIBSENC_LOGGER_H_

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "senc_assist.h"

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>
#elif defined (linux) || defined (__linux__)
//#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#endif

#ifdef __GNUC__
#define __inline static inline
#define LOCAL_THREAD __thread
#elif __STDC_VERSION__ >= 201112L
#define LOCAL_THREAD __Thread_local
#elif defined(_MSC_VER)
#define LOCAL_THREAD __declspec(thread)
#else
# error Cannot define LOCAL_THREAD
#endif

#define DIRECTORY_PATH_LENGTH    100    // 目录字符串长度
#define CTEMPORARY_MESSAGE_BUFFER_LENGTH    2560    // 临时消息存储区

#define SENC_LOG_DIRECTORYNAME    "logs"    
#define SENC_LOG_FILENAME    "\\libsenc_log"
#define SENC_LOG_FILENAME_EXTEND ".log"

#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
#define SENC_LOG(a,b,c,...)	_snprintf_s(a,b,b,c,...)
#define ITOA	_itoa_s
#define STRCAT(a,b,c)	strcat_s(a,b,c)
#define IOLPTR	int
#elif defined (linux) || defined (__linux__)
#define SENC_LOG	snprintf
#define MAX_PATH 260
#define  ITOA	itoa_s
#define STRCAT(a,b,c)	strcat(a,c)
#define IOLPTR	long
#endif


#define SENC_LOG_STR_NORMAL    "Normal"
#define SENC_LOG_STR_WARNING    "Warning"
#define SENC_LOG_STR_ERROR    "Error"

#define SENC_LOG_LEVEL_NORMAL   0x01    // 记录正常（normal）信息
#define SENC_LOG_LEVEL_WARNING  0x02    // 记录警告（warning）信息
#define SENC_LOG_LEVEL_ERROR    0x04    // 记录错误（error）信息

#define SENC_LOG_PARAM_NORMAL    0x01    // 正常信息参数
#define SENC_LOG_PARAM_WARNING    0x02    // 警告信息参数 
#define SENC_LOG_PARAM_ERROR    0x04    // 错误信息参数


// #define  LOG_SWITCH_ON

#ifdef LOG_SWITCH_ON  //LOG_SWITCH_ON
void Log_GenerateLogInfo();
void Log_NormalMsg(const SINT8* pcMsg);
void Log_IndefinitedMsg(SUINT32 iWitch, const SINT8* cTag, SINT8* cFile, SINT32 iLine, SINT8* pcParam, ...);
void Log_CommData(const SINT8* pcTag, const SUINT8* pcMsg, SINT32 iLen);
#else   //LOG_SWITCH_OFF
#define Log_GenerateLogInfo()
#define Log_NormalMsg(a);
__inline void Log_IndefinitedMsg(SUINT32 iWitch, const SINT8* cTag, SINT8* cFile, SINT32 iLine, SINT8* pcParam, ...){}
#define Log_CommData(a,b,c);
#endif   //LOG_SWITCH_ON

#endif   //LIBSENC_LOGGER_H_

