#include "senc_logger.h"
#include "libsenc.h"
#include "senc_assist.h"
// #include <stdint.h>

#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
#include <ShlObj.h>
#endif

LOCAL_THREAD SINT32 g_LogLevel=7;
LOCAL_THREAD SINT32 g_LogGenerated=1;
LOCAL_THREAD SINT32 g_LogParamLevel=7;

LOCAL_THREAD SINT8 g_IsSetLogDirectory = 0;
LOCAL_THREAD SINT8 g_LogUserSetDirectoryPath[DIRECTORY_PATH_LENGTH];
LOCAL_THREAD SINT8 g_LogDirectoryPath[DIRECTORY_PATH_LENGTH];
LOCAL_THREAD SINT8 g_LogFileName[DIRECTORY_PATH_LENGTH];
LOCAL_THREAD FILE* g_pFile;
LOCAL_THREAD SINT8 g_LogMutex=1;

LOCAL_THREAD time_t stTime;
LOCAL_THREAD SINT8 TempMsgBuf[CTEMPORARY_MESSAGE_BUFFER_LENGTH];



#if defined (linux) || defined (__linux__)
int GetModuleFileName(char* sModuleName, char* sFileName, int nSize){
	int ret = -1;
	char sLine[1024]={0};
	void* pSymbol = (void*)"";
	FILE* fp;
	char* pPath;

	fp = fopen ("/proc/self/maps", "r");
	if(fp){
		while(!feof(fp)){
			unsigned long st, ed;
			if(!fgets(sLine,sizeof(sLine),fp))
				continue;
			if(!strstr(sLine," r-xp ")||!strchr(sLine, '/'))
				continue;
			sscanf(sLine,"%lx-%lx ", &st, &ed);
			if(pSymbol >= (void*)st && pSymbol < (void*) ed){
				char *tmp;
// 				size_t len;
				pPath = strchr(sLine, '/');
				tmp = strchr( pPath, '\n');
				if(tmp) *tmp = 0;

				ret = 0;
				strcpy(sFileName, pPath);
			}
		}
		fclose(fp);
	}
	return ret;
}

void itoa_s(int sInt, char* tarStr, size_t tarStrLen, int Radix){
	switch (Radix)
	{
	case 10:
		snprintf(tarStr,tarStrLen,"%d",sInt);
		break;
	case 16:
		snprintf(tarStr,tarStrLen,"%x",sInt);
		break;
	default:
		printf("Not Supported!");
		return;
	}
}
#endif


void Log_GetDirectoryName(){
	time_t ctime=time(0);
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
	struct tm tms;
	localtime_s(&tms,&ctime);
	memset(g_LogDirectoryPath, 0, DIRECTORY_PATH_LENGTH);
	if (g_IsSetLogDirectory == 1)
		strcpy(g_LogDirectoryPath,g_LogUserSetDirectoryPath);
	_snprintf_s(g_LogDirectoryPath,sizeof(g_LogDirectoryPath),sizeof(g_LogDirectoryPath),"%s_%d_%d_%d",SENC_LOG_DIRECTORYNAME,tms.tm_year+1900,tms.tm_mon+1,tms.tm_mday);
#elif defined (linux) || defined (__linux__)
	struct tm tms=*localtime(&ctime);
	memset(g_LogDirectoryPath,0,DIRECTORY_PATH_LENGTH);
	if (g_IsSetLogDirectory == 1)
		strcpy(g_LogDirectoryPath, g_LogUserSetDirectoryPath);
	snprintf(g_LogDirectoryPath,sizeof(g_LogDirectoryPath),"%s_%d_%d_%d",SENC_LOG_DIRECTORYNAME,tms.tm_year+1900,tms.tm_mon+1,tms.tm_mday);
#endif
}

void Log_GetFileName(){
	time_t ctime=time(0);
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
	SUINT32 uiProcessId=GetCurrentProcessId();
	SUINT32 uiThreadId=GetCurrentThreadId();
	struct tm tms;
	localtime_s(&tms,&ctime);
	_snprintf_s(g_LogFileName,sizeof(g_LogFileName),sizeof(g_LogFileName),"%s%s_%d_%d_%d_%d_%d%s",g_LogDirectoryPath,
		SENC_LOG_FILENAME,tms.tm_hour,tms.tm_min,tms.tm_sec,uiProcessId,uiThreadId,SENC_LOG_FILENAME_EXTEND);
#elif defined (linux) || defined (__linux__)
	SUINT32 uiProcessId=::getpid();
	SUINT32 uiThreadId=pthread_self();
	struct tm tms=*localtime(&ctime);
	snprintf(g_LogFileName,sizeof(g_LogFileName),"%s%s_%d_%d_%d_%d_%d%s",g_LogDirectoryPath,
		SENC_LOG_FILENAME,tms.tm_hour,tms.tm_min,tms.tm_sec,uiProcessId,uiThreadId,SENC_LOG_FILENAME_EXTEND);
#endif
}

void Log_CreateFile(){
	Log_GetFileName();
	if(g_LogFileName[0]!='0'){
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
		fopen_s(&g_pFile,g_LogFileName,"a");
#elif defined (linux) || defined (__linux__)
		g_pFile=fopen(g_LogFileName,"a");
#endif
	}
}

void Log_CreateDirectory(){
	Log_GetDirectoryName();
	if(g_LogDirectoryPath[0]!='0'){
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
		if(0==CreateDirectory(g_LogDirectoryPath,NULL)){
			int ierr = GetLastError();
			if(ierr != ERROR_ALREADY_EXISTS){
				TCHAR szPath[MAX_PATH];
				if(SUCCEEDED(SHGetSpecialFolderPath(NULL,szPath,CSIDL_DESKTOP,TRUE))){
					time_t ctime=time(0);
					struct tm tms;
					localtime_s(&tms,&ctime);
					_snprintf_s(g_LogDirectoryPath,sizeof(g_LogDirectoryPath),sizeof(g_LogDirectoryPath),"%s%s%s_%d_%d_%d",szPath,"\\",SENC_LOG_DIRECTORYNAME,tms.tm_year+1900,tms.tm_mon+1,tms.tm_mday);
					if(0==CreateDirectory(g_LogDirectoryPath,NULL)){
						int ierr=GetLastError();
						if(ierr!=ERROR_ALREADY_EXISTS){
							memset(g_LogDirectoryPath,0,DIRECTORY_PATH_LENGTH);
							return;
						}
					}
				}
			}
		}
#elif defined (linux) || defined (__linux__)
		mkdir(g_LogDirectoryPath,S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
#endif
	}
}

void Log_WriteTitle2File(){
	if (g_pFile)
	{
		SINT8 cModuleName[MAX_PATH] = {0};
		SINT8 cTemp[100] = {0};
		GetModuleFileName(NULL,cModuleName,MAX_PATH);
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
		_snprintf_s(cTemp,sizeof(cTemp),sizeof(cTemp),"Application Name: %s",cModuleName);
		fwrite(cTemp,strlen(cTemp),1,g_pFile);

		_snprintf_s(cTemp,sizeof(cTemp),sizeof(cTemp),"  LibsencVersion: %s",LIBSENC_VERSION);
		fwrite(cTemp,strlen(cTemp),1,g_pFile);
#elif defined (linux) || defined (__linux__)
		snprintf(cTemp,sizeof(cTemp),"Application Name: %s",cModuleName);
		fwrite(cTemp,strlen(cTemp),1,g_pFile);

		snprintf(cTemp,sizeof(cTemp),"  LibsencVersion: %s",LIBSENC_VERSION);
		fwrite(cTemp,strlen(cTemp),1,g_pFile);

#endif
		fwrite("\r\n",2,1,g_pFile);
	}
}

void Log_WriteTime2File(){
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
	SYSTEMTIME sTime = {0};
	if(g_pFile){
		GetLocalTime(&sTime);
		memset(TempMsgBuf,0,CTEMPORARY_MESSAGE_BUFFER_LENGTH);
		_snprintf_s(TempMsgBuf,sizeof(TempMsgBuf),sizeof(TempMsgBuf),"%d-%d-%d %d:%d:%d:%3d     ", sTime.wYear,sTime.wMonth,
			sTime.wDay,sTime.wHour,sTime.wMinute,sTime.wSecond,sTime.wMilliseconds);
		fwrite(TempMsgBuf,strlen(TempMsgBuf)-1,1,g_pFile);
	}

#elif defined (linux) || defined (__linux__)
	time_t cTime = time(0);
	struct tm tms=*localtime(&cTime);
	if(g_pFile){
		memset(TempMsgBuf,0,CTEMPORARY_MESSAGE_BUFFER_LENGTH);
		snprintf(TempMsgBuf,sizeof(TempMsgBuf),"%d-%d-%d %d:%d:%d     ", tms.tm_year+1900,tms.tm_mon+1,tms.tm_mday,
			tms.tm_hour,tms.tm_min,tms.tm_sec);
		fwrite(TempMsgBuf,strlen(TempMsgBuf)-1,1,g_pFile);
	}

#endif
}

void Log_WriteTag2File(const SINT8* pcTag){
	if(g_pFile){
		memset(TempMsgBuf,0,CTEMPORARY_MESSAGE_BUFFER_LENGTH);
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
		_snprintf_s(TempMsgBuf,sizeof(TempMsgBuf),sizeof(TempMsgBuf),"%45s",pcTag);
#elif defined (linux) || defined (__linux__)
		snprintf(TempMsgBuf,sizeof(TempMsgBuf),"%45s",pcTag);
#endif
		fwrite(TempMsgBuf,strlen(TempMsgBuf),1,g_pFile);
		fwrite("    ",4,1,g_pFile);
	}
}

void Log_WriteTag2FileS(const SINT8* pcTag){
	if(g_pFile){
		memset(TempMsgBuf,0,CTEMPORARY_MESSAGE_BUFFER_LENGTH);
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
		_snprintf_s(TempMsgBuf,sizeof(TempMsgBuf),sizeof(TempMsgBuf),"%10s",pcTag);
#elif defined (linux) || defined (__linux__)
		snprintf(TempMsgBuf,sizeof(TempMsgBuf),"%10s",pcTag);
#endif
		fwrite(TempMsgBuf,strlen(TempMsgBuf),1,g_pFile);
		fwrite("    ",4,1,g_pFile);
	}
}

void Log_WriteMsg2File(const SINT8* pcMsg){
	if(g_pFile){
		fwrite(pcMsg,strlen(pcMsg),1,g_pFile);
		fwrite("    ",4,1,g_pFile);
	}
}

void Log_WriteEnd2File(){
	if(g_pFile){
		fwrite("\r\n",2,1,g_pFile);
	}
}
#ifdef LOG_SWITCH_ON
void Log_GenerateLogInfo(){
	if(g_LogMutex==1){
		Log_CreateDirectory();
		Log_CreateFile();
		Log_WriteTitle2File();

		g_LogMutex=0;
	}
}

void Log_NormalMsg(const SINT8* pcMsg){
	if(!g_LogGenerated){
		return;
	}
	if(SENC_LOG_LEVEL_NORMAL==(g_LogLevel&SENC_LOG_LEVEL_NORMAL)){
		Log_WriteTime2File();
		Log_WriteTag2FileS((char*)SENC_LOG_STR_NORMAL);
		Log_WriteTag2File(pcMsg);
		Log_WriteEnd2File();
	}
}

void Log_IndefinitedMsg(SUINT32 iWitch, const SINT8* cTag, SINT8* cFile, SINT32 iLine, SINT8* pcParam, ...){
	SINT32 iLen=0;
// 	SINT32 i=0;
	SINT32 cTemp[10];
	va_list argptr;
	SUINT32 ParamGenerated=0;
	va_start(argptr,pcParam);

	if((0==g_LogGenerated)||(0==(g_LogLevel&iWitch))){
		return;
	}

	Log_WriteTime2File();
	switch (iWitch)
	{
	case SENC_LOG_LEVEL_NORMAL:
		Log_WriteTag2FileS((char*)SENC_LOG_STR_NORMAL);
		break;
	case SENC_LOG_LEVEL_WARNING:
		Log_WriteTag2FileS((char*)SENC_LOG_STR_WARNING);
		break;
	case SENC_LOG_LEVEL_ERROR:
		Log_WriteTag2FileS((char*)SENC_LOG_STR_ERROR);
		break;
	default:
		return;
	}
	Log_WriteTag2File(cTag);

	memset(TempMsgBuf,0,CTEMPORARY_MESSAGE_BUFFER_LENGTH);
	memset(cTemp,0,10);
	if(iWitch==SENC_LOG_LEVEL_NORMAL&&(SENC_LOG_PARAM_NORMAL==(g_LogParamLevel&SENC_LOG_PARAM_NORMAL))){
		ParamGenerated=1;
	}else if(iWitch==SENC_LOG_LEVEL_WARNING&&(SENC_LOG_PARAM_WARNING==(g_LogParamLevel&SENC_LOG_PARAM_WARNING))){
		ParamGenerated=1;
	}else if(iWitch==SENC_LOG_LEVEL_ERROR&&(SENC_LOG_PARAM_ERROR==(g_LogParamLevel&SENC_LOG_PARAM_ERROR))){
		ParamGenerated=1;
	}

	if(ParamGenerated){
		iLen=strlen(pcParam);
		for(int i=0;i<iLen;i++){
			if(pcParam[i]=='1'){
				int iParam=va_arg(argptr,int);
				ITOA(iParam,(char*)TempMsgBuf,sizeof(TempMsgBuf),16);
				STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"0x");
				STRCAT(TempMsgBuf,sizeof(TempMsgBuf),(char*)cTemp);
			}else if(pcParam[i]=='2'){
				int iParam=va_arg(argptr,unsigned int);
				STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"0x");
				ITOA(iParam,(char*)cTemp,sizeof(cTemp),16);
				STRCAT(TempMsgBuf,sizeof(TempMsgBuf),(char*)cTemp);
			}else if(pcParam[i]=='3'){
				char * iParam=va_arg(argptr,char*);
				if(iParam){
					if(strlen(iParam)>=sizeof(TempMsgBuf)){
						STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"Message is Too Long!");
					}else{
						STRCAT(TempMsgBuf,sizeof(TempMsgBuf),iParam);
					}
				}else{
					STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"Null");
				}
			}else if(pcParam[i]=='4'){
				unsigned char * iParam=va_arg(argptr,unsigned char*);
				if(iParam){
					if(strlen((char*)iParam)>=sizeof(TempMsgBuf)){
						STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"Message is Too Long!");
					}else{
						STRCAT(TempMsgBuf,sizeof(TempMsgBuf),(char*)iParam);
					}
				}else{
					STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"Null");
				}
			}else if(pcParam[i]=='5'){
				IOLPTR iParam=(IOLPTR)(va_arg(argptr,void*));
				if(iParam){
					ITOA(iParam,(char*)cTemp,sizeof(cTemp),16);
					STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"0x");
					STRCAT(TempMsgBuf,sizeof(TempMsgBuf),(char*)cTemp);
				}else{
					STRCAT(TempMsgBuf,sizeof(TempMsgBuf),"Null");
				}
			}else if(pcParam[i]=='6'){

			}else{
				continue;
			}
			STRCAT(TempMsgBuf,sizeof(TempMsgBuf)," ");
		}
		va_end(argptr);
		Log_WriteMsg2File(TempMsgBuf);
		Log_WriteMsg2File(cFile);
		ITOA(iLine,(char*)cTemp,sizeof(cTemp),10);
		Log_WriteMsg2File((char*)cTemp);
	}

	Log_WriteEnd2File();
}

void Log_CommData(const SINT8* pcTag, const SUINT8* pcMsg, SINT32 iLen){
	SINT32 iloop=0;
	SINT8 acTemp[10]={0};

	if((!g_LogGenerated)||(SENC_LOG_LEVEL_NORMAL!=(g_LogLevel&SENC_LOG_LEVEL_NORMAL))){
		return;
	}

	Log_WriteTime2File();
	Log_WriteTag2FileS((char*)SENC_LOG_STR_NORMAL);
	Log_WriteTag2File(pcTag);

	ITOA(iLen,acTemp,sizeof(acTemp),10);
	Log_WriteMsg2File(acTemp);
	Log_WriteMsg2File((char*)"bytes transported.");

	memset(TempMsgBuf,0,CTEMPORARY_MESSAGE_BUFFER_LENGTH);
	for(iloop=0;iloop<iLen;iloop++){
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
		_snprintf_s(acTemp,sizeof(acTemp),sizeof(acTemp),"%02X", pcMsg[iloop]);
#elif defined (linux) || defined (__linux__)
		snprintf(acTemp,sizeof(acTemp),"%02X", pcMsg[iloop]);
#endif
		fwrite(acTemp,2,1,g_pFile);
	}
	Log_WriteEnd2File();
}
#endif

void SENC_SetLogDirectory(char *log_path)
{
	if (log_path == NULL || strlen(log_path) == 0)
		return;
	memset(g_LogUserSetDirectoryPath, 0, DIRECTORY_PATH_LENGTH);
	strcpy(g_LogUserSetDirectoryPath, log_path);
	g_IsSetLogDirectory = 1;
}