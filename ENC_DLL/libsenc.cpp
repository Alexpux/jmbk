#include "libsenc.h"
#include "senc_usbapi.h"
#include "senc_cmd_frame.h"
#include "senc_diffiehellman.h"
#include "senc_aes.h"
#include "senc_rsa.h"
#include "senc_dongleapi.h"
#include "senc_assist.h"
#include "openssl_locker.h"
#include "senc_serialport.h"
#include "PtrConverter.h"
#include "senc_error.h"
#include "senc_logger.h"


#if defined(linux) || defined(__linux__)
#include <string.h>
#include <stdlib.h>
const char *LIB_INFO=LIBSENC_VERSION_STR;
#endif

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#define SENC_INT unsigned int
#define SENC_API
#elif defined(linux) || defined(__linux__)
#define SENC_INT unsigned long
#define SENC_API extern "C" 
#endif



#if defined (linux) || defined (__linux__)
#include <unistd.h>

void __attribute__ ((constructor)) load_point(void);
void __attribute__ ((destructor)) unload_point(void);

void load_point(void)
{
	Log_GenerateLogInfo();
	init_openssl_locker();
}

void unload_point(void)
{
	fini_openssl_locker();
}

#elif defined(_WIN32) || defined(WIN32) || defined(_WIN64)
BOOL APIENTRY DllMain( HANDLE hModule, 
					  DWORD  ul_reason_for_call, 
					  LPVOID lpReserved
					  )

{
	SENCryptCard sencDev;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{			
			sencDev.OpenSign = FALSE;
			Log_GenerateLogInfo();
			init_openssl_locker();
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		{
			sencDev.OpenSign = FALSE;
			fini_openssl_locker();
		}
		break;
	}
	return TRUE;
}
#endif

const unsigned char u8rsaSHA1Der[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };

const unsigned char u8rsaSHA256Der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 
	0x00, 0x04, 0x20 };



SENC_API unsigned int SENC_GetDevList(SENCryptCardList OUT *SencDevsList){

	unsigned int uiRet=0;

	if(!SencDevsList) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_GetDevList: Parameter Null"); 	

	if(SencDevsList->InitFlag!=0xFFFF)
		return ERROR_LOG(SENC_ERROR_DEVICE_LIST_NOT_INITIALIZED,"SENC_GetDevList: List Not Init"); 

	for(int i=0;i<64;i++){
		memset(SencDevsList->devs[i],-1,sizeof(CardInfo));
	}
	uiRet=USB_GetDevList(SencDevsList);
	return uiRet;
}

SENC_API unsigned int SENC_NewDevList(SENCryptCardList IN *SencDevsList){

	unsigned int uiRet=0;

	if(!SencDevsList) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_NewDevList: Parameter Null"); 

	if(SencDevsList->InitFlag==0xFFFF){
		uiRet=SENC_FreeDevList(SencDevsList);
		if(uiRet!=SENC_SUCCESS)
			return uiRet;
	}

	for(int i=0;i<64;i++){
		SencDevsList->devs[i]=(CardInfo*)malloc(sizeof(CardInfo));
		memset(SencDevsList->devs[i],-1,sizeof(CardInfo));
	}

	SencDevsList->DevNums=-1;
	SencDevsList->ctx=NULL;

	SencDevsList->InitFlag=0xFFFF;

	RandSeed();

	uiRet=USB_NewCtx(SencDevsList);

	return uiRet;
}



SENC_API unsigned int SENC_FreeDevList(SENCryptCardList IN *SencDevsList){

	unsigned int uiRet=0;

	if(!SencDevsList) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_FreeDevList: Parameter Null"); 
	if(SencDevsList->InitFlag!=0xFFFF)
		return ERROR_LOG(SENC_ERROR_DEVICE_LIST_NOT_INITIALIZED,"SENC_FreeDevList: List Not Init"); 

	for(int i=0;i<64;i++){
		free(SencDevsList->devs[i]);
	}
	uiRet=USB_FreeCtx(SencDevsList);
	if(uiRet != SENC_SUCCESS)
		return uiRet;

	SencDevsList->DevNums=-1;
	SencDevsList->ctx=NULL;
	SencDevsList->InitFlag=0;

	SencDevsList=NULL;

	return SENC_SUCCESS;
}




SENC_API unsigned int SENC_Open(CardInfo* SencDev,SENCHANDLE* OUT SencDevHandle){
	unsigned int uiRet=0;
	unsigned char CardState;
	SENCryptCard *pscSencDev;

	if(!SencDevHandle||!SencDev) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Open: Parameter Null"); 
	if(SencDev->Dev_Path[0]==-1)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Open: Device Not Found"); 
	// 	if(SencDev->OpenSign==TRUE)
	// 		return SENC_ERROR_DEVICE_OPENED;

	uiRet=sencdev_New(&pscSencDev);
	if(uiRet!=SENC_SUCCESS)
		return uiRet;

	for(int i=0;SencDev->Dev_Path[i]!=-1;i++){
		pscSencDev->Dev_Path[i]=SencDev->Dev_Path[i];
	}

	uiRet = USB_Open(pscSencDev);
	if(uiRet != SENC_SUCCESS)
		return uiRet;
	uiRet=SENC_CMD_EC_GetState(pscSencDev,&CardState);
	if(uiRet!=SENC_SUCCESS)
		return uiRet;
	if(CardState!=0x00){
		uiRet=SENC_DH_KeyExchange(pscSencDev);		//秘钥交换
		if(uiRet!=SENC_SUCCESS)
			return uiRet;
	}
	*SencDevHandle=Ptr2SencHandle(pscSencDev);

	return uiRet;
}


SENC_API unsigned int SENC_Close(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int uiRet=0;

	if(!SencDevHandle||!(SencDevHandle)) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Close: Device Not Found"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Close: Device Closed"); 

	uiRet = USB_Close(pstEncDev);
	if(uiRet != SENC_SUCCESS)
		return uiRet;
	pstEncDev->OpenSign=FALSE;

	// 	uiRet = sencdev_Free(&pstEncDev);

	// 	*SencDevHandle=NULL;

	return uiRet;
}

SENC_API unsigned int SENC_Free(SENCHANDLE* IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int uiRet=0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Free: Handle Null"); 

	pstEncDev = SencHandle2Ptr(*SencDevHandle);  //指针转换
	if(!pstEncDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Free: Device Not Found"); 
// 	if(pstEncDev->OpenSign==TRUE)
// 		return SENC_ERROR_DEVICE_OPENED;

	uiRet = sencdev_Free(pstEncDev);
	if(uiRet != SENC_SUCCESS)
		return uiRet;
	*SencDevHandle=NULL;

	return uiRet;
}

SENC_API unsigned int SENC_ResetByHandle(SENCHANDLE* IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int uiRet=0;
	int TargetPortNum;
	int tflag=2;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ResetByHandle: Handle Null"); 

	pstEncDev = SencHandle2Ptr(*SencDevHandle);  //指针转换
	if(!pstEncDev) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ResetByHandle: Device Not Found"); 

	if(!pstEncDev->dev_handle)
		return ERROR_LOG(SENC_ERROR_SERIAL_PORT_HANDLE_CLOSED,"SENC_ResetByHandle: Handle Closed");

	if(pstEncDev->Dev_Path[1]>0&&pstEncDev->Dev_Path[2]>0){		
		while(pstEncDev->Dev_Path[tflag]!=-1) tflag++;
		TargetPortNum=pstEncDev->Dev_Path[tflag-1]+(pstEncDev->Dev_Path[tflag-2]-1)*4;
	}else{
		TargetPortNum=pstEncDev->Dev_Path[0];
	}

	uiRet = SENC_COM_RESET(TargetPortNum,pstEncDev->Dev_Path[tflag-3]);
	if(uiRet != SENC_SUCCESS)
		return uiRet;

	uiRet = sencdev_Free(pstEncDev);
	if(uiRet != SENC_SUCCESS)
		return uiRet;
	*SencDevHandle=NULL;

	return uiRet;
}

SENC_API unsigned int SENC_ResetByPort(int IN TargetPortNumber, int IN CaseIndex){
	unsigned int uiRet=0;

	if(TargetPortNumber<1||TargetPortNumber>16) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_ResetByPort: Port Index Error"); 

	uiRet = SENC_COM_RESET(TargetPortNumber,CaseIndex);

	return uiRet;
}


// SENC_API unsigned int SENC_Init(SENCHANDLE IN SencDevHandle){
// 	SENCryptCard* pstEncDev=NULL;
// 	unsigned int uiRet=0;
// 
// 	if(!SencDevHandle||!(SencDevHandle)) 
// 		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,": Device Not Found"); 
// 
// 	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
// 	if(pstEncDev->OpenSign==FALSE)
// 		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,": Device Closed"); 
// 
// 	uiRet = sencdev_Init(pstEncDev);
// 	SencDevHandle=NULL;
// 
// 	return uiRet;
// }


// unsigned int SENC_Init(SENCHANDLE IN SencDevHandle){
// 	SENCryptCard* pstEncDev=NULL;
// 
// 	if(!SencDevHandle) 
// 		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,": Device Not Found"); 
// 
// 	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
// 	memset(pstEncDev->CommKey,0x00,sizeof(pstEncDev->CommKey));
// 	memset(pstEncDev->DHPrivKey,0x00,sizeof(pstEncDev->DHPrivKey));
// 	memset(pstEncDev->SessionKey,0x00,sizeof(pstEncDev->SessionKey));
// 
// 	return SENC_SUCCESS;
// }



//*函数：SENC_KeyExchange()
//*功能：秘钥交换接口|| exchange communication keys with EC card.
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//*日期：2016/11/10 by Wangjf
unsigned int SENC_KeyExchange(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KeyExchange: Handle Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  			//指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KeyExchange: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//*函数：SENC_EncryptCard_GetState()
//*功能：获取加密卡状态|| Inquire EC card state
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char*		OutEcState						//传出加密卡状态
//		unsigned int		OutEcStateLen					//状态buffer大小
//*日期：2016/11/10  by Wangjf
SENC_API unsigned int SENC_EncryptCard_GetState(SENCHANDLE IN SencDevHandle,
												unsigned char* OUT OutEcState,
												unsigned int* OUT OutEcStateLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_EncryptCard_GetState: Handle Null"); 
	if(!OutEcState||!OutEcStateLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_EncryptCard_GetState: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);					//指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_EncryptCard_GetState: Device Closed"); 

	ucRet=SENC_CMD_EC_GetState(pstEncDev,OutEcState);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*OutEcStateLen=1;

	return SENC_SUCCESS;
}

//*函数：SENC_EncryptCard_GetID()
//*功能：获取加密卡ID|| Inquire EC card ID
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char*		OutEncryptCardID				//传出加密卡ID
//		unsigned int		OutEncryptCardIDLen					//ID buffer大小
//*日期：2016/11/10  by Wangjf
unsigned int SENC_EncryptCard_GetID(SENCHANDLE IN SencDevHandle,
									unsigned char* OUT OutEncryptCardID,
									unsigned int* OUT OutEncryptCardIDLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_EncryptCard_GetID: Device Not Found"); 
	if(!OutEncryptCardID||!OutEncryptCardIDLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_EncryptCard_GetID: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);					//指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_EncryptCard_GetID: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_EC_GetID(pstEncDev,OutEncryptCardID);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*OutEncryptCardIDLen=8;

	return SENC_SUCCESS;
}

//*函数：SENC_EncryptCard_GetVersion()
//*功能：获取加密卡版本|| Inquire EC card version
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char*		OutEcHwVersion				//传出加密卡硬件版本
//		unsigned int*		OutEcHwVersionLen			//硬件版本 buffer大小
//		unsigned char*		OutEcFwVersion				//传出加密卡固件版本
//		unsigned int*		OutEcFwVersionLen			//固件版本 buffer大小
//*日期：2016/11/10  by Wangjf
unsigned int SENC_EncryptCard_GetVersion(SENCHANDLE IN SencDevHandle,
										 unsigned char* OUT OutEcHwVersion,
										 unsigned int* OUT OutEcHwVersionLen,
										 unsigned char* OUT OutEcFwVersion,
										 unsigned int* OUT OutEcFwVersionLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_EncryptCard_GetVersion: Device Not Found"); 
	if(!OutEcHwVersion||!OutEcFwVersion||!OutEcHwVersionLen||!OutEcFwVersionLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_EncryptCard_GetVersion: Parameter Error"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_EncryptCard_GetVersion: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_EC_GetVersion(pstEncDev,OutEcHwVersion,OutEcFwVersion);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*OutEcHwVersionLen=8;
	*OutEcFwVersionLen=8;

	return SENC_SUCCESS;
}

//*函数：SENC_Product_SetID()
//*功能：设置加密卡ID|| Set EC card ID
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char*		InEcId					//传入加密卡ID
//		unsigned int		InEcIdLen					//ID buffer大小
//*日期：2016/11/10  by Wangjf
unsigned int SENC_Product_SetID(SENCHANDLE IN SencDevHandle,
								unsigned char* IN InEcId,
								unsigned int IN InEcIdLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	
	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Product_SetID: Device Not Found"); 
	if(!InEcId)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Product_SetID: Parameter Error"); 
	if(InEcIdLen!=16)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_Product_SetID: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Product_SetID: Device Closed"); 

	ucRet=SENC_CMD_Product_SetCardId(pstEncDev,InEcId);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//*函数：SENC_Product_SetVersion()
//*功能：设置加密卡版本|| Set EC card version
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char*		InHwVersion				//传入加密卡硬件版本
//		unsigned int		InHwVersionLen			//硬件版本 buffer大小
//		unsigned char*		InFwVersion				//传入加密卡固件版本
//		unsigned int		InFwVersionLen			//固件版本 buffer大小
//*日期：2016/11/10  by Wangjf
unsigned int SENC_Product_SetVersion(SENCHANDLE IN SencDevHandle,
									 unsigned char* IN InHwVersion,
									 unsigned int IN InHwVersionLen, 
									 unsigned char* IN InFwVersion,
									 unsigned int IN InFwVersionLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Product_SetVersion: Device Not Found"); 
	if(!InHwVersion||!InFwVersion)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Product_SetVersion: Parameter Error"); 
	if(InHwVersionLen!=8||InFwVersionLen!=8)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_Product_SetVersion: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Product_SetVersion: Device Closed"); 

	ucRet=SENC_CMD_Product_SetCardVersion(pstEncDev,InHwVersion,InFwVersion);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//*函数：SENC_Product_GenerateFlashKey()
//*功能：生成Flash秘钥|| Generate Flash Key
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//*日期：2016/11/10  by Wangjf
unsigned int SENC_Product_GenerateFlashKey(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Product_GenerateFlashKey: Device Not Found"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Product_GenerateFlashKey: Device Closed"); 

	ucRet=SENC_CMD_Product_GenerateFlashKey(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//*函数：SENC_Product_SetDHAttributes()
//*功能：设置Diffie-Hellman秘钥交换参数P&G|| Set P and G for Diffie-Hellman key exchange
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char*		InP				//传入P
//		unsigned int		InPLen			//传入P buffer大小
//		unsigned char*		InG				//传入G
//		unsigned int		InGLen			//传入G buffer大小
//*日期：2016/11/10  by Wangjf
unsigned int SENC_Product_SetDHAttributes(SENCHANDLE IN SencDevHandle,
										  unsigned char* IN InP,
										  unsigned int IN InPLen,
										  unsigned char* IN InG,
										  unsigned int IN InGLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Product_SetDHAttributes: Device Not Found"); 
	if(!InP||!InG)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Product_SetDHAttributes: Parameter Error"); 
	if(InPLen!=4||InGLen!=1)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_Product_SetDHAttributes: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Product_SetDHAttributes: Device Closed"); 

	ucRet=SENC_CMD_Product_SetDHAttributes(pstEncDev,InP,InG);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

/************************************************
*函数：SENC_Product_SM2KeyGenerate()
*功能：生成板卡设备密钥对||  Generate Senc Card RSA Keys
*参数：
SENCHANDLE		IN		SencDevHandle	//设备handle
unsigned char	IN		InEncryptLength	//加密长度，固定为1字节
unsigned char	IN		RsaKeyIdx		//加密密钥索引，固定为1字节
*返回值：错误码，0为成功
*日期： 2018/11/1 by Zhang Tao
*备注：
************************************************/
unsigned int SENC_Product_SM2KeyGenerate(SENCHANDLE IN SencDevHandle,
										 unsigned char IN InEncryptLength,
										 unsigned char IN RsaKeyIdx)
{
	SENCryptCard* pstEncDev = NULL;
	unsigned int ucRet = 0;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_Product_SM2KeyGenerate: Device Not Found");
	if (RsaKeyIdx<1 || RsaKeyIdx>128)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_Product_SM2KeyGenerate: Parameter Index Error");
	if (InEncryptLength != 0x02)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_Product_SM2KeyGenerate: Parameter Type Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_Product_SM2KeyGenerate: Device Closed");

	//ucRet = SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	//if (ucRet != SENC_SUCCESS)
	//	return ucRet;

	ucRet = SENC_CMD_Product_SM2_Generate(pstEncDev, InEncryptLength, RsaKeyIdx);
	if (ucRet != SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

/************************************************
*函数：SENC_Product_RequestCSR()
*功能：向设备请求CSR||  Request CSR From Device
*参数：
SENCHANDLE		IN		SencDevHandle	//设备handle
unsigned int*	OUT		CsrLen			//返回CSR长度
unsigned char*	OUT		Csr				//返回CSR数据
*返回值：错误码，0为成功
*日期： 2018/11/1 by Zhang Tao
*备注：
************************************************/
unsigned int SENC_Product_RequestCSR(SENCHANDLE IN SencDevHandle,
									 unsigned int* OUT CsrLen,
									 unsigned char* OUT Csr)
{
	SENCryptCard* pstEncDev = NULL;
	unsigned int ucRet = 0;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_Product_RequestCSR: Device Not Found");
	if (!CsrLen || !Csr)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_Product_RequestCSR: Parameter Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_Product_RequestCSR: Device Closed");

	ucRet = SENC_CMD_Product_RequestCSR(pstEncDev, CsrLen, Csr);
	if (ucRet != SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

/************************************************
*函数：SENC_Product_DownLoadCert()
*功能：下载证书||  Download Certification
*参数：
SENCHANDLE		IN		SencDevHandle	//设备handle
uint8_t			IN		CertType		//证书类型，固定为1字节
unsigned int	IN		CertLen			//证书长度，固定为2字节
unsigned char*  IN      Cert			//证书内容
*返回值：错误码，0为成功
*日期： 2018/11/1 by Zhang Tao
*备注：
************************************************/
unsigned int SENC_Product_DownLoadCert(SENCHANDLE IN SencDevHandle,
									   uint8_t IN CertType,
									   unsigned int IN CertLen,
									   unsigned char* IN Cert)
{
	SENCryptCard* pstEncDev = NULL;
	unsigned int ucRet = 0;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_Product_DownLoadCert: Device Not Found");
	if (!Cert)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_Product_DownLoadCert: Parameter Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_Product_DownLoadCert: Device Closed");

	ucRet = SENC_CMD_Product_DownLoadCert(pstEncDev, CertType, CertLen, Cert);
	if (ucRet != SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//*函数：SENC_Product_SetDefaultState()
//*功能：设为出厂状态|| Set EC card to default state
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//*日期：2016/11/10  by Wangjf
unsigned int SENC_Product_SetDefaultState(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Product_SetDefaultState: Device Not Found"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Product_SetDefaultState: Device Closed"); 

	ucRet=SENC_CMD_Product_SetDefault(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	// 	pstEncDev->CardState=SENC_EC_STATE_DEFAULT;

	return SENC_SUCCESS;
}

//*函数：SENC_RSA_PrivkeySignatureExternal()
//*功能：RSA签名|| Signature by RSA encryption
//*参数：SENCHANDLE*			SencDevHandle				//加密卡设备handle
//		EncryptAttr*		inEncAttr						//传入秘钥参数
//		unsigned char*		IV								//RSA私钥加密初始向量
//		unsigned int		IVlen							//RSA私钥加密初始向量 buffer大小 16 bytes
//		unsigned char*		MAC								//RSA私钥加密mac
//		unsigned int		MAClen							//RSA私钥加密mac buffer大小 16 bytes
//		unsigned char*		RsaPrivKeyData					//RSA私钥数据
//		unsigned int		RsaPrivKeyDataLen				//RSA私钥数据 buffer大小 1412 bytes
//		unsigned char*		inData							//待签名数据
//		unsigned int		inDataLen						//待签名数据 buffer大小 256 bytes
//		unsigned char*		retSignedData					//签名返回数据
//		unsigned int*		retSignedDataLen				//签名返回数据长度
//*日期：2016/11/01
//by Wangjf
SENC_API unsigned int SENC_RSA_PrivkeySignatureExternal(SENCHANDLE IN SencDevHandle,
														EncryptAttr* IN inEncAttr,
														unsigned char* IN IV,
														unsigned int IN	IVlen,
														unsigned char* IN MAC,
														unsigned int IN MACLen,
														unsigned char* IN RsaPrivKeyData,
														unsigned int IN RsaPrivKeyDataLen,
														unsigned char* IN inData,
														unsigned int IN inDataLen,
														unsigned char* OUT retSignedData,
														unsigned int* OUT retSignedDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char hash_buf[MAX_HASH_SHA_SIZE] = {0};
	unsigned int hash_len = 0;
	unsigned char temp_buf[MAX_RSA_PADDING_SIZE] = {0};
	unsigned int temp_len = 2048 >> 3;
	unsigned char dhash_buf[MAX_RSA_SHA_DER_SIZE] = {0};
	unsigned int dhash_len = sizeof(dhash_buf);
	const unsigned char *p_hash_header = NULL;
	unsigned char emptyiv[16]={0};
	unsigned int pkcsret=0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PrivkeySignatureExternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_PrikeyEncMode<0x01||inEncAttr->RSA_PrikeyEncMode>0x03)
		||(inEncAttr->RSA_PrikeyEncIdx<1||inEncAttr->RSA_PrikeyEncIdx>64)
		||(inEncAttr->RSA_HashAlgorithm<1||inEncAttr->RSA_HashAlgorithm>2)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PrivkeySignatureExternal: EncAttr Error");
	if(!RsaPrivKeyData||!inData||!retSignedData||!retSignedDataLen||!MAC)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PrivkeySignatureExternal: Parameter Null"); 
	if(RsaPrivKeyDataLen!=SENC_RSA_PRIVATE_KEY_LENGTH||MACLen!=SENC_ENC_MAC_LENGTH||(IV&&IVlen!=SENC_ENC_IV_LENGTH)||(!IV&&IVlen!=0))//||inDataLen>256
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PrivkeySignatureExternal: Parameter Length Error");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_RSA_PrivkeySignatureExternal: Device Closed"); 

	//hash data
	if(inEncAttr->RSA_HashAlgorithm==HASH_SHA1){
		sha1(inData,inDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA1Der;
		dhash_len=sizeof(u8rsaSHA1Der);
	}else if(inEncAttr->RSA_HashAlgorithm==HASH_SHA256){
		sha256(inData,inDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA256Der;
		dhash_len=sizeof(u8rsaSHA256Der);
	}
	memcpy(dhash_buf,p_hash_header,dhash_len);
	memcpy(dhash_buf+dhash_len,hash_buf,hash_len);
	dhash_len+=hash_len;

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_encode(PKCS_1_V1_5_EMSA, dhash_buf,dhash_len,temp_buf,temp_len);
		if(pkcsret){
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_ENCODE|((pkcsret&0xf)<<12),"SENC_RSA_PrivkeySignatureExternal: PKCS Encode Error"); 
		}

	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(temp_buf,dhash_buf,dhash_len);
	}

	//签名
	if(IV!=NULL){
		ucRet=SENC_CMD_RSA_Signature_External(pstEncDev,inEncAttr,IV,MAC,RsaPrivKeyData,temp_buf,retSignedData);
	}else{
		ucRet=SENC_CMD_RSA_Signature_External(pstEncDev,inEncAttr,emptyiv,MAC,RsaPrivKeyData,temp_buf,retSignedData);
	}
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*retSignedDataLen=256;

	return SENC_SUCCESS;
}

//*函数：SENC_RSA_PrivkeyDecryptExternal()
//*功能：RSA解密 外部|| Decrypt by RSA encryption
//*参数：SENCHANDLE*		SencDevHandle				//加密卡设备handle
//		EncryptAttr*		inEncAttr					//传入秘钥参数
//		unsigned char*		IV							//RSA私钥加密初始向量
//		unsigned int		IVlen						//RSA私钥加密初始向量 buffer大小 16 bytes
//		unsigned char*		MAC							//RSA私钥加密mac
//		unsigned int		MAClen						//RSA私钥加密mac buffer大小 16 bytes
//		unsigned char*		RsaPrivKeyData				//RSA私钥数据
//		unsigned int		RsaPrivKeyDataLen			//RSA私钥数据 buffer大小 1412 bytes
//		unsigned char*		inData						//待解密数据
//		unsigned int		inDataLen					//待解密数据 buffer大小 256 bytes
//		unsigned char*		retDecData					//返回已解密数据
//		unsigned int*		retDecDataLen				//返回已解密数据长度
//*日期：2017/02/16
//by Wangjf
SENC_API unsigned int SENC_RSA_PrivkeyDecryptExternal(SENCHANDLE IN SencDevHandle,
													  EncryptAttr* IN inEncAttr,
													  unsigned char* IN IV,
													  unsigned int IN	IVlen,
													  unsigned char* IN	MAC,
													  unsigned int	IN	MAClen,
													  unsigned char* IN RsaPrivKeyData,
													  unsigned int IN RsaPrivKeyDataLen,
													  unsigned char* IN inData,
													  unsigned int IN inDataLen,
													  unsigned char* OUT retDecData,
													  unsigned int* OUT retDecDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char buf_pkcs[MAX_RSA_PADDING_SIZE] = {0};

	unsigned int temp_len = 2048 >> 3;
	unsigned int real_len = temp_len;
	unsigned int pkcsret=0;

	unsigned char emptyiv[16]={0};

	if(!SencDevHandle ) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PrivkeyDecryptExternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_PrikeyEncMode<0x01||inEncAttr->RSA_PrikeyEncMode>0x03)
		||(inEncAttr->RSA_PrikeyEncIdx<1||inEncAttr->RSA_PrikeyEncIdx>64)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PrivkeyDecryptExternal: EncAttr Error");
	if(!RsaPrivKeyData ||!inData ||!retDecData||!retDecDataLen||!MAC)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PrivkeyDecryptExternal: Parameter Null"); 
	if(RsaPrivKeyDataLen!=SENC_RSA_PRIVATE_KEY_LENGTH||MAClen!=SENC_ENC_MAC_LENGTH||inDataLen>256||(IV&&IVlen!=SENC_ENC_IV_LENGTH)||(!IV&&IVlen!=0))
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PrivkeyDecryptExternal: Parameter Length Error");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_RSA_PrivkeyDecryptExternal: Device Closed"); 

	//解密
	if(IV!=NULL){
		ucRet=SENC_CMD_RSA_Decrypt_External(pstEncDev,inEncAttr,IV,MAC,RsaPrivKeyData,inData,buf_pkcs);
	}else{
		ucRet=SENC_CMD_RSA_Decrypt_External(pstEncDev,inEncAttr,emptyiv,MAC,RsaPrivKeyData,inData,buf_pkcs);
	}
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	//解码
	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_decode(PKCS_1_V1_5_EME, buf_pkcs, temp_len, retDecData, real_len, &real_len);
		if (pkcsret) {
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_DECODE|((pkcsret&0xf)<<12),"SENC_RSA_PrivkeyDecryptExternal: PKCS Decode Error"); 
		}
		*retDecDataLen=real_len;
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(retDecData,buf_pkcs,temp_len);
		*retDecDataLen=temp_len;
	}

	return SENC_SUCCESS;
}


//*函数：SENC_AES_Encrypt()
//*功能：AES加密|| AES Encryption
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char		EncryptLength					//加密长度 AES 128 0x01|256 0x02
//		unsigned char		PrivKeyEncMode					//加密模式 ECB 0x01|CBC 0x02
//		unsigned char		KeyId							//加密秘钥索引
//		unsigned char*		inCBCiv							//CBC模式初始向量，16bytes，ecb模式下可为NULL
//		unsigned int		inCBCivLen						//CBC模式初始向量长度，16bytes，ecb模式下可为0
//		unsigned char*		inData							//待加密数据
//		unsigned int		inDataLen						//待加密数据长度
//		unsigned char*		retEncData						//返回加密数据
//		unsigned int		retEncDataLen					//返回加密数据长度
//*日期：2016/11/01
//by Wangjf
SENC_API unsigned int SENC_AES_Encrypt(SENCHANDLE IN SencDevHandle, 
									   EncryptAttr* IN inEncAttr,
									   unsigned char* IN inCBCiv,
									   unsigned int IN inCBCivLen,
									   unsigned char* IN inData,
									   unsigned int IN inDataLen,
									   unsigned char* OUT retEncData,
									   unsigned int* OUT retEncDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle ) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_AES_Encrypt: Device Not Found"); 
	if(!inData||!retEncData||!retEncDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_AES_Encrypt: Parameter Null"); 
	if((inEncAttr->AES_EncLength<1||inEncAttr->AES_EncLength>2)||(inEncAttr->AES_EncMode<1||inEncAttr->AES_EncMode>2)||(inEncAttr->AES_EncIdx<65||inEncAttr->AES_EncIdx>128))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_AES_Encrypt: EncAttr Error");
	if((inEncAttr->AES_EncMode==0x01&&inCBCivLen!=0)||(inEncAttr->AES_EncMode==0x02&&inCBCivLen!=16))
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_AES_Encrypt: Parameter Length Error");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_AES_Encrypt: Device Closed"); 

	//AES加密
	ucRet=SENC_CMD_AES_Encrypt(pstEncDev,inEncAttr,inCBCiv,inData,inDataLen,retEncData,retEncDataLen);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//*函数：SENC_AES_Decrypt()
//*功能：AES解密|| AES Decryption
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		unsigned char		EncryptLength					//加密长度 AES 128 0x01|256 0x02
//		unsigned char		PrivKeyEncMode					//加密模式 ECB 0x01|CBC 0x02
//		unsigned char		KeyId							//加密秘钥索引
//		unsigned char*		inCBCiv							//CBC模式初始向量，16bytes，ecb模式下可为NULL
//		unsigned int		inCBCivLen						//CBC模式初始向量长度，16bytes，ecb模式下可为0
//		unsigned char*		inData							//待解密数据
//		unsigned int		inDataLen						//待解密数据长度
//		unsigned char*		retDecData						//返回解密数据
//		unsigned int*		retDecDataLen					//返回解密数据长度
//*日期：2016/11/01
//by Wangjf
SENC_API unsigned int SENC_AES_Decrypt(SENCHANDLE IN SencDevHandle,
									   EncryptAttr* IN inEncAttr,
									   unsigned char* IN inCBCiv,
									   unsigned int IN inCBCivLen,
									   unsigned char* IN inData,
									   unsigned int IN inDataLen,
									   unsigned char* OUT retDecData,
									   unsigned int* OUT retDecDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle ) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_AES_Decrypt: Device Not Found"); 
	if(!inData||!retDecData||!retDecDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_AES_Decrypt: Parameter Null"); 
	if((inEncAttr->AES_EncLength<1||inEncAttr->AES_EncLength>2)||(inEncAttr->AES_EncMode<1||inEncAttr->AES_EncMode>2)||(inEncAttr->AES_EncIdx<65||inEncAttr->AES_EncIdx>128))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_AES_Decrypt: EncAttr Error");
	if((inEncAttr->AES_EncMode==0x01&&inCBCivLen!=0)||(inEncAttr->AES_EncMode==0x02&&inCBCivLen!=16))
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_AES_Decrypt: Parameter Length Error");
	if(inDataLen%16!=0)
		return SENC_ERROR_AES_LENGTH_ERROR;

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_AES_Decrypt: Device Closed"); 

	//AES解密
	ucRet=SENC_CMD_AES_Decrypt(pstEncDev,inEncAttr,inCBCiv,inData,inDataLen,retDecData,retDecDataLen);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


unsigned int SENC_ProTest_RsaSignature(SENCHANDLE IN SencDevHandle,
									   unsigned char* IN rsaKey,
									   unsigned int IN rsaKeyLen,
									   unsigned char* IN InData,
									   unsigned int IN InDataLen,
									   unsigned char* OUT SignedData, 
									   unsigned int* OUT SignedDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle ) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ProTest_RsaSignature: Device Not Found"); 
	if(!rsaKey||!InData||!SignedData||!SignedDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_ProTest_RsaSignature: Parameter Null"); 
	if(rsaKeyLen!=1412||InDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_ProTest_RsaSignature: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_ProTest_RsaSignature: Device Closed"); 

	ucRet=SENC_CMD_ProTest_RSA_Signature(pstEncDev,rsaKey,InData,SignedData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*SignedDataLen=256;

	return SENC_SUCCESS;
}

unsigned int SENC_ProTest_AesEncrypt(SENCHANDLE IN SencDevHandle,
									 unsigned char* IN pwKey,
									 unsigned int IN pwKeyLen,
									 unsigned char* IN InData,
									 unsigned int IN InDataLen, 
									 unsigned char* OUT RetData,
									 unsigned int* OUT RetDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ProTest_AesEncrypt: Device Not Found"); 
	if(!pwKey||!InData||!RetData||!RetDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_ProTest_AesEncrypt: Parameter Null"); 
	if(pwKeyLen!=32||InDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_ProTest_AesEncrypt: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_ProTest_AesEncrypt: Device Closed"); 

	ucRet=SENC_CMD_ProTest_AES_Encrypt(pstEncDev,pwKey,InData,RetData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetDataLen=256;

	return SENC_SUCCESS;
}


unsigned int SENC_ProTest_WriteEp(SENCHANDLE IN SencDevHandle, 
								  unsigned char* IN inData,
								  unsigned int IN inDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ProTest_WriteEp: Device Not Found"); 
	if(!inData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_ProTest_WriteEp: Parameter Null"); 
	if(inDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_ProTest_WriteEp: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_ProTest_WriteEp: Device Closed"); 

	ucRet=SENC_CMD_ProTest_Write_EP(pstEncDev,inData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_ProTest_WriteNp(SENCHANDLE IN SencDevHandle, 
								  unsigned char* IN inData, 
								  unsigned int IN inDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ProTest_WriteNp: Device Not Found"); 
	if(!inData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_ProTest_WriteNp: Parameter Null"); 
	if(inDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_ProTest_WriteNp: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_ProTest_WriteNp: Device Closed"); 

	ucRet=SENC_CMD_ProTest_Write_NoEP(pstEncDev,inData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_ProTest_Read(SENCHANDLE IN SencDevHandle, 
							   unsigned char* IN outData, 
							   unsigned int* OUT outDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ProTest_Read: Device Not Found"); 
	if(!outData||!outDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_ProTest_Read: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_ProTest_Read: Device Closed"); 

	ucRet=SENC_CMD_ProTest_Read(pstEncDev,outData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*outDataLen=256;

	return SENC_SUCCESS;
}

unsigned int SENC_ProTest_FlashSweep(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_ProTest_FlashSweep: Device Not Found"); 
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_ProTest_FlashSweep: Device Closed"); 

	ucRet=SENC_CMD_ProTest_Flash_sweep(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_MC_NewMasterCard(SENCHANDLE IN SencDevHandle,
								   unsigned char* OUT RetCardId,
								   unsigned int* OUT RetCardIdLen,
								   unsigned char* OUT RetNums,
								   unsigned int* OUT RetNumsLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_NewMasterCard: Device Not Found"); 
	if(!RetCardId||!RetNums||!RetCardIdLen||!RetNumsLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_MC_NewMasterCard: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_NewMasterCard: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_MC_NewMasterCard(pstEncDev,RetCardId,RetNums);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetCardIdLen=8;
	*RetNumsLen=1;

	return SENC_SUCCESS;
}

unsigned int SENC_MC_VerifyMasterCard(SENCHANDLE IN SencDevHandle,
									  unsigned char* OUT RetCardId,
									  unsigned int* OUT RetCardIdLen,
									  unsigned char* OUT RetCardPermission,
									  unsigned int* OUT RetCardPermissionLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_VerifyMasterCard: Device Not Found"); 
	if(!RetCardId||!RetCardPermission||!RetCardIdLen||!RetCardPermissionLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_MC_VerifyMasterCard: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_VerifyMasterCard: Device Closed"); 

	ucRet=SENC_CMD_MC_VerifyMasterCard(pstEncDev,RetCardId,RetCardPermission);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetCardIdLen=8;
	*RetCardPermissionLen=1;

	return SENC_SUCCESS;
}


unsigned int SENC_MC_DeleteMasterCard(SENCHANDLE IN SencDevHandle,
									  unsigned char* IN inCardId,
									  unsigned int IN inCardIdLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_DeleteMasterCard: Device Not Found"); 
	if(!inCardId)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_MC_DeleteMasterCard: Parameter Null"); 
	if(inCardIdLen!=8)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_MC_DeleteMasterCard: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_DeleteMasterCard: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_MC_DeleteMasterCard(pstEncDev,inCardId);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_MC_GetMasterCardId(SENCHANDLE IN SencDevHandle,
									 unsigned char* OUT RetCardInfo, 
									 unsigned int* OUT RetCardInfoLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_GetMasterCardId: Device Not Found"); 
	if(!RetCardInfo||!RetCardInfoLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_MC_GetMasterCardId: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_GetMasterCardId: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_MC_GetMasterCardId(pstEncDev,RetCardInfo);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetCardInfoLen=45;

	return SENC_SUCCESS;
}


unsigned int SENC_MC_QuitManagement(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_QuitManagement: Device Not Found"); 
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_QuitManagement: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_MC_MngQuit(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_MC_SetStandby(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_SetStandby: Device Not Found"); 
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_SetStandby: Device Closed"); 

	ucRet=SENC_CMD_MC_WorkStandby(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_MC_GetBackupKey(SENCHANDLE IN SencDevHandle, 
								  unsigned char* OUT RetCardSign,
								  unsigned int* OUT RetCardSignLen,
								  unsigned char* OUT RetCardInfo,
								  unsigned int * OUT RetCardInfoLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_GetBackupKey: Device Not Found"); 
	if(!RetCardSign||!RetCardInfo||!RetCardSignLen||!RetCardInfoLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_MC_GetBackupKey: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_GetBackupKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_MC_GetBackupKey(pstEncDev,RetCardSign,RetCardInfo);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetCardSignLen=5;
	*RetCardInfoLen=SENC_BAKCUP_KEYS_LENGTH;

	return SENC_SUCCESS;
}


unsigned int SENC_MC_SetRecoveryKey(SENCHANDLE IN SencDevHandle,
									unsigned char* IN inCardInfo,
									unsigned int IN inCardInfoLen,
									unsigned char* OUT RetCardSign,
									unsigned int * OUT RetCardSignLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_MC_SetRecoveryKey: Device Not Found"); 
	if(!RetCardSign||!inCardInfo||!RetCardSignLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_MC_SetRecoveryKey: Parameter Null"); 
	if(inCardInfoLen!=SENC_BAKCUP_KEYS_LENGTH)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_MC_SetRecoveryKey: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_MC_SetRecoveryKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_MC_SetRecoveryKey(pstEncDev,inCardInfo,RetCardSign);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetCardSignLen=6;

	return SENC_SUCCESS;
}



unsigned int SENC_DK_NewDongle(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DK_NewDongle: Device Not Found"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DK_NewDongle: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_DongleAPI_NewDongle(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_DK_DeleteDongle(SENCHANDLE IN SencDevHandle,
								  unsigned char* IN DongleID, 
								  unsigned int IN DongleIDLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DK_DeleteDongle: Device Not Found"); 
	if((DongleID&&DongleIDLen!=8)||(!DongleID&&DongleIDLen!=0))
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_DK_DeleteDongle: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DK_DeleteDongle: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	if(DongleID)
		ucRet=SENC_CMD_Dongle_Delete(pstEncDev,DongleID);
	else
		ucRet=SENC_DongleAPI_DeletePlugDongle(pstEncDev);

	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_DK_VerifyDongle(SENCHANDLE IN SencDevHandle,
								  unsigned char InAuthKeyIdx,
								  unsigned char FlashDecKeyIdx,
								  unsigned char* IN inRndNum,
								  unsigned int IN inRndNumLen,
								  unsigned char* IN FlashKey,
								  unsigned int IN FlashKeyLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DK_VerifyDongle: Device Not Found"); 
	if(!inRndNum||!FlashKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DK_VerifyDongle: Parameter Null"); 
	if(inRndNumLen!=8||FlashKeyLen!=8)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_DK_VerifyDongle: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DK_VerifyDongle: Device Closed"); 

	ucRet=SENC_DongleAPI_VerifyStep(pstEncDev,InAuthKeyIdx,FlashDecKeyIdx,inRndNum,FlashKey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;

}

unsigned int SENC_DK_GetVerifyRand(SENCHANDLE IN SencDevHandle, 
								   unsigned char* OUT InAuthKeyIdx,
								   unsigned int * OUT InAuthKeyIdxLen,
								   unsigned char* OUT FlashDecKeyIdx,
								   unsigned int * OUT FlashDecKeyIdxLen,
								   unsigned char* OUT retRndNum,
								   unsigned int * OUT retRndNumLen,
								   unsigned char* OUT FlashKey,
								   unsigned int * OUT FlashKeyLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DK_GetVerifyRand: Device Not Found"); 
	if(!retRndNum||!FlashKey||!retRndNumLen||!FlashKeyLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DK_GetVerifyRand: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DK_GetVerifyRand: Device Closed"); 

	ucRet=SENC_DongleAPI_GetRndNum(pstEncDev,InAuthKeyIdx,FlashDecKeyIdx,retRndNum,FlashKey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*retRndNumLen=8;
	*FlashKeyLen=8;
	*InAuthKeyIdxLen=1;
	*FlashDecKeyIdxLen=1;

	return SENC_SUCCESS;
}

unsigned int SENC_DK_GetDonglesId(SENCHANDLE IN SencDevHandle, 
								  unsigned char* OUT RetDongleIdInfo,
								  unsigned int* OUT RetDongleIdInfoLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DK_GetDonglesId: Device Not Found"); 
	if(!RetDongleIdInfo||!RetDongleIdInfoLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DK_GetDonglesId: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DK_GetDonglesId: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Get_Dongle_ID(pstEncDev,RetDongleIdInfo);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetDongleIdInfoLen=27;

	return SENC_SUCCESS;
}



SENC_API unsigned int SENC_QuitOperateState(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_QuitOperateState: Device Not Found"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_QuitOperateState: Device Closed"); 

	ucRet=SENC_CMD_Dongle_Quit(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


SENC_API unsigned int SENC_RSA_PrivkeySignatureInternal(SENCHANDLE IN SencDevHandle,
														EncryptAttr* IN inEncAttr,
														unsigned char* IN InData,
														unsigned int IN InDataLen,
														unsigned char* OUT RetSignedData,
														unsigned int* OUT RetSignedDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char hash_buf[MAX_HASH_SHA_SIZE] = {0};
	unsigned int hash_len = 0;
	unsigned char temp_buf[MAX_RSA_PADDING_SIZE] = {0};
	unsigned int temp_len = 2048 >> 3;
	unsigned char dhash_buf[MAX_RSA_SHA_DER_SIZE] = {0};
	unsigned int dhash_len = sizeof(dhash_buf);
	const unsigned char *p_hash_header = NULL;
	unsigned int pkcsret=0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PrivkeySignatureInternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_InternalKeyIdx<1||inEncAttr->RSA_InternalKeyIdx>128)
		||(inEncAttr->RSA_HashAlgorithm<1||inEncAttr->RSA_HashAlgorithm>2)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PrivkeySignatureInternal: EncAttr Error");
	if(!InData||!RetSignedData||!RetSignedDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PrivkeySignatureInternal: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_RSA_PrivkeySignatureInternal: Device Closed"); 

	//hash data
	if(inEncAttr->RSA_HashAlgorithm==HASH_SHA1){
		sha1(InData,InDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA1Der;
		dhash_len=sizeof(u8rsaSHA1Der);
	}else if(inEncAttr->RSA_HashAlgorithm==HASH_SHA256){
		sha256(InData,InDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA256Der;
		dhash_len=sizeof(u8rsaSHA256Der);
	}
	memcpy(dhash_buf,p_hash_header,dhash_len);
	memcpy(dhash_buf+dhash_len,hash_buf,hash_len);
	dhash_len+=hash_len;

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_encode(PKCS_1_V1_5_EMSA, dhash_buf,dhash_len,temp_buf,temp_len);
		if(pkcsret){
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_ENCODE|((pkcsret&0xf)<<12),"SENC_RSA_PrivkeySignatureInternal: PKCS Encode Error"); 
		}
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(temp_buf,dhash_buf,dhash_len);
	}

	ucRet=SENC_CMD_RSA_Signature_Internal(pstEncDev,inEncAttr,temp_buf,RetSignedData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetSignedDataLen=256;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_RSA_PrivkeyDecryptInternal(SENCHANDLE IN SencDevHandle,
													  EncryptAttr* IN inEncAttr,
													  unsigned char* IN InData, 
													  unsigned int IN InDataLen,
													  unsigned char* OUT RetDecData,
													  unsigned int* OUT RetDecDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char buf_pkcs[MAX_RSA_PADDING_SIZE] = {0};

	unsigned int temp_len = 2048 >> 3;
	unsigned int real_len = temp_len;
	unsigned int pkcsret=0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PrivkeyDecryptInternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_InternalKeyIdx<1||inEncAttr->RSA_InternalKeyIdx>128)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PrivkeyDecryptInternal: EncAttr Error");
	if(!InData||!RetDecData||!RetDecDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PrivkeyDecryptInternal: Parameter Null"); 
	if(InDataLen>256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PrivkeyDecryptInternal: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_RSA_PrivkeyDecryptInternal: Device Closed"); 

	ucRet=SENC_CMD_RSA_Decrypt_Internal(pstEncDev,inEncAttr,InData,buf_pkcs);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_decode(PKCS_1_V1_5_EME, buf_pkcs, temp_len, RetDecData, real_len, &real_len);
		if (pkcsret) {
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_DECODE|((pkcsret&0xf)<<12),"SENC_RSA_PrivkeyDecryptInternal: PKCS Decode Error"); 
		}
		*RetDecDataLen=real_len;
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(RetDecData,buf_pkcs,temp_len);
		*RetDecDataLen=temp_len;
	}


	return SENC_SUCCESS;
}



SENC_API unsigned int SENC_KEY_RSAKeyGenerate(SENCHANDLE IN SencDevHandle,
											  EncryptAttr* IN inEncAttr,
											  unsigned char* IN IV,
											  unsigned int IN IVlen,
											  unsigned char* OUT RetMAC,
											  unsigned int*	OUT	RetMACLen,
											  unsigned char* OUT RetRSAPrivKey,
											  unsigned int* OUT RetRSAPrivKeyLen,
											  unsigned char* OUT RetRSAPubKey,
											  unsigned int* OUT RetRSAPubKeyLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char tIV[16]={0};

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_RSAKeyGenerate: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)||(inEncAttr->RSA_PrikeyEncMode!=0x01&&inEncAttr->RSA_PrikeyEncMode!=0x02&&inEncAttr->RSA_PrikeyEncMode!=0x03)||
		(inEncAttr->RSA_PrikeyEncIdx<1||inEncAttr->RSA_PrikeyEncIdx>64)||(IVlen!=SENC_ENC_IV_LENGTH&&IV)||(!IV&&IVlen!=0))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_KEY_RSAKeyGenerate: EncAttr Error");
	if(!RetRSAPrivKey||!RetRSAPubKey||!RetRSAPrivKeyLen||!RetRSAPubKeyLen||!RetMAC)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RSAKeyGenerate: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_RSAKeyGenerate: Device Closed"); 

	//签名
	if(IV!=NULL){
		ucRet=SENC_CMD_Key_RSA_Generate_Ret(pstEncDev,inEncAttr,IV,RetMAC,RetRSAPrivKey,RetRSAPubKey);
	}else{
		ucRet=SENC_CMD_Key_RSA_Generate_Ret(pstEncDev,inEncAttr,tIV,RetMAC,RetRSAPrivKey,RetRSAPubKey);
	}
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetRSAPrivKeyLen=SENC_RSA_PRIVATE_KEY_LENGTH;
	*RetRSAPubKeyLen=SENC_RSA_PUBLIC_KEY_LENGTH;
	*RetMACLen=SENC_ENC_MAC_LENGTH;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_KEY_RSAKeyGenerateInternal(SENCHANDLE IN SencDevHandle,
													  unsigned char IN InEncryptLength,
													  unsigned char IN RsaKeyIdx)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_RSAKeyGenerateInternal: Device Not Found"); 
	if(RsaKeyIdx<1||RsaKeyIdx>128)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RSAKeyGenerateInternal: Parameter Index Error"); 
	if(InEncryptLength!=0x01)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RSAKeyGenerateInternal: Parameter Type Error"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_RSAKeyGenerateInternal: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_RSA_Generate_Internal(pstEncDev,InEncryptLength,RsaKeyIdx);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_KEY_RSAKeyGetPublicKey(SENCHANDLE IN SencDevHandle,
												  EncryptAttr* IN inEncAttr,
												  unsigned char* OUT RetRsaPubKey,
												  unsigned int* OUT RetRsaPubKeyLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_RSAKeyGetPublicKey: Device Not Found"); 
	if(!RetRsaPubKey||!RetRsaPubKeyLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RSAKeyGetPublicKey: Parameter Null"); 
	if((inEncAttr->RSA_Mode!=0x01)||(inEncAttr->RSA_InternalKeyIdx<1||inEncAttr->RSA_InternalKeyIdx>128))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_KEY_RSAKeyGetPublicKey: EncAttr Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_RSAKeyGetPublicKey: Device Closed"); 

	ucRet=SENC_CMD_Key_RSA_GetPublicKey(pstEncDev,inEncAttr->RSA_Mode,inEncAttr->RSA_InternalKeyIdx,RetRsaPubKey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetRsaPubKeyLen=512;

	return SENC_SUCCESS;
}

unsigned int SENC_KEY_SymmetricKeyGenerate(SENCHANDLE IN SencDevHandle, 
										   unsigned char IN InEncryptLength,
										   unsigned char IN inKeyIdx)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_SymmetricKeyGenerate: Device Not Found"); 

	switch (InEncryptLength)
	{
	case 0x01:
	case 0x02:
		if(inKeyIdx<1||inKeyIdx>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_SymmetricKeyGenerate: Parameter Index Error"); 
		break;
	case 0x03:
		if(inKeyIdx<1||inKeyIdx>64)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_SymmetricKeyGenerate: Parameter Index Error"); 
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_SymmetricKeyGenerate: Parameter Type Error"); 
	}

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_SymmetricKeyGenerate: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_Symmetric_Key_Generate(pstEncDev,InEncryptLength,inKeyIdx);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_KEY_ImportKey(SENCHANDLE IN SencDevHandle,
								unsigned char IN InEncryptType,
								unsigned char IN inKeyIdx,
								unsigned char* IN inKeyData, 
								unsigned int IN inKeyDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_ImportKey: Device Not Found"); 

	switch (InEncryptType)
	{
	case 0x01:
	case 0x02:
		if(inKeyIdx<65||inKeyIdx>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_ImportKey: Parameter Index Error"); 
		break;
	case 0x03:
		if(inKeyIdx<1||inKeyIdx>64)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_ImportKey: Parameter Index Error"); 
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_ImportKey: Parameter Type Error"); 
	}
	if(!inKeyData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_ImportKey: Parameter Null"); 
	if(((InEncryptType==1||InEncryptType==3)&&inKeyDataLen!=16)||(InEncryptType==2&&inKeyDataLen!=32))
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_KEY_ImportKey: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_ImportKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_Import(pstEncDev,InEncryptType,inKeyIdx,inKeyData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_KEY_DeleteKey(SENCHANDLE IN SencDevHandle,
								unsigned char IN InEncryptType, 
								unsigned char IN DelKeyId)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_DeleteKey: Device Not Found"); 
	if(InEncryptType<0x01||InEncryptType>0x04)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_DeleteKey: Parameter Type Error"); 
	switch (InEncryptType)
	{
	case 0x01:
	case 0x02:
	case 0x04:
		if(DelKeyId<1||DelKeyId>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_DeleteKey: Parameter Index Error"); 
		break;
	case 0x03:
		if(DelKeyId<1||DelKeyId>64)	//only 64 SM4 keys are stored
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_DeleteKey: Parameter Index Error"); 
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_DeleteKey: Parameter Type Error"); 
	}


	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_DeleteKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_Delete(pstEncDev,InEncryptType,DelKeyId);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

//aes rsa required 16 bytes for context, sm4 required 8 bytes.
unsigned int SENC_KEY_QueryKey(SENCHANDLE IN SencDevHandle,
							   unsigned char* OUT RetAes128state,unsigned int * OUT RetAes128stateLen,
							   unsigned char* OUT RetAes256state,unsigned int * OUT RetAes256stateLen,
							   unsigned char* OUT RetSm4state,unsigned int * OUT RetSm4stateLen,
							   unsigned char* OUT RetRsa2048state,unsigned int * OUT RetRsa2048stateLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_QueryKey: Device Not Found"); 
	if(!RetAes128state||!RetAes256state||!RetSm4state||!RetRsa2048state||!RetAes128stateLen||!RetAes256stateLen||!RetSm4stateLen||!RetRsa2048stateLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_QueryKey: Parameter Null"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_QueryKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_Query(pstEncDev,RetAes128state,RetAes256state,RetSm4state,RetRsa2048state);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetAes128stateLen=16;
	*RetAes256stateLen=16;
	*RetSm4stateLen=8;
	*RetRsa2048stateLen=16;

	return SENC_SUCCESS;
}

unsigned int SENC_KEY_BackupKey(SENCHANDLE IN SencDevHandle, 
								unsigned char IN InEncryptType,
								unsigned char IN BackupKeyId,
								unsigned char* OUT RetBakData,
								unsigned int* OUT RetBakDataLength)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_BackupKey: Device Not Found"); 
	if(!RetBakData||!RetBakDataLength)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_BackupKey: Parameter Null"); 
	switch (InEncryptType)
	{
	case 0x01:
	case 0x02:
	case 0x04:
		if(BackupKeyId<1||BackupKeyId>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_BackupKey: Parameter Index Error"); 
		break;
	case 0x03:
		if(BackupKeyId<1||BackupKeyId>64)	//only 64 SM4 keys are stored
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_BackupKey: Parameter Index Error"); 
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_BackupKey: Parameter Type Error"); 
	}


	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_BackupKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_Backup(pstEncDev,InEncryptType,BackupKeyId,RetBakData,RetBakDataLength);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_KEY_RecoverKey(SENCHANDLE IN SencDevHandle,
								 unsigned char IN InEncryptType,
								 unsigned char IN KeyId, 
								 unsigned char* IN inBakData,
								 unsigned int IN KeyDataLength)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_KEY_RecoverKey: Device Not Found"); 
	if(!inBakData||KeyDataLength==0)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RecoverKey: Parameter Null"); 
	switch (InEncryptType)
	{
	case 0x01:
	case 0x02:
	case 0x04:
		if(KeyId<1||KeyId>128)
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RecoverKey: Parameter Index Error"); 
		break;
	case 0x03:
		if(KeyId<1||KeyId>64)	//only 64 SM4 keys are stored
			return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RecoverKey: Parameter Index Error"); 
		break;

	default:
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_KEY_RecoverKey: Parameter Type Error"); 
	}


	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_KEY_RecoverKey: Device Closed"); 

	ucRet=SENC_DH_KeyExchange(pstEncDev);		//管理权限，秘钥交换
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=SENC_CMD_Key_Recover(pstEncDev,InEncryptType,KeyId,KeyDataLength,inBakData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

unsigned int SENC_DongleVerify(SENCHANDLE IN SencDevHandle){
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DongleVerify: Device Not Found"); 

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DongleVerify: Device Closed"); 

	ucRet=SENC_DongleAPI_Verify(pstEncDev);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


unsigned int SENC_DK_NewDongleGroup(SENCryptCardList* IN DevList){
	unsigned int ucRet = 0;

	if(!DevList) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DK_NewDongleGroup: Device List Not Found"); 

	ucRet=SENC_DongleAPI_NewDongle_Group(DevList);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


//*函数：SENC_RSA_PubkeyVerifyExternal()
//*功能：RSA签名|| Signature by RSA encryption
//*参数：SENCHANDLE*			SencDevHandle					//加密卡设备handle
//		EncryptAttr*		inEncAttr						//传入秘钥参数
//		unsigned char*		PubKey							//RSA公钥数据
//		unsigned int		PubKeyLen						//RSA公钥数据 buffer大小 512 bytes
//		unsigned char*		inData							//待签名数据
//		unsigned int		inDataLen						//待签名数据 buffer大小 256 bytes
//		unsigned char*		retSignedData					//签名返回数据
//		unsigned int		retSignedDataLen				//签名返回数据长度
//*日期：2016/11/01
//by Wangjf
SENC_API unsigned int SENC_RSA_PubkeyVerifyExternal(SENCHANDLE IN SencDevHandle,
													EncryptAttr* IN inEncAttr,
													unsigned char* IN PubKey,
													unsigned int IN PubKeyLen,
													unsigned char* IN inData,
													unsigned int IN inDataLen,
													unsigned char* IN SignedData,
													unsigned int IN SignedDataLen)
{
	unsigned int ucRet = 0;
	unsigned char hash_buf[MAX_HASH_SHA_SIZE] = {0};
	unsigned int hash_len = sizeof(hash_buf);
	unsigned char buf_rsa[MAX_RSA_PADDING_SIZE] = {0};
	unsigned char buf_pkcs[MAX_RSA_PADDING_SIZE] = {0};
	unsigned int temp_len = 2048 >> 3;
	unsigned int real_len = temp_len;
	unsigned char dhash_buf[MAX_RSA_SHA_DER_SIZE] = {0};
	unsigned int dhash_len = sizeof(dhash_buf);
	const unsigned char *p_hash_header = NULL;
	unsigned int pkcsret=0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PubkeyVerifyExternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_HashAlgorithm<1||inEncAttr->RSA_HashAlgorithm>2)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PubkeyVerifyExternal: EncAttr Error");
	if(!PubKey||!inData||!SignedData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PubkeyVerifyExternal: Parameter Null"); 
	if(PubKeyLen!=SENC_RSA_PUBLIC_KEY_LENGTH||SignedDataLen>256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PubkeyVerifyExternal: Parameter Length Error");

	//hash data
	if(inEncAttr->RSA_HashAlgorithm==HASH_SHA1){
		sha1(inData,inDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA1Der;
		dhash_len=sizeof(u8rsaSHA1Der);
	}else if(inEncAttr->RSA_HashAlgorithm==HASH_SHA256){
		sha256(inData,inDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA256Der;
		dhash_len=sizeof(u8rsaSHA256Der);
	}
	memcpy(dhash_buf,p_hash_header,dhash_len);
	memcpy(dhash_buf+dhash_len,hash_buf,hash_len);
	dhash_len+=hash_len;

	ucRet = pure_rsa_pub_key_decrypt(PubKey,PubKeyLen,SignedData,SignedDataLen,buf_rsa,&temp_len);
	if(ucRet!=SENC_SUCCESS){
		return ucRet;
	}

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_decode(PKCS_1_V1_5_EMSA, buf_rsa,temp_len,buf_pkcs,real_len,&real_len);
		if(pkcsret){
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_DECODE|((pkcsret&0xf)<<12),"SENC_RSA_PubkeyVerifyExternal: PKCS Decode Error");
		}
		if(real_len!=dhash_len){
			return ERROR_LOG(SENC_ERROR_RSA_VERIFY_FAILED_LENGTH,"SENC_RSA_PubkeyVerifyExternal: Decoded Length Error");
		}
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(buf_pkcs,buf_rsa,temp_len);
	}

	if(memcmp(dhash_buf, buf_pkcs, dhash_len)){
		return  ERROR_LOG(SENC_ERROR_RSA_VERIFY_FAILED_DATA,"SENC_RSA_PubkeyVerifyExternal: Decoded Data Error");
	}

	return SENC_SUCCESS;
}

//*函数：SENC_RSA_PubkeyEncryptExternal()
//*功能：RSA解密 外部|| Decrypt by RSA encryption
//*参数：SENCHANDLE*		SencDevHandle				//加密卡设备handle
//		EncryptAttr*		inEncAttr					//传入秘钥参数
//		unsigned char*		pubkey						//RSA公钥数据
//		unsigned int		pubkeyLen					//RSA公钥数据 buffer大小 512 bytes
//		unsigned char*		inData						//待解密数据
//		unsigned int		inDataLen					//待解密数据 buffer大小 256 bytes
//		unsigned char*		retDecData					//返回已解密数据
//		unsigned int*		retDecDataLen				//返回已解密数据长度
//*日期：2017/02/16
//by Wangjf
SENC_API unsigned int SENC_RSA_PubkeyEncryptExternal(SENCHANDLE IN SencDevHandle,
													 EncryptAttr* IN inEncAttr,
													 unsigned char* IN pubkey,
													 unsigned int IN pubkeyLen,
													 unsigned char* IN inData,
													 unsigned int IN inDataLen,
													 unsigned char* OUT retEncData,
													 unsigned int* OUT retEncDataLen)
{
	unsigned int ucRet = 0;
	unsigned char buf_pkcs[MAX_RSA_PADDING_SIZE] = {0};
	unsigned int pkcsret=0;

	unsigned int temp_len = 2048 >> 3;

	if(!SencDevHandle ) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PubkeyEncryptExternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PubkeyEncryptExternal: EncAttr Error");
	if(!pubkey ||!inData ||!retEncData||!retEncDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PubkeyEncryptExternal: Parameter Null"); 
	if(pubkeyLen!=SENC_RSA_PUBLIC_KEY_LENGTH||inDataLen>256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PubkeyEncryptExternal: Parameter Length Error");

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_encode(PKCS_1_V1_5_EME, inData,inDataLen,buf_pkcs,temp_len);
		if(pkcsret){
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_ENCODE|((pkcsret&0xf)<<12),"SENC_RSA_PubkeyEncryptExternal: PKCS Encode Error");
		}
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(buf_pkcs,inData,inDataLen);
		temp_len=inDataLen;
	}

	ucRet=pure_rsa_pub_key_encrypt(pubkey,512,buf_pkcs,temp_len,retEncData,retEncDataLen);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


SENC_API unsigned int SENC_RSA_PubkeyVerifyInternal(SENCHANDLE IN SencDevHandle,
													EncryptAttr* IN inEncAttr,
													unsigned char* IN InData,
													unsigned int IN InDataLen,
													unsigned char* IN SignedData,
													unsigned int IN SignedDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char hash_buf[MAX_HASH_SHA_SIZE] = {0};
	unsigned int hash_len = sizeof(hash_buf);
	unsigned char buf_rsa[MAX_RSA_PADDING_SIZE] = {0};
	unsigned char buf_pkcs[MAX_RSA_PADDING_SIZE] = {0};
	unsigned int temp_len = 2048 >> 3;
	unsigned int real_len = temp_len;
	unsigned char dhash_buf[MAX_RSA_SHA_DER_SIZE] = {0};
	unsigned int dhash_len = sizeof(dhash_buf);
	const unsigned char *p_hash_header = NULL;
	unsigned char pubkey[512]={0};
	unsigned int pkcsret=0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PubkeyVerifyInternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_InternalKeyIdx<1||inEncAttr->RSA_InternalKeyIdx>128)
		||(inEncAttr->RSA_HashAlgorithm<1||inEncAttr->RSA_HashAlgorithm>2)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PubkeyVerifyInternal: EncAttr Error");
	if(!InData||!SignedData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PubkeyVerifyInternal: Parameter Null"); 
	if(SignedDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PubkeyVerifyInternal: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_RSA_PubkeyVerifyInternal: Device Closed"); 

	//hash data
	if(inEncAttr->RSA_HashAlgorithm==HASH_SHA1){
		sha1(InData,InDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA1Der;
		dhash_len=sizeof(u8rsaSHA1Der);
	}else if(inEncAttr->RSA_HashAlgorithm==HASH_SHA256){
		sha256(InData,InDataLen,hash_buf,&hash_len);
		p_hash_header=u8rsaSHA256Der;
		dhash_len=sizeof(u8rsaSHA256Der);
	}
	memcpy(dhash_buf,p_hash_header,dhash_len);
	memcpy(dhash_buf+dhash_len,hash_buf,hash_len);
	dhash_len+=hash_len;

	ucRet=SENC_CMD_Key_RSA_GetPublicKey(pstEncDev,inEncAttr->RSA_Mode,inEncAttr->RSA_InternalKeyIdx,pubkey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	ucRet=pure_rsa_pub_key_decrypt(pubkey,512,SignedData,SignedDataLen,buf_rsa,&temp_len);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_decode(PKCS_1_V1_5_EMSA, buf_rsa,temp_len,buf_pkcs,real_len,&real_len);
		if(pkcsret){
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_DECODE|((pkcsret&0xf)<<12),"SENC_RSA_PubkeyVerifyInternal: PKCS Decode Error"); 
		}
		if(real_len!=dhash_len){
			return ERROR_LOG(SENC_ERROR_RSA_VERIFY_FAILED_LENGTH,"SENC_RSA_PubkeyVerifyInternal: Decoded Length Error");
		}
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(buf_pkcs,buf_rsa,temp_len);
	}

	if(memcmp(dhash_buf, buf_pkcs, dhash_len)){
		return ERROR_LOG(SENC_ERROR_RSA_VERIFY_FAILED_DATA,"SENC_RSA_PubkeyVerifyInternal: Decoded Data Error");
	}

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_RSA_PubkeyEncryptInternal(SENCHANDLE IN SencDevHandle,
													 EncryptAttr* IN inEncAttr,
													 unsigned char* IN InData, 
													 unsigned int IN InDataLen,
													 unsigned char* OUT RetEncData,
													 unsigned int* OUT RetEncDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char buf_pkcs[MAX_RSA_PADDING_SIZE] = {0};
	unsigned char pubkey[512]={0};
	unsigned int pkcsret=0;

	unsigned int temp_len = 2048 >> 3;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_RSA_PubkeyEncryptInternal: Device Not Found"); 
	if((inEncAttr->RSA_Mode!=0x01)
		||(inEncAttr->RSA_InternalKeyIdx<1||inEncAttr->RSA_InternalKeyIdx>128)
		||(inEncAttr->RSA_PaddingMode<1||inEncAttr->RSA_PaddingMode>2))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_RSA_PubkeyEncryptInternal: EncAttr Error");
	if(!InData||!RetEncData||!RetEncDataLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_RSA_PubkeyEncryptInternal: Parameter Null"); 
	if(InDataLen>256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_RSA_PubkeyEncryptInternal: Parameter Length Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_RSA_PubkeyEncryptInternal: Device Closed"); 

	if(inEncAttr->RSA_PaddingMode==PAD_MODE_PKCS_1_V1_5){
		pkcsret=pkcs_1_v1_5_encode(PKCS_1_V1_5_EME, InData,InDataLen,buf_pkcs,temp_len);
		if(pkcsret){
			return ERROR_LOG(SENC_ERROR_PKCS1_V1_5_ENCODE|((pkcsret&0xf)<<12),"SENC_RSA_PubkeyEncryptInternal: PKCS Encode Error"); 
		}
	}else if(inEncAttr->RSA_PaddingMode==PAD_MODE_NONE){
		memcpy(buf_pkcs,InData,InDataLen);
		temp_len=InDataLen;
	}

	ucRet=SENC_CMD_Key_RSA_GetPublicKey(pstEncDev,inEncAttr->RSA_Mode,inEncAttr->RSA_InternalKeyIdx,pubkey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;


	ucRet=pure_rsa_pub_key_encrypt(pubkey,512,buf_pkcs,temp_len,RetEncData,RetEncDataLen);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}


#if defined __ALTER_ON__

SENC_API unsigned int SENC_Alternative_Hash(SENCHANDLE IN SencDevHandle,
									 unsigned char hashAlgo,
									 const unsigned char* inData,
									 unsigned int inDataLen,
									 unsigned char* retData,
									 unsigned int* retDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_Hash: Device Not Found"); 
	if(!inData||!retData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_Hash: Parameter Null"); 
	if(hashAlgo<1||hashAlgo>3||inDataLen<1)
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_Hash: EncAttr Error");

	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_Hash: Device Closed"); 

	ucRet=SENC_CMD_Alternative_Hash(pstEncDev,hashAlgo,inData,inDataLen,retData,retDataLen);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_Alternative_GenerateKeyPair(SENCHANDLE IN SencDevHandle,
													   unsigned char keyBits,
													   unsigned char EncMethod,
													   unsigned char EncIdx,
													   unsigned char* IN IV,
													   unsigned int IN IVlen,
													   unsigned char* OUT RetMAC,
													   unsigned int*	OUT	RetMACLen,
													   unsigned char* OUT RetRSAPrivKey,
													   unsigned int* OUT RetRSAPrivKeyLen,
													   unsigned char* OUT RetRSAPubKey,
													   unsigned int* OUT RetRSAPubKeyLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char tIV[16]={0};

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_GenerateKeyPair: Device Not Found"); 
	if((keyBits!=0x01)||(EncMethod<0x01||EncMethod>0x03)||
		(EncIdx<1||EncIdx>64))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_GenerateKeyPair: EncAttr Error");
	if(!RetRSAPrivKey||!RetRSAPubKey||!RetRSAPrivKeyLen||!RetRSAPubKeyLen||!RetMAC||!RetMACLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_GenerateKeyPair: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_GenerateKeyPair: Device Closed"); 

	memcpy(tIV,IV,IVlen);

	//签名
	ucRet=SENC_CMD_Alternative_GenRsaKeyPair(pstEncDev,keyBits,EncMethod,EncIdx,tIV,RetMAC,RetRSAPrivKey,RetRSAPubKey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*RetRSAPrivKeyLen=SENC_RSA_PRIVATE_KEY_LENGTH;
	*RetRSAPubKeyLen=SENC_RSA_PUBLIC_KEY_LENGTH;
	*RetMACLen=SENC_ENC_MAC_LENGTH;

	return SENC_SUCCESS;
}


SENC_API unsigned int SENC_Alternative_SignatureExternal(SENCHANDLE IN SencDevHandle,
														 unsigned char keyBits,
														 unsigned char EncMethod,
														 unsigned char EncIdx,
														 unsigned char* IN IV,
														 unsigned int IN IVlen,
														 unsigned char* IN MAC,
														 unsigned int	IN	MACLen,
														 unsigned char* IN RSAPrivKey,
														 unsigned int IN RSAPrivKeyLen,
														 unsigned char* IN inData,
														 unsigned int IN inDataLen,
														 unsigned char* OUT retSignedData,
														 unsigned int* OUT retSignedDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;
	unsigned char tIV[16]={0};

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_SignatureExternal: Device Not Found"); 
	if((keyBits!=0x01)||(EncMethod<0x01||EncMethod>0x03)||
		(EncIdx<1||EncIdx>64))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_SignatureExternal: EncAttr Error");
	if(!MAC||!retSignedData||!RSAPrivKey||!inData||!retSignedDataLen||MACLen!=16||RSAPrivKeyLen!=1412||inDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_SignatureExternal: Parameter Error"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_SignatureExternal: Device Closed"); 

	memcpy(tIV,IV,IVlen);

	//签名
	ucRet=SENC_CMD_Alternative_SignatureExternal(pstEncDev,keyBits,EncMethod,EncIdx,IV,MAC,RSAPrivKey,inData,retSignedData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*retSignedDataLen=256;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_Alternative_VerifyExternal(SENCHANDLE IN SencDevHandle,
													  unsigned char keyBits,
													  unsigned char* IN RSAPubKey,
													  unsigned int IN RSAPubKeyLen,
													  unsigned char* IN SignedData,
													  unsigned int IN SignedDataLen,
													  unsigned char* OUT retDecrypto,
													  unsigned int* OUT retDecryptoLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_VerifyExternal: Device Not Found"); 
	if(keyBits!=0x01)
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_VerifyExternal: EncAttr Error");
	if(!RSAPubKey||!SignedData||!retDecrypto||RSAPubKeyLen!=512||SignedDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_VerifyExternal: Parameter Error"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_VerifyExternal: Device Closed"); 

	//签名
	ucRet=SENC_CMD_Alternative_VerifyExternal(pstEncDev,keyBits,RSAPubKey,SignedData,retDecrypto);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*retDecryptoLen=256;

	return SENC_SUCCESS;
}


SENC_API unsigned int SENC_Alternative_SignatureInternal(SENCHANDLE IN SencDevHandle,
														 unsigned char keyBits,
														 unsigned char KeyIdx,
														 unsigned char* IN inData,
														 unsigned int IN inDataLen,
														 unsigned char* OUT retSignedData,
														 unsigned int* OUT retSignedDataLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_SignatureInternal: Device Not Found"); 
	if((keyBits!=0x01)||(KeyIdx<1||KeyIdx>128))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_SignatureInternal: EncAttr Error");
	if(!retSignedData||!inData||!retSignedDataLen||inDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_SignatureInternal: Parameter Error"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_SignatureInternal: Device Closed"); 

	//签名
	ucRet=SENC_CMD_Alternative_SignatureInternal(pstEncDev,keyBits,KeyIdx,inData,retSignedData);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*retSignedDataLen=256;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_Alternative_VerifyInternal(SENCHANDLE IN SencDevHandle,
													  unsigned char keyBits,
													  unsigned char KeyIdx,
													  unsigned char* IN SignedData,
													  unsigned int IN SignedDataLen,
													  unsigned char* OUT retDecrypto,
													  unsigned int* OUT retDecryptoLen)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_VerifyInternal: Device Not Found"); 
	if((keyBits!=0x01)||(KeyIdx<1||KeyIdx>128))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_VerifyInternal: EncAttr Error");
	if(!SignedData||!retDecrypto||SignedDataLen!=256)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_VerifyInternal: Parameter Error"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_VerifyInternal: Device Closed"); 

	//签名
	ucRet=SENC_CMD_Alternative_VerifyInternal(pstEncDev,keyBits,KeyIdx,SignedData,retDecrypto);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	*retDecryptoLen=256;

	return SENC_SUCCESS;
}

SENC_API unsigned int SENC_Alternative_PBKDF2Encrypt(SENCHANDLE IN SencDevHandle,
													 unsigned char HashMacAlgo,
													 unsigned char HashSaltAttr,
													 unsigned int iteration,
													 unsigned int exportKeyLen,
													 unsigned char* IN inPwData,
													 unsigned int IN inPwDataLen,
													 unsigned char* IN inSaltData,
													 unsigned int IN inSaltDataLen,
													 unsigned char* OUT exportKeydata)
{
	SENCryptCard* pstEncDev=NULL;
	unsigned int ucRet = 0;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_Alternative_PBKDF2Encrypt: Device Not Found"); 
	if((HashSaltAttr<1||HashSaltAttr>3)||(HashMacAlgo<1||HashMacAlgo>3))
		return ERROR_LOG(SENC_ERROR_ENCRYPTION_ATTRIBUTES_ERROR,"SENC_Alternative_PBKDF2Encrypt: EncAttr Error");
	if(!inPwData||!inSaltData||!exportKeydata)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_Alternative_PBKDF2Encrypt: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_Alternative_PBKDF2Encrypt: Device Closed"); 

	//签名
	ucRet=SENC_CMD_Alternative_PBKDF2Encrypt(pstEncDev,HashMacAlgo,HashSaltAttr,iteration,exportKeyLen,inSaltData,inSaltDataLen,inPwData,inPwDataLen,exportKeydata);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

#endif

#if defined __DATA_PROTECTOR_ON__
//签发用户公钥
SENC_API unsigned int SENC_DataProtector_SignUserPubKey(SENCHANDLE IN SencDevHandle,
														UserPubKey* IN  userkey,
														UserPubKey* OUT userkey_new)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_SignUserPubKey: Device Not Found"); 
	if(!userkey||!userkey_new)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_SignUserPubKey: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_SignUserPubKey: Device Closed"); 

	return SENC_CMD_DataProtector_SignUserPubKey(pstEncDev,userkey,userkey_new);
}
//生成云端秘钥
SENC_API unsigned int SENC_DataProtector_GenCloudKey(SENCHANDLE IN SencDevHandle,
													 KeyRecordRequest* IN req, 
													 UserPubKey* IN userPubKey,
													 KeyRecord* OUT key)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_GenCloudKey: Device Not Found"); 
	if(!req||!key||!userPubKey)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_GenCloudKey: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_GenCloudKey: Device Closed"); 

	return SENC_CMD_DataProtector_GenWebKey(pstEncDev,req,userPubKey,key);
}
//设置云端秘钥有效期
SENC_API unsigned int SENC_DataProtector_SetWebKeyPeriod(SENCHANDLE IN SencDevHandle,
														 KeyRecord* IN key, 
														 UserPubKey* IN userPubKey,
														 KeyPeriod* IN keyPeriod, 
														 KeyRecord* OUT key_new)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_SetWebKeyPeriod: Device Not Found"); 
	if(!key||!keyPeriod||!userPubKey||!key_new)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_SetWebKeyPeriod: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_SetWebKeyPeriod: Device Closed"); 

	return SENC_CMD_DataProtector_SetWebKeyPeriod(pstEncDev,key,userPubKey,keyPeriod,key_new);
}
//生成秘钥种子S1
SENC_API unsigned int SENC_DataProtector_GenS1(SENCHANDLE IN SencDevHandle,
											   KeyRecord* IN key, 
											   UserPubKey* IN userkey,
											   License* IN license,
											   S1Cipher* OUT S1_E_Kc,
											   S1Cipher* OUT S1_E_Ku,
											   License* OUT license_new)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_GenS1: Device Not Found"); 
	if(!userkey||!key||!S1_E_Ku||!S1_E_Kc||!license||!license_new)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_GenS1: Parameter Error"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_GenS1: Device Closed"); 

	return SENC_CMD_DataProtector_GenS1(pstEncDev,key,userkey,license,S1_E_Kc,S1_E_Ku,license_new);
}
//签发许可
SENC_API unsigned int SENC_DataProtector_IssueLicense(SENCHANDLE IN SencDevHandle,
													  KeyRecord* IN key, 
													  UserPubKey* IN userkey,
													  uint8_t* IN LicID,
													  License* IN fatherLic,
													  LicenseRequest* IN LicReq,
													  License* OUT Lic)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_IssueLicense: Device Not Found"); 
	if(!userkey||!key||!LicID||!LicReq||!Lic)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_IssueLicense: Parameter Null"); 


	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_IssueLicense: Device Closed"); 

	return SENC_CMD_DataProtector_IssueLicense(pstEncDev,key,userkey,LicID,fatherLic,LicReq,Lic);
}
//转换密文
SENC_API unsigned int SENC_DataProtector_CipherConvert(SENCHANDLE IN SencDevHandle,
													   KeyRecord* IN key, 
													   UserPubKey* IN userkey,
													   License* IN Lic,
													   S1Cipher* IN S1_E_Kc,
													   S1Cipher* OUT S1_E_Ku,
													   License* OUT Lic_new)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_CipherConvert: Device Not Found"); 
	if(!userkey||!key||!S1_E_Kc||!S1_E_Ku)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_CipherConvert: Parameter Null"); 
	if(Lic&&!Lic_new)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_CipherConvert: Parameter Null"); 

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_CipherConvert: Device Closed"); 

	return SENC_CMD_DataProtector_CipherConvert(pstEncDev,key,userkey,Lic,S1_E_Kc,S1_E_Ku,Lic_new);
}

SENC_API unsigned int SENC_DataProtector_SetMacCalculateKey(SENCHANDLE IN SencDevHandle,
													   uint8_t* IN UserData, 
													   uint32_t IN UserDataLen)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_SetMacCalculateKey: Device Not Found"); 
	if(!UserData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_SetMacCalculateKey: Parameter Null"); 
	if(UserDataLen>768)
		return ERROR_LOG(SENC_ERROR_DATA_OVERFLOW,"SENC_DataProtector_SetMacCalculateKey: User Data Too Long"); 

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_SetMacCalculateKey: Device Closed"); 

	return SENC_CMD_DataProtector_SetMacCalculateKey(pstEncDev,UserData,UserDataLen);
}


SENC_API unsigned int SENC_DataProtector_GetRTCTime(SENCHANDLE IN SencDevHandle,
													uint64_t* OUT lpRTCtime)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_GetRTCTime: Device Not Found"); 
	if(!lpRTCtime)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_GetRTCTime: Parameter Null"); 

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_GetRTCTime: Device Closed"); 

	return SENC_CMD_DataProtector_GetRTCTime(pstEncDev,lpRTCtime);
}

SENC_API unsigned int SENC_DataProtector_GetSupportedAlgorithm(SENCHANDLE IN SencDevHandle,
															   uint8_t* OUT uiSupportedAlgo)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_GetSupportedAlgorithm: Device Not Found"); 
	if(!uiSupportedAlgo)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_GetSupportedAlgorithm: Parameter Null"); 

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_GetSupportedAlgorithm: Device Closed"); 

	return SENC_CMD_DataProtector_GetSupportedAlgorithm(pstEncDev,uiSupportedAlgo);
}

SENC_API unsigned int SENC_DataProtector_SetRTCTime(SENCHANDLE IN SencDevHandle,
													uint8_t* IN Pincode, 
													uint32_t IN PincodeLen,
													uint64_t* IN TimeStamp)
{
	SENCryptCard* pstEncDev=NULL;

	if(!SencDevHandle) 
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"SENC_DataProtector_SetRTCTime: Device Not Found"); 
	if(!Pincode||!TimeStamp)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"SENC_DataProtector_SetRTCTime: Parameter Null"); 
	if(PincodeLen<8)
		return ERROR_LOG(SENC_ERROR_PARAMETER_LENGTH_ERROR,"SENC_DataProtector_SetRTCTime: Parameter Too Short"); 

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if(pstEncDev->OpenSign==FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED,"SENC_DataProtector_SetRTCTime: Device Closed"); 

	return SENC_CMD_DataProtector_SetRTCTime(pstEncDev,Pincode,TimeStamp);
}



//获取板卡初始化状态
unsigned int SENC_DataProtector_GetChipInitStatus(SENCHANDLE IN SencDevHandle,
												  unsigned char* OUT OutEcState,
												  unsigned int* OUT OutEcStateLen)
{
	SENCryptCard* pstEncDev = NULL;
	unsigned int ucRet = 0;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_DataProtector_GetChipInitStatus: Handle Null");
	if (!OutEcState || !OutEcStateLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_DataProtector_GetChipInitStatus: Parameter Null");

	pstEncDev = SencHandle2Ptr(SencDevHandle);					//指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_DataProtector_GetChipInitStatus: Device Closed");

	ucRet = SENC_CMD_DataProtector_GetChipInitStatus(pstEncDev, OutEcState);
	if (ucRet != SENC_SUCCESS)
		return ucRet;

	*OutEcStateLen = 1;
	return SENC_SUCCESS;
}

//从板卡获取初始化请求包
unsigned int SENC_DataProtector_GetInitReq(SENCHANDLE IN SencDevHandle,
										   ChipInitRequest* OUT Req,
										   uint8_t* OUT CaCert,
										   uint32_t* OUT CaCertLen,
										   uint8_t* OUT Cert,
										   uint32_t* OUT CertLen,
										   uint8_t* OUT Pri,
										   uint8_t* OUT Pub)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_DataProtector_GetInitReq: Device Not Found");
	if (!CaCert || !CaCertLen || !Cert || !CertLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_DataProtector_GetInitReq: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_DataProtector_GetInitReq: Device Closed");

	return SENC_CMD_DataProtector_GetInitReq(pstEncDev, Req, CaCert, CaCertLen, Cert, CertLen,Pri,Pub);
}
//板卡执行初始化请求包
unsigned int SENC_DataProtector_ChipInit(SENCHANDLE IN SencDevHandle,
										 ChipInitCommand IN Cmd,
										 uint8_t * IN CaCert,
										 uint32_t IN CaCertLen,
										 uint8_t * IN Cert,
										 uint32_t IN CertLen)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_DataProtector_ChipInit: Device Not Found");
	if (!CaCert || !Cert)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_DataProtector_ChipInit: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_DataProtector_ChipInit: Device Closed");

	return SENC_CMD_DataProtector_ChipInit(pstEncDev, Cmd, CaCert, CaCertLen, Cert, CertLen);
}
//从板卡获取认证管理员锁数据包
unsigned int SENC_DataProtector_GetAuthPackage(SENCHANDLE IN SencDevHandle,
											   AuthAdminKey* OUT pkg)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_DataProtector_GetAuthPackage: Device Not Found");
	if (!pkg)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_DataProtector_GetAuthPackage: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_DataProtector_GetAuthPackage: Device Closed");

	return SENC_CMD_DataProtector_GetAuthPackage(pstEncDev, pkg);
}

//创建KeyChain
unsigned int SENC_KeyManager_CreateKeyChain(SENCHANDLE IN SencDevHandle,
											KeychainCreateReq IN KCCreateReq,
											uint32_t IN KCCreateReqLen,
											uint8_t* IN CaCert,
											uint32_t IN CaCertLen,
											uint8_t* IN FirmailCert,
											uint32_t IN FirmailCertLen,
											uint8_t* IN KeyBagId,
											KeychainCreateCode* OUT KCCreateCode,
											uint32_t* OUT KCCreateCodeLen)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_KeyManager_CreateKeyChain: Device Not Found");
	if (!CaCert || !FirmailCert || !KeyBagId || !KCCreateCode || !KCCreateCodeLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_KeyManager_CreateKeyChain: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_KeyManager_CreateKeyChain: Device Closed");

	return SENC_CMD_KeyManager_CreateKeyChain(pstEncDev, KCCreateReq, KCCreateReqLen, CaCert, CaCertLen, FirmailCert, FirmailCertLen, KeyBagId, KCCreateCode, KCCreateCodeLen);
}

//签发BindCode
unsigned int SENC_KeyManager_BindCode(SENCHANDLE IN SencDevHandle,
									  KeybagBindCode IN KBBindCode,
									  uint32_t IN KBBindCodeLen,
									  uint8_t* IN CaCert,
									  uint32_t IN CaCertLen,
									  uint8_t* IN KeyBagCert,
									  uint32_t IN KeyBagCertLen,
									  uint8_t* OUT BindCodePlain,
									  uint8_t* OUT PhoneNumber,
									  uint8_t* OUT BindCodeCipher,
									  uint32_t* OUT BindCodeCipherLen)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_KeyManager_BindCode: Device Not Found");
	if (!CaCert || !KeyBagCert || !BindCodePlain || !PhoneNumber || !BindCodeCipher || !BindCodeCipherLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_KeyManager_BindCode: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_KeyManager_BindCode: Device Closed");

	return SENC_CMD_KeyManager_BindCode(pstEncDev, KBBindCode, KBBindCodeLen, CaCert, CaCertLen, KeyBagCert, KeyBagCertLen, BindCodePlain, PhoneNumber, BindCodeCipher, BindCodeCipherLen);
}

//创建Circle
unsigned int SENC_KeyManager_CreateCircle(SENCHANDLE IN SencDevHandle,
										  uint8_t* IN circle_id,
										  KeybagCreateCircleReq IN KBCreateCircleReq,
										  uint32_t IN KBCreateCircleReqLen,
										  uint8_t* IN BindCodeVrfPkgCipher,
										  uint32_t IN BindCodeVrfPkgCipherLen,
										  uint32_t* OUT TimeStamp,
										  KeybagCircle* OUT KBCircle,
										  uint32_t* OUT KBCircleLen)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_KeyManager_CreateCircle: Device Not Found");
	if (!BindCodeVrfPkgCipher || !TimeStamp || !KBCircle || !KBCircleLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_KeyManager_CreateCircle: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_KeyManager_CreateCircle: Device Closed");

	return SENC_CMD_KeyManager_CreateCircle(pstEncDev, circle_id, KBCreateCircleReq, KBCreateCircleReqLen, BindCodeVrfPkgCipher, BindCodeVrfPkgCipherLen, TimeStamp, KBCircle, KBCircleLen);
}

//加入Circle
unsigned int SENC_KeyManager_JoinCircle(SENCHANDLE IN SencDevHandle,
										KeybagCircle IN KBOldCircle,
										uint32_t IN KBOldCircleLen,
										KeybagJoinCircleApprove IN KBJoinCircleApprove,
										uint32_t IN KBJoinCircleApproveLen,
										uint8_t* IN BindCodeVrfPkgCipher,
										uint32_t IN BindCodeVrfPkgCipherLen,
										uint32_t* OUT TimeStamp,
										KeybagCircle* OUT KBNewCircle,
										uint32_t* OUT KBNewCircleLen)
{
	SENCryptCard* pstEncDev = NULL;

	if (!SencDevHandle)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND, "SENC_KeyManager_JoinCircle: Device Not Found");
	if (!BindCodeVrfPkgCipher || !TimeStamp || !KBNewCircle || !KBNewCircleLen)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR, "SENC_KeyManager_JoinCircle: Parameter Null");

	//handle转为结构体指针
	pstEncDev = SencHandle2Ptr(SencDevHandle);  //指针转换
	if (pstEncDev->OpenSign == FALSE)
		return ERROR_LOG(SENC_ERROR_DEVICE_CLOSED, "SENC_KeyManager_JoinCircle: Device Closed");

	return SENC_CMD_KeyManager_JoinCircle(pstEncDev, KBOldCircle, KBOldCircleLen, KBJoinCircleApprove, KBJoinCircleApproveLen, BindCodeVrfPkgCipher, BindCodeVrfPkgCipherLen, TimeStamp, KBNewCircle, KBNewCircleLen);
}

#endif