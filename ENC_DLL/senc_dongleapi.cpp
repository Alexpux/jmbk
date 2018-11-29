#include "senc_cmd_frame.h"
#include "libsenc.h"
#include "senc_dongleapi.h"
#include "itoken.h"
#include "senc_assist.h"
#include "PtrConverter.h"
#include "senc_error.h"
#include <stdlib.h>
#if defined(linux) || defined(__linux__)
#include <string.h>
#endif



//*函数：SENC_DongleAPI_NewDongle()
//*功能：绑定当前插入精锐锁||Key exchange
//*参数：SENCryptCard*	sencDev					//加密卡设备handle
//*日期：2016/11/25
//by Wangjf
unsigned int SENC_DongleAPI_NewDongle(SENCryptCard*	sencDev){
	unsigned long ctxlen,protocol,sendLen,recvLen;
	unsigned int ret;
	ITOKEN_CONTEXT ctx,tctx;
	unsigned char DecFlashKey[10],EncFlashKey[10],keysign1,keysign2;

	unsigned char keyid[8], AuthKey[16],sendBuf[1024],recvBuf[1024],EncKey[16];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"New Dongle: Device Not Found");

	//enum dongle list
	ctxlen=sizeof(ctx);
	ret=SKeyListKey(&ctx,&ctxlen);
	memcpy(&tctx,&ctx,sizeof(ITOKEN_CONTEXT));
	if(ret==SKEY_INSUFFICIENT_BUFFER){
		return ERROR_LOG(SENC_ERROR_DONGLE_TOO_MANY_DONGLES,"New Dongle: Too Mang Dongles");
	}
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle: Enumeration Failed");
	}
	if(ctxlen==0){
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"New Dongle: No Dongle Found");
	}

	//connect dongle
	protocol=SKEY_PROTOCOL_USB;
	ret=SKeyConnect(&ctx,0,protocol,&protocol);
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle: Connection Failed");
	}

	//create file sys
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_CREATE_FLIE_SYSTEM,22);
	sendLen=22;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Create Sys File: Transmit Failed");
	}
	if(recvBuf[recvLen-2] == 0x69 && recvBuf[recvLen-1] == 0x01)
		goto created;
	else if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Create Sys File: iToken Error");
	}

	//create key file
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_CREATE_KEY_FILE,13);
	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Create Key File: Transmit Failed");
	}
	if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Create Key File: iToken Error");
	}

	//install pin
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_INSTALL_PIN,20);
	sendLen=20;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Install PIN: Transmit Failed");
	}
	if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Install PIN: iToken Error");
	}

	//enable secure
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_ENABLE_SECURE,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Enable Secure Feature: Transmit Failed");
	}
	if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Enable Secure Feature: iToken Error");
	}

created:

	//install key 1
	// 	RAND_bytes(AuthKey,sizeof(AuthKey));
	RandGenerator(AuthKey,sizeof(AuthKey));
	// 	memcpy(AuthKey,CMD_TEST_AUTHKEY,16);
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_INSTALL_KEY,12);
	memcpy(sendBuf+12,AuthKey,16);
	sendLen=28;

	for(int i=0;i<128;i++){
		memset(recvBuf,0x00,sizeof(recvBuf));
		sendBuf[5]=i&0xff;
		keysign1=sendBuf[5];
		recvLen=sizeof(recvBuf);
		ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
		if(ret!=SENC_SUCCESS){
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Install Key 1: Transmit Failed");
		}
		if(recvBuf[recvLen-2] == 0x69 && recvBuf[recvLen-1] == 0x85)
			continue;
		else if(recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
		{
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Install Key 1: iToken Error");
		}
		break;
	}


	//install key 2
	// 		RAND_bytes(EncKey,sizeof(EncKey));
	RandGenerator(EncKey,sizeof(EncKey));
	// 	memcpy(EncKey,CMD_TEST_FLASHKEY,16);
	memset(sendBuf,0,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_INSTALL_KEY,12);
	sendBuf[7]=0x07;
	memcpy(sendBuf+12,EncKey,16);
	sendLen=28;

	for(int i=0;i<128;i++){
		memset(recvBuf,0x00,sizeof(recvBuf));
		sendBuf[5]=i&0xff;
		keysign2=sendBuf[5];
		recvLen=sizeof(recvBuf);
		ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
		if(ret!=SENC_SUCCESS){
			SKeyDisconnect(&ctx,SKEY_LEAVE);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Install Key 2: Transmit Failed");
		}
		if(recvBuf[recvLen-2] == 0x69 && recvBuf[recvLen-1] == 0x85)
			continue;
		else if(recvLen!=0x02||recvBuf[recvLen-2]!=0x90||recvBuf[recvLen-1]!=0x00){
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Install Key 2: iToken Error");
		}
		break;
	}

	//get dongle id
	memcpy(sendBuf,CMD_GET_ID,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Get Dongle ID: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Get Dongle ID: iToken Error");
	}
	memcpy(keyid,recvBuf,8);


	// 	//test
	// 	memcpy(AuthKey,CMD_TEST_AUTHKEY,16);


	//sending relative info to senc card for flash key
	ret=SENC_CMD_Dongle_NewDongle(sencDev,keyid,keysign1,keysign2,AuthKey,DecFlashKey);
	if(ret!=SENC_SUCCESS)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ret;
	}

	//encrypt flash key
	memcpy(sendBuf,CMD_FLASH_KEY_ENC,5);
	sendBuf[3]=keysign2;
	memcpy(sendBuf+5,DecFlashKey,8);
	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"New Dongle - Enc Flash Key: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"New Dongle - Enc Flash Key: iToken Error");
	}
	memcpy(EncFlashKey,recvBuf,8);

	//disconnect dongle
	SKeyDisconnect(&ctx, SKEY_LEAVE);

	//dongle part done, sending encrypted flash key to senc card
	ret=SENC_CMD_Dongle_SetEncryptedKey(sencDev,EncFlashKey);
	if(ret!=SENC_SUCCESS)
		return ret;


	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));


	return SENC_SUCCESS;
}


//*函数：SENC_DongleAPI_GetRndNum()
//*功能：获取随机数据||Get random number
//*参数：SENCryptCard*	sencDev					//加密卡设备handle
//		unsigned char*	retData,				//返回随机数数据
//*日期：2016/11/25
//by Wangjf
unsigned int SENC_DongleAPI_GetRndNum(SENCryptCard*	sencDev,unsigned char* keyIdx1, unsigned char* keyIdx2,unsigned char* RandNum, unsigned char* EncFlashKey){
	unsigned long ctxlen,protocol,sendLen,recvLen;
	unsigned int ret;
	ITOKEN_CONTEXT ctx;
	unsigned char keyid[8],sendBuf[1024],recvBuf[1024];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Get Rnd Num: Device Not Found");

	//dongle enum
	ctxlen=sizeof(ctx);
	ret=SKeyListKey(&ctx,&ctxlen);
	if(ret==SKEY_INSUFFICIENT_BUFFER){
		return ERROR_LOG(SENC_ERROR_DONGLE_TOO_MANY_DONGLES,"Get Rnd Num: Too Mang Dongles");
	}
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"Get Rnd Num: Enumeration Failed");
	}
	if(ctxlen==0){
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"Get Rnd Num: No Dongle Found");
	}

	//dongle connnection
	protocol = SKEY_PROTOCOL_USB;
	ret = SKeyConnect(&ctx, 0, protocol, &protocol);
	if (ret != SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"Get Rnd Num: Connection Failed");
	}

	//get dongle id
	memcpy(sendBuf,CMD_GET_ID,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"Get Rnd Num - Get Dongle ID: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"Get Rnd Num - Get Dongle ID: iToken Error");
	}
	memcpy(keyid,recvBuf,8);

	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));

	//send dongle ID to senc card
	ret=SENC_CMD_Dongle_GetVerifyRand(sencDev,keyid,keyIdx1,keyIdx2,RandNum,EncFlashKey);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ret;
	}

	SKeyDisconnect(&ctx, SKEY_LEAVE);

	return SENC_SUCCESS;
}

//*函数：SENC_DongleAPI_DeletePlugDongle()
//*功能：删除当前出入锁|| Delete plug dongle
//*参数：SENCryptCard*	sencDev					//加密卡设备handle
//*日期：2016/11/25
//by Wangjf
unsigned int SENC_DongleAPI_DeletePlugDongle(SENCryptCard*	sencDev){
	unsigned long ctxlen,protocol,sendLen,recvLen;
	unsigned int ret;
	ITOKEN_CONTEXT ctx;
	unsigned char keyid[8],sendBuf[1024],recvBuf[1024];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"DeletePlugDongle: Device Not Found");

	//dongle enum
	ctxlen=sizeof(ctx);
	ret=SKeyListKey(&ctx,&ctxlen);
	if(ret==SKEY_INSUFFICIENT_BUFFER){
		return ERROR_LOG(SENC_ERROR_DONGLE_TOO_MANY_DONGLES,"DeletePlugDongle: Too Mang Dongles");
	}
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DeletePlugDongle: Enumeration Failed");
	}
	if(ctxlen==0){
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"DeletePlugDongle: No Dongle Found");
	}

	//dongle connnection
	protocol = SKEY_PROTOCOL_USB;
	ret = SKeyConnect(&ctx, 0, protocol, &protocol);
	if (ret != SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DeletePlugDongle: Connection Failed");
	}

	//get dongle id
	memcpy(sendBuf,CMD_GET_ID,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DeletePlugDongle - Get Dongle ID: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DeletePlugDongle - Get Dongle ID: iToken Error");
	}
	memcpy(keyid,recvBuf,8);

	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));

	//send dongle ID to senc card
	ret=SENC_CMD_Dongle_Delete(sencDev,keyid);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ret;
	}

	SKeyDisconnect(&ctx, SKEY_LEAVE);

	return SENC_SUCCESS;
}



//*函数：SENC_DongleAPI_VerifyStep()
//*功能：验证加密锁||Verify dongle
//*参数：SENCryptCard*	sencDev					//加密卡设备handle
//		unsigned char	inKeyIdx,				//内部认证秘钥标识
//		unsigned char*	inRndNum,				//随机数数据
//*日期：2016/11/25
//by Wangjf
unsigned int SENC_DongleAPI_VerifyStep(SENCryptCard* sencDev,unsigned char keyidx1, unsigned char keyidx2,unsigned char* inRndNum,unsigned char* inEncFlashKey){
	unsigned long ctxlen,protocol,sendLen,recvLen;
	unsigned int ret;
	ITOKEN_CONTEXT ctx;
	unsigned char keyid[8],challenge[8],sendBuf[1024],recvBuf[1024];
	unsigned char DecFlashKey[10];

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"DongleVerifyStep: Device Not Found");

	//dongle enum
	ctxlen=sizeof(ctx);
	ret=SKeyListKey(&ctx,&ctxlen);
	if(ret==SKEY_INSUFFICIENT_BUFFER){
		return ERROR_LOG(SENC_ERROR_DONGLE_TOO_MANY_DONGLES,"DongleVerifyStep: Too Mang Dongles");
	}
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerifyStep: Enumeration Failed");
	}
	if(ctxlen==0){
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"DongleVerifyStep: No Dongle Found");
	}

	//dongle connection
	protocol = SKEY_PROTOCOL_USB;
	ret = SKeyConnect(&ctx, 0, protocol, &protocol);
	if (ret != SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerifyStep: Connection Failed");
	}

	//get dongle id
	memcpy(sendBuf,CMD_GET_ID,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerifyStep - Get Dongle ID: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleVerifyStep - Get Dongle ID: iToken Error");
	}
	memcpy(keyid,recvBuf,8);

	//internal auth
	memcpy(sendBuf,CMD_INTAUTH,5);
	sendBuf[3]=keyidx1;
	memcpy(sendBuf+5,inRndNum,8);

	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerifyStep - Internal Auth: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleVerifyStep - Internal Auth: iToken Error");
	}
	memcpy(challenge,recvBuf,8);


	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));

	//decrypt flash key
	memcpy(sendBuf,CMD_FLASH_KEY_DEC,5);
	sendBuf[3]=keyidx2;
	memcpy(sendBuf+5,inEncFlashKey,8);
	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerifyStep - Decrypt Flash Key: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleVerifyStep - Decrypt Flash Key: iToken Error");
	}
	memcpy(DecFlashKey,recvBuf,8);


	ret=SENC_CMD_Dongle_Verify(sencDev,keyid,challenge,DecFlashKey);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ret;
	}

	SKeyDisconnect(&ctx, SKEY_LEAVE);

	return SENC_SUCCESS;
}

//*函数：SENC_DongleAPI_NewDongle_Group()
//*功能：批量绑定当前插入精锐锁|| Bound plug dongle for senc cards group
//*参数：SENCryptCard*	sencDev					//加密卡设备handle
//*日期：2016/11/25
//by Wangjf
unsigned int SENC_DongleAPI_NewDongle_Group(SENCryptCardList* DevList){
	unsigned long ctxlen,protocol,sendLen,recvLen;
	unsigned int ret;
	ITOKEN_CONTEXT ctx,tctx;
	unsigned char DecFlashKey[10],EncFlashKey[10],keysign1,keysign2;
	SENCHANDLE devHandle;
	SENCryptCard* pstEncDev=NULL;


	unsigned char keyid[8], AuthKey[16],sendBuf[1024],recvBuf[1024],EncKey[16];

	//param check
	if(!DevList)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"DongleNewMultiple: Device Not Found");

	//enum dongle list
	ctxlen=sizeof(ctx);
	ret=SKeyListKey(&ctx,&ctxlen);
	memcpy(&tctx,&ctx,sizeof(ITOKEN_CONTEXT));
	if(ret==SKEY_INSUFFICIENT_BUFFER){
		return ERROR_LOG(SENC_ERROR_DONGLE_TOO_MANY_DONGLES,"DongleNewMultiple: Too Mang Dongles");
	}
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple: Enumeration Failed");
	}
	if(ctxlen==0){
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"DongleNewMultiple: No Dongle Found");
	}

	//connect dongle
	protocol=SKEY_PROTOCOL_USB;
	ret=SKeyConnect(&ctx,0,protocol,&protocol);
	if(ret!=SENC_SUCCESS){
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple: Connection Failed");
	}

	//create file sys
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_CREATE_FLIE_SYSTEM,22);
	sendLen=22;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Create Sys File: Transmit Failed");
	}
	if(recvBuf[recvLen-2] == 0x69 && recvBuf[recvLen-1] == 0x01)
		goto created;
	else if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Create Sys File: iToken Error");
	}

	//create key file
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_CREATE_KEY_FILE,13);
	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Create Key File: Transmit Failed");
	}
	if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Create Key File: iToken Error");
	}

	//install pin
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_INSTALL_PIN,20);
	sendLen=20;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Install PIN: Transmit Failed");
	}
	if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Install PIN: iToken Error");
	}

	//enable secure
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_ENABLE_SECURE,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Enable Secure Feature: Transmit Failed");
	}
	if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Enable Secure Feature: iToken Error");
	}

created:

	//install key 1
	// 	RAND_bytes(AuthKey,sizeof(AuthKey));
	RandGenerator(AuthKey,sizeof(AuthKey));
	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_INSTALL_KEY,12);
	memcpy(sendBuf+12,AuthKey,16);
	sendLen=28;

	for(int i=0;i<128;i++){
		memset(recvBuf,0x00,sizeof(recvBuf));
		sendBuf[5]=i&0xff;
		keysign1=sendBuf[5];
		recvLen=sizeof(recvBuf);
		ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
		if(ret!=SENC_SUCCESS){
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Install Key 1: Transmit Failed");
		}
		if(recvBuf[recvLen-2] == 0x69 && recvBuf[recvLen-1] == 0x85)
			continue;
		else if (recvLen != 0x02 || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
		{
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Install Key 1: iToken Error");
		}
		break;
	}


	//install key 2
	// 		RAND_bytes(EncKey,sizeof(EncKey));
	RandGenerator(EncKey,sizeof(EncKey));
	memset(sendBuf,0,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));
	memcpy(sendBuf,CMD_INSTALL_KEY,12);
	sendBuf[7]=0x07;
	memcpy(sendBuf+12,EncKey,16);
	sendLen=28;

	for(int i=0;i<128;i++){
		memset(recvBuf,0x00,sizeof(recvBuf));
		sendBuf[5]=i&0xff;
		keysign2=sendBuf[5];
		recvLen=sizeof(recvBuf);
		ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
		if(ret!=SENC_SUCCESS){
			SKeyDisconnect(&ctx,SKEY_LEAVE);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Install Key 2: Transmit Failed");
		}
		if(recvBuf[recvLen-2] == 0x69 && recvBuf[recvLen-1] == 0x85)
			continue;
		else if(recvLen!=0x02||recvBuf[recvLen-2]!=0x90||recvBuf[recvLen-1]!=0x00){
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Install Key 2: iToken Error");
		}
		break;
	}

	//get dongle id
	memcpy(sendBuf,CMD_GET_ID,5);
	sendLen=5;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Get Dongle ID: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect(&ctx, SKEY_LEAVE);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Get Dongle ID: iToken Error");
	}
	memcpy(keyid,recvBuf,8);

	for(int i=0;i<(int)DevList->DevNums;i++){
		//sending relative info to senc card for flash key
		ret=SENC_Open(DevList->devs[i],&devHandle);
		if(ret!=SENC_SUCCESS)
			break;
		pstEncDev = SencHandle2Ptr(devHandle);  //指针转换

		ret=SENC_CMD_Dongle_NewDongle(pstEncDev,keyid,keysign1,keysign2,AuthKey,DecFlashKey);
		if(ret!=SENC_SUCCESS)
			break;

		//encrypt flash key
		memcpy(sendBuf,CMD_FLASH_KEY_ENC,5);
		sendBuf[3]=keysign2;
		memcpy(sendBuf+5,DecFlashKey,8);
		sendLen=13;
		recvLen=sizeof(recvBuf);
		ret=SKeyTransmit(&ctx,sendBuf,sendLen,recvBuf,&recvLen);
		if(ret!=SENC_SUCCESS){
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleNewMultiple - Enc Flash Key: Transmit Failed");
		}
		if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
		{
			SKeyDisconnect(&ctx, SKEY_LEAVE);
			return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleNewMultiple - Enc Flash Key: iToken Error");
		}
		memcpy(EncFlashKey,recvBuf,8);

		ret=SENC_CMD_Dongle_SetEncryptedKey(pstEncDev,EncFlashKey);
		if(ret!=SENC_SUCCESS)
			break;

		ret=SENC_Close(devHandle);
		if(ret!=SENC_SUCCESS)
			break;
	}

	//disconnect dongle
	SKeyDisconnect(&ctx, SKEY_LEAVE);


	memset(AuthKey,0,sizeof(AuthKey));
	memset(DecFlashKey,0,sizeof(DecFlashKey));
	memset(EncFlashKey,0,sizeof(EncFlashKey));

	return ret;
}

//*函数：SENC_DongleAPI_Verify()
//*功能：验证加密锁||Verify dongle
//*参数：SENCryptCard*	sencDev					//加密卡设备handle
//*日期：2017/04/24
//by Wangjf
unsigned int SENC_DongleAPI_Verify(SENCryptCard* sencDev){
	unsigned long ctxlen=0,protocol,sendLen,recvLen;
	unsigned int ret;
	int dev_offset=-1,offset,devnum;
	ITOKEN_CONTEXT *ctx;
	void* TargetDongle;
	unsigned char keyid[8],sendBuf[1024],recvBuf[1024],RandNum[8],EncFlashKey[8],DecFlashKey[8],challenge[8],keyidx1,keyidx2;

	//param check
	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"DongleVerify: Device Not Found");

	//check device number
	ret=SKeyListKey(NULL,&ctxlen);
	if(ctxlen==0){
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"DongleVerify: No Dongle Found");
	}
	offset=sizeof(ITOKEN_CONTEXT);
	devnum=ctxlen/offset;

	//enum dongles
	ctxlen=offset*devnum;
	ctx=(ITOKEN_CONTEXT*)malloc(sizeof(ITOKEN_CONTEXT)*devnum);
	ret=SKeyListKey(ctx,&ctxlen);
	if(ret!=SENC_SUCCESS){
		free(ctx);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerify: Enumeration Failed");
	}

	//find target dongle
	int t=0;
	while(t<devnum*offset){

		//dongle connnection
		protocol = SKEY_PROTOCOL_USB;

		TargetDongle=(char *)ctx+t;

		ret = SKeyConnect((ITOKEN_CONTEXT*)TargetDongle, 0, protocol, &protocol);
		if (ret != SENC_SUCCESS){
			free(ctx);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerify: Connection Failed");
		}

		//get dongle id
		memcpy(sendBuf,CMD_GET_ID,5);
		sendLen=5;
		recvLen=sizeof(recvBuf);
		ret=SKeyTransmit((ITOKEN_CONTEXT*)TargetDongle,sendBuf,sendLen,recvBuf,&recvLen);
		if(ret!=SENC_SUCCESS){
			SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
			free(ctx);
			return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerify - Get Dongle ID: Transmit Failed");
		}
		if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
		{
			SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
			free(ctx);
			return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleVerify - Get Dongle ID: iToken Error");
		}
		memcpy(keyid,recvBuf,8);

		memset(sendBuf,0x00,sizeof(sendBuf));
		memset(recvBuf,0x00,sizeof(recvBuf));

		//send dongle ID to senc card
		ret=SENC_CMD_Dongle_GetVerifyRand(sencDev,keyid,&keyidx1,&keyidx2,RandNum,EncFlashKey);
		if(ret==SENC_SUCCESS){
			dev_offset=t;
			break;
		}

		SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
		t+=offset;
	}
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect(ctx, SKEY_LEAVE);
		free(ctx);
		return ret;
	}
	if(dev_offset==-1){
		free(ctx);
		return ERROR_LOG(SENC_ERROR_DONGLE_NO_DONGLE,"DongleVerify: Cannot Found Target Dongle");
	}

	//internal auth
	memcpy(sendBuf,CMD_INTAUTH,5);
	sendBuf[3]=keyidx1;
	memcpy(sendBuf+5,RandNum,8);

	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit((ITOKEN_CONTEXT*)TargetDongle,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
		free(ctx);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerify - Internal Auth: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
		free(ctx);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleVerify - Internal Auth: iToken Error");
	}
	memcpy(challenge,recvBuf,8);


	memset(sendBuf,0x00,sizeof(sendBuf));
	memset(recvBuf,0x00,sizeof(recvBuf));

	//decrypt flash key
	memcpy(sendBuf,CMD_FLASH_KEY_DEC,5);
	sendBuf[3]=keyidx2;
	memcpy(sendBuf+5,EncFlashKey,8);
	sendLen=13;
	recvLen=sizeof(recvBuf);
	ret=SKeyTransmit((ITOKEN_CONTEXT*)TargetDongle,sendBuf,sendLen,recvBuf,&recvLen);
	if(ret!=SENC_SUCCESS){
		SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
		free(ctx);
		return ERROR_LOG(ret|SENC_ERROR_DONGLES,"DongleVerify - Decrypt Flash Key: Transmit Failed");
	}
	if (recvLen != 0x0A || recvBuf[recvLen-2] != 0x90 || recvBuf[recvLen-1] != 0x00)
	{
		SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
		free(ctx);
		return ERROR_LOG((recvBuf[recvLen-2]<<8|recvBuf[recvLen-1])|SENC_ERROR_DONGLES,"DongleVerify - Decrypt Flash Key: iToken Error");
	}
	memcpy(DecFlashKey,recvBuf,8);


	ret=SENC_CMD_Dongle_Verify(sencDev,keyid,challenge,DecFlashKey);

	SKeyDisconnect((ITOKEN_CONTEXT*)TargetDongle, SKEY_LEAVE);
	free(ctx);
	return ret;

}