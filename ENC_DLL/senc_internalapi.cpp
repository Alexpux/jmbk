#include "senc_usbapi.h"
#include "libsenc.h"
#include "senc_aes.h"
#include "senc_crc.h"
#include "senc_des.h"
#include "senc_assist.h"
#include "senc_internalapi.h"
#include "senc_error.h"
#if defined(linux) || defined(__linux__)
#include <string.h>
#endif




//*函数：SENC_CMD_Transfer()
//*功能：SENC加密卡数据传输||Data transfer
//*参数：SENCryptCard		sencDev,					//加密卡设备handle
//		unsigned char		EncryptType					//安全标识
//		unsigned char		WriteEndPoint				//发送端口
//		unsigned char		ReadEndPoint				//接收端口
// 		unsigned char*		pucSendData					//待发送数据
//		unsigned int		uiSendLength				//待发送数据长度
// 		unsigned char*		pucReadData					//接收数据
//		unsigned int		uiReadLength				//接收数据长度
//*日期：2016/10/24
//by Wangjf
unsigned int SENC_CMD_Transfer(SENCryptCard*		sencDev,				//加密卡设备handle
							   unsigned char		EncryptType,			//安全标识
							   unsigned char		WriteEndPoint,			//发送端口
							   unsigned char		ReadEndPoint,			//接收端口
							   unsigned char*		pucSendData,			//待发送数据
							   unsigned int			uiSendLength,			//待发送数据长度
							   unsigned char*		pucReadData,			//接收数据
							   unsigned int			uiReadLength)			//接收数据长度
{
	unsigned int ucRet = 0;
	unsigned char Rand[4];
	unsigned char SendBuf[SENC_BUFFER_SIZE];
	unsigned char ReadBuf[SENC_BUFFER_SIZE];
	unsigned char tempBuf[SENC_BUFFER_SIZE];

	unsigned int CmdLength;
	unsigned char Mac[8]={0};
	unsigned int crc;

	//param check
	if(!sencDev) return SENC_ERROR_DEVICE_NOT_FOUND;

	if((EncryptType!=SENC_PLAINTEXT_SIGN&&EncryptType!=SENC_CIPHER_SIGN))
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Transfer Error: Secure Head Error"); //SENC_ERROR_PARAMETER_ERROR;
	if(!pucSendData||!pucReadData)
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Transfer Error: Send/Receive Pointer Null"); //SENC_ERROR_PARAMETER_ERROR;
	if(!(((WriteEndPoint==SENC_BULK_ENDPOINT_WRITE_1K)||(WriteEndPoint==SENC_BULK_ENDPOINT_WRITE_2K))&&((ReadEndPoint==SENC_BULK_ENDPOINT_READ_1K)||(ReadEndPoint==SENC_BULK_ENDPOINT_READ_2K)))) 
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Transfer Error: EndPoint Error");//SENC_ERROR_PARAMETER_ERROR;

	if(WriteEndPoint==SENC_BULK_ENDPOINT_WRITE_1K){
		if(ReadEndPoint!=SENC_BULK_ENDPOINT_READ_1K)
			return ERROR_LOG(SENC_ERROR_ENDPOINT_NOT_MATCH,"Transfer Error: EndPoint Not Match");//SENC_ERROR_ENDPOINT_NOT_MATCH;
	}else if(WriteEndPoint==SENC_BULK_ENDPOINT_WRITE_2K){
		if(ReadEndPoint!=SENC_BULK_ENDPOINT_READ_2K)
			return ERROR_LOG(SENC_ERROR_ENDPOINT_NOT_MATCH,"Transfer Error: EndPoint Not Match");//SENC_ERROR_ENDPOINT_NOT_MATCH;
	}

	if((uiSendLength<1||uiSendLength>2048)||(uiReadLength<1||uiReadLength>2048))
		return ERROR_LOG(SENC_ERROR_DATA_OVERFLOW,"Transfer Error: Data Too Long");//SENC_ERROR_DATA_OVERFLOW;

	{
		do 
		{
#if defined(_WIN32)
			CGuard guard(*((CLock*)sencDev->DevLock));
#elif defined(linux) || defined(__linux__)
			AUTO_GUARD(ThreadLock,MUTEX_TYPE,*((MUTEX_TYPE*)sencDev->DevLock))
#endif

			//生成随机数
// 			RAND_bytes(Rand,sizeof(Rand));
			RandGenerator(Rand,sizeof(Rand));

			memset(SendBuf,0x00,sizeof(SendBuf));
			SendBuf[0]=SENC_CMD_HEAD;	//传输命令头0x55
			SendBuf[1]=EncryptType;		//安全标识
			memcpy(SendBuf+2,Rand,4);	//随机数 4 bytes

			switch (EncryptType)
			{
				//标识0x00 明文
			case SENC_PLAINTEXT_SIGN:

				CmdLength=((pucSendData[1]<<8)|pucSendData[2])+3;
				SendBuf[10]=(CmdLength>>8)&0xff;//命令数据长度
				SendBuf[11]=CmdLength&0xff;
				memcpy(SendBuf+12,pucSendData,CmdLength);//命令数据

				crc=Crc16T(SendBuf+1,CmdLength+7);//计算crc
				SendBuf[8]=(crc>>8)&0xff;//mac高2bytes 0x00，低2 bytes为crc
				SendBuf[9]=crc&0xff;

				break;
				//标识0x11 密文
			case SENC_CIPHER_SIGN:
				ucRet=SENC_AES_Dispersion(sencDev,Rand);//根据随机数秘钥分散产生会话秘钥
				if(ucRet!=SENC_SUCCESS)
					return ucRet;

				ucRet=SENC_AES_CmdDataEncrypt(sencDev,pucSendData,SendBuf+12,&CmdLength);//命令数据进行AES加密
				if(ucRet!=SENC_SUCCESS)
					return ucRet;

				SendBuf[10]=(CmdLength>>8)&0xff;//长度为加密后长度
				SendBuf[11]=CmdLength&0xff;
				memcpy(tempBuf,SendBuf+1,5);
				memcpy(tempBuf+5,SendBuf+10,CmdLength+2);

				memset(Mac,0x00,8);
				ucRet=API_calculateMAC(tempBuf,CmdLength+7,((KeyData*)(sencDev->DevCtx))->SessionKey,Mac);//计算MAC
				if(ucRet!=SENC_SUCCESS)
					return ucRet;

				memcpy(SendBuf+6,Mac,4);

				break;
			default:
				return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Transfer Error: Encrypt Type");
			}

			//写入
			ucRet = SENC_Bulk_Write(sencDev,WriteEndPoint,SendBuf,uiSendLength);
			if(ucRet!=SENC_SUCCESS)
				break;

			//读返回数据
			ucRet = SENC_Bulk_Read(sencDev,ReadEndPoint,ReadBuf,uiReadLength);
			if(ucRet!=SENC_SUCCESS)
				break;

			if(ReadBuf[0]!=SENC_CMD_HEAD)
				return ERROR_LOG(SENC_ERROR_RECEIVED_DATA_HEAD_ERROR,"Transfer Error: Received Data Head Error");

			CmdLength=(ReadBuf[10]<<8)|ReadBuf[11];

			//安全标识判断
			switch (ReadBuf[1])
			{
			case SENC_PLAINTEXT_SIGN:
				//crc检查
				crc=Crc16T(ReadBuf+1,CmdLength+7);
				if((unsigned short)crc!=((ReadBuf[8]<<8)|ReadBuf[9]))
					return ERROR_LOG(SENC_ERROR_CRC_ERROR,"Transfer Error: Received Data CRC Error");

				memcpy(pucReadData,ReadBuf+12,CmdLength);

				break;

			case SENC_CIPHER_SIGN:
				memset(tempBuf,0x00,SENC_BUFFER_SIZE);
				memset(Mac,0x00,8);
				memcpy(tempBuf,ReadBuf+1,5);
				memcpy(tempBuf+5,ReadBuf+10,CmdLength+2);

				//读随机数，进行秘钥分散，产生会话秘钥
				memcpy(Rand,ReadBuf+2,4);
				ucRet=SENC_AES_Dispersion(sencDev,Rand);
				if(ucRet!=SENC_SUCCESS)
					return ucRet;

				//MAC计算并验证
				ucRet=API_calculateMAC(tempBuf,CmdLength+7,((KeyData*)(sencDev->DevCtx))->SessionKey,Mac);//计算MAC
				if(ucRet!=SENC_SUCCESS)
					return ucRet;
				if(memcmp(Mac,ReadBuf+6,4)!=0)
					return ERROR_LOG(SENC_ERROR_MAC_ERROR,"Transfer Error: Received Data Mac Error");

				//利用会话秘钥解密加密命令数据
				ucRet=SENC_AES_CmdDataDecrypt(sencDev,ReadBuf+12,pucReadData,CmdLength);
				if(ucRet!=SENC_SUCCESS)
					return ucRet;

				break;

			default:
				return ERROR_LOG(SENC_ERROR_RECEIVED_SECURE_SIGN_ERROR,"Transfer Error: Received Data Secure Sign Error");
			}

		} while (0);

		if(ucRet!=SENC_SUCCESS)
			return ucRet;
	}
// 	Log_CommData(LOGMSG,pucReadData,CmdLength);

	return SENC_SUCCESS;
}


