#ifndef LIBSENC_SENC_INTERNALAPI_H_
#define LIBSENC_SENC_INTERNALAPI_H_

#include "libsenc.h"

#define			SENC_CMD_HEAD													0x55
#define			SENC_PLAINTEXT_SIGN												0x00
#define			SENC_CIPHER_SIGN												0x11

//*函数：SENC_CMD_Transfer()
//*功能：SENC加密卡数据传输||Data transfer
//*参数：SENCryptCard		sencDev,				//加密卡设备handle
//		unsigned char	EncryptType					//加密类型
//		unsigned char	WriteEndPoint				//发送端口
//		unsigned char	ReadEndPoint				//接收端口
// 		unsigned char*	pucSendData					//接收数据
//		unsigned int	uiSendLength				//接收数据长度
// 		unsigned char*	pucReadData					//接收数据
//		unsigned int	uiReadLength				//接收数据长度
//*日期：2016/10/24
//by Wangjf
unsigned int SENC_CMD_Transfer(SENCryptCard*			sencDev,
							   unsigned char			EncryptType,
							   unsigned char			WriteEndPoint,
							   unsigned char			ReadEndPoint,
							   unsigned char*			pucSendData,	
							   unsigned int				uiSendLength,	
							   unsigned char*			pucReadData,
							   unsigned int				uiReadLength);


#endif //LIBSENC_SENC_INTERNALAPI_H_