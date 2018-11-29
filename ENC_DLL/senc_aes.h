#ifndef LIBSENC_SENC_AES_H_
#define LIBSENC_SENC_AES_H_
#include "senc_assist.h"

#define			SENC_AES_128														128
#define			SENC_AES_256														256
#define			SENC_AES_BLOCK_SIZE													16


//********************************************************************************************************//
//*函数：SENC_AES_Dispersion()
//*功能：秘钥分散，产生会话秘钥||Key dispersion and generate session key
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
//		unsigned char*		RandNum						//标示随机数
//*日期：2016/10/27
//by Wangjf
unsigned int SENC_AES_Dispersion(SENCryptCard* sencDev,			//加密卡设备handle
								 unsigned char* RandNum);		//标示随机数
//********************************************************************************************************//
//*函数：SENC_AES_CmdDataEncrypt()
//*功能：对数据进行AES加密||Encrypt input data by AES
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
//		unsigned char*		pucCmdData					//需加密命令明文
//		unsigned char*		pucCryptograph				//输出密文
//		unsigned int*		DataLength					//加密后输出长度
//*日期：2016/10/28
//by Wangjf
unsigned int SENC_AES_CmdDataEncrypt(SENCryptCard* sencDev,			//加密卡设备handle
									 unsigned char* pucCmdData,		//需加密命令明文
									 unsigned char* pucCryptograph,	//输出密文
									 unsigned int* DataLength);		//加密后输出长度
//********************************************************************************************************//
//*函数：SENC_AES_CmdDataDecrypt()
//*功能：对数据进行AES解密||Decrypt input data by AES
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
//		unsigned char*		pucCryptograph				//需解密命令密文
//		unsigned char*		pucDecryptedData			//输出明文
//		unsigned int*		DataLength					//解密后输出长度
//*日期：2016/10/28
//by Wangjf
unsigned int SENC_AES_CmdDataDecrypt(SENCryptCard* sencDev,				//加密卡设备handle
									 unsigned char* pucCryptograph,		//需解密命令密文
									 unsigned char* pucDecryptedData,	//输出明文
									 unsigned int DataLength);			//输入长度
//********************************************************************************************************//
//*函数：SENC_AES_DHPrivCal()
//*功能：计算通信秘钥||Calculate Communication Key
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
//		unsigned char*		ucInEncKey					//加密通信秘钥
//*日期：2016/10/27
//by Wangjf
unsigned int SENC_AES_DHPrivCal(SENCryptCard* sencDev,				//加密卡设备handle
								unsigned char* ucInEncKey);			//加密通信秘钥
//********************************************************************************************************//
//********************************************************************************************************//
//********************************************************************************************************//

#endif //LIBSENC_SENC_AES_H_