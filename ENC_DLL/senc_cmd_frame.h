#ifndef LIBSENC_SENC_CMD_FRAME_H_
#define LIBSENC_SENC_CMD_FRAME_H_

#include "libsenc.h"
#include "senc_assist.h"


//板卡操作码
#define			SENC_CMD_KEY_EXCHANGE											0x00
#define			SENC_CMD_ENCRYPT_CARD_OPERATION									0x01
#define			SENC_CMD_MANAGEMENT												0x02
#define			SENC_CMD_DONGLE_OPERATION										0x03
#define			SENC_CMD_AES													0x04
#define			SENC_CMD_RSA													0x05
#define			SENC_CMD_KEY_OPERATION											0x06
#define			SENC_CMD_PRODUCTION												0x07
#define			SENC_CMD_PRO_TEST												0x08

#define			SENC_CMD_ALTERNATIVE_HASH										0xF0
#define			SENC_CMD_ALTERNATIVE_RSA										0xF1
#define			SENC_CMD_ALTERNATIVE_PBKDF2										0xF2
#define			SENC_CMD_DATA_PROTECTION										0xF3
#define			SENC_CMD_DOE_MANAGEMENT											0xF5
#define			SENC_CMD_KEY_MANAGEMENT											0xF6

#define			DP_SIGN_USER_PUB_KEY											0x01
#define			DP_GEN_WEB_KEY													0x02
#define			DP_SET_WEB_KEY_PERIOD											0x03
#define			DP_GEN_KEY_SEED_S1												0x04
#define			DP_ISSUE_LICENSE												0x05
#define			DP_CIPHER_CONVERT												0x06
#define			DP_GET_RTC_TIME													0x11
#define			DP_GET_SUPPORTED_ALGORITHM										0x12
#define			DP_SET_RTC_TIME													0x13

#define			DP_GET_CHIP_INIT_STATUS											0x01
#define			DP_GET_INIT_REQ													0x02
#define			DP_CHIP_INIT													0x03
#define			DP_GET_AUTH_PACKAGE												0x04

#define			KM_CREATE_KEY_CHAIN												0x01
#define			KM_SIGN_BIND_CODE												0x02
#define			KM_CREATE_CIRCLE												0x03
#define			KM_JOIN_CIRCLE													0x04

#define			DP_SET_CALC_KEY													0x10
#define			DP_SCK_MAC														0x01

#define			SENC_CMD_CONFIRM												0xff


#define			SENC_ECARD_GET_STAT												0x01
#define			SENC_ECARD_GET_ID												0x02
#define			SENC_ECARD_GET_VERSION											0x03


#define			SENC_MANAGE_ADDITION											0x01
#define			SENC_MANAGE_VERIFITION											0x02
#define			SENC_MANAGE_DELETION											0x03
#define			SENC_MANAGE_GET_ID												0x04
#define			SENC_MANAGE_BACKUP_KEY											0x05
#define			SENC_MANAGE_RECOVERY_KEY										0x06
#define			SENC_MANAGE_QUIT												0x07
#define			SENC_MANAGE_WORK_STANDBY										0x08


#define			SENC_DONGLE_ADDITION											0x01
#define			SENC_DONGLE_SET_KEY												0x02
#define			SENC_DONGLE_DELETION											0x03
#define			SENC_DONGLE_GET_VERIFITION_DATA									0x04
#define			SENC_DONGLE_VERIFITION											0x05
#define			SENC_DONGLE_GET_ID												0x06
#define			SENC_DONGLE_QUIT												0x07

#define			SENC_AES_ENCRYPTION												0x01
#define			SENC_AES_DECRYPTION												0x02

#define			SENC_CMD_AES_LENGTH_128											0x01
#define			SENC_CMD_AES_LENGTH_256											0x02
#define			SENC_CMD_AES_MODE_ECB											0x01
#define			SENC_CMD_AES_MODE_CBC											0x02
#define			SENC_CMD_SM4													0x03
// #define			SENC_CMD_RSA_LENGTH_1024										0x01
#define			SENC_CMD_RSA_LENGTH_2048										0x01


#define			SENC_RSA_SIGNATURE_EXTERNAL										0x01
#define			SENC_RSA_SIGNATURE_INTERNAL										0x02
#define			SENC_RSA_DECRYPT_EXTERNAL										0x03
#define			SENC_RSA_DECRYPT_INTERNAL										0x04

#define			SENC_KEYS_RSA_KEY_GENERATION_RETURN								0x01
#define			SENC_KEYS_RSA_KEY_GENERATION_INTERNAL_STORAGE					0x02
#define			SENC_KEYS_GET_RSA_PUBLIC_KEY									0x03
#define			SENC_KEYS_AES_KEY_GENERATION									0x04
#define			SENC_KEYS_IMPORT_KEY											0x05
#define			SENC_KEYS_DELETION												0x06
#define			SENC_KEYS_QUERY													0x07
#define			SENC_KEYS_BACKUP												0x08
#define			SENC_KEYS_RECOVERY												0x09

#define			SENC_PRODUCT_SET_ID												0x01
#define			SENC_PRODUCT_SET_VERSION										0x02
#define			SENC_PRODUCT_GENERATE_FLASH_KEY									0x03
#define			SENC_PRODUCT_SET_DH_PARAMETER									0x04
#define			SENC_PRODUCT_GENERATE_RSA_KEY									0x05
#define			SENC_PRODUCT_REQUEST_CSR										0x06
#define			SENC_PRODUCT_DOWNLOAD_CERT										0x07
#define			SENC_PRODUCT_SET_DONE											0x08

#define			SENC_PRO_TEST_RSA_SIGNATURE										0x01
#define			SENC_PRO_TEST_AES_ENCRYPTION									0x02
#define			SENC_PRO_TEST_GET_MASTER_CARD_ID								0x03
#define			SENC_PRO_TEST_WRITE_NO_PROTECT									0x04
#define			SENC_PRO_TEST_WRITE_EJECT_PROTECT								0x05
#define			SENC_PRO_TEST_READ												0x06
#define			SENC_PRO_TEST_FLASH_SWEEP										0x07

#define			SENC_ALTERNATIVE_RSA_KEY_PAIR_GENERATION						0x01
#define			SENC_ALTERNATIVE_RSA_SIGNATURE_EXTERNAL							0x02
#define			SENC_ALTERNATIVE_RSA_VIRIFY_EXTERNAL							0x03
#define			SENC_ALTERNATIVE_RSA_SIGNATURE_INTERNAL							0x04
#define			SENC_ALTERNATIVE_RSA_VIRIFY_INTERNAL							0x05

#define			SENC_CMD_LENGTH_DONGLE_ID										8
#define			SENC_CMD_LENGTH_DONGLE_KEY_DATA									16
#define			SENC_CMD_LENGTH_DONGLE_RAND										8



#define			SENC_ALG_AES_128												0x01
#define			SENC_ALG_AES_256												0x02
#define			SENC_ALG_SM4													0x03
#define			SENC_ALG_RSA_2048												0x04

#define			SENC_CARD_ID_LENGTH												16			//管理卡ID长度
#define			SENC_BAKCUP_KEYS_LENGTH											208			//备份秘钥长度
#define			SENC_RSA_PRIVATE_KEY_LENGTH_IVM									SENC_RSA_PRIVATE_KEY_LENGTH+SENC_ENC_MAC_LENGTH+SENC_ENC_IV_LENGTH //1444
#define			SENC_RSA_PRIVATE_KEY_LENGTH										1412
#define			SENC_ENC_MAC_LENGTH												16
#define			SENC_ENC_IV_LENGTH												16
#define			SENC_RSA_PUBLIC_KEY_LENGTH										512




//*函数：SENC_CMD_KEX_KeyExchange()
//*功能：秘钥交换||Key exchange;
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//		unsigned char*		pucCmpAttr,				//发送的计算参数A
//		unsigned char*		pucRecvCmpAttr,			//收到的计算参数B
//		unsigned char*		pucRetPrivCommuKey)		//返回通信密钥
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_KEX_KeyExchange(SENCryptCard*		IN	sencDev,
									  unsigned char*	IN	pucCmpAttr,	
									  unsigned char*	OUT	pucRecvCmpAttr,
									  unsigned char*	OUT	pucRetPrivCommuKey);
//********************************************************************************************************//
//*函数：SENC_CMD_EC_GetState()
//*功能：获取加密卡状态||Get encrypt card's state; 
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//*参数：unsigned char*		pucRetState				//返回的加密卡状态
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetState(SENCryptCard*		IN	sencDev,
								  unsigned char*	OUT	pucRetState);
//********************************************************************************************************//
//*函数：SENC_CMD_EC_GetID()
//*功能：获取加密卡ID||Get encrypt card's ID;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucRetID				//返回ID数据
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetID(SENCryptCard*	IN	sencDev,		
							   unsigned char*	OUT	pucRetID);		
//********************************************************************************************************//
//*函数：SENC_CMD_EC_GetVersion()
//*功能：获取加密卡版本||Get hardware and firmware version from encrypt card;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucRetHardwareVer		//返回硬件版本
//		unsigned char*		pucRetFirmwareVer		//返回固件版本
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_EC_GetVersion(SENCryptCard*	IN	sencDev,			
									unsigned char*	OUT	pucRetHardwareVer,	
									unsigned char*	OUT	pucRetFirmwareVer);	
//********************************************************************************************************//
//*函数：SENC_CMD_MC_NewMasterCard()
//*功能：添加新管理卡||Add a new master card;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucRetAddedCardId		//返回添加卡
//		unsigned char*		pucRetRestNums			//返回剩余可添加卡数量
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_NewMasterCard(SENCryptCard*	IN	sencDev,			
									   unsigned char*	OUT	pucRetAddedCardId,	
									   unsigned char*	OUT	pucRetRestNums);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_VerifyMasterCard()
//*功能：验证管理卡||Verify a master card;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucRetVerifiedCardId	//返回被认证卡ID
//		unsigned char*		pucRetPermission		//返回卡权限
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_VerifyMasterCard(SENCryptCard*		IN	sencDev,
										  unsigned char*	OUT	pucRetVerifiedCardId,
										  unsigned char*	OUT	pucRetPermission);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_DeleteMasterCard()
//*功能：删除管理卡||Delete a master card;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucDelCardId			//待删除卡ID
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_DeleteMasterCard(SENCryptCard*		IN	sencDev,
										  unsigned char*	IN	pucDelCardId);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_GetMasterCardId()
//*功能：获取管理卡ID|| Get all master cards' ID;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucRetData				//返回管理卡信息
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_GetMasterCardId(SENCryptCard*	IN	sencDev,
										 unsigned char*	OUT	pucRetData);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_GetBackupKey()
//*功能：获取备份秘钥|| Get backup key;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucRetEncryptSign		//返回加密标识
//		unsigned char*		pucRetKeys				//返回加密备份秘钥数据
//*日期：2016/10/25	
//by Wangjf
unsigned int SENC_CMD_MC_GetBackupKey(SENCryptCard*		IN	sencDev,
									  unsigned char*	OUT	pucRetEncryptSign,	
									  unsigned char*	OUT	pucRetKeys);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_SetRecoveryKey()
//*功能：设置恢复备份秘钥|| Set back-up keys for recovery;
//*参数：SENCryptCard*		sencDev,				//加密卡设备handle
//		unsigned char*		pucInKeys,				//需恢复的加密备份秘钥数据
//		unsigned char*		pucRetDecryptSign		//返回管理卡解密标识
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_SetRecoveryKey(SENCryptCard*	IN	sencDev,
										unsigned char*	IN	pucInKeys,
										unsigned char*	OUT	pucRetDecryptSign);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_MngQuit()
//*功能：退出管理模式|| Quit management state;
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_MC_MngQuit(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_CMD_MC_WorkStandby()
//*功能：进入工作状态|| Set to Standby state;
//*参数：SENCryptCard*		sencDev,							//加密卡设备handle
//*日期：2016/11/04
//by Wangjf
unsigned int SENC_CMD_MC_WorkStandby(SENCryptCard* IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_CMD_Dongle_NewDongle()
//*功能：添加新锁|| Add a new key dongle;
//*参数：SENCryptCard*		sencDev,							//加密卡设备handle
//		unsigned char*		pucDongleId,						//锁ID
//		unsigned char*		pucInKeyData,						//外部认证秘钥
//		unsigned char*		pucPlaintextKey,					//明文flash key
//*日期：2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_NewDongle(SENCryptCard*	sencDev,			//加密卡设备handle
									   unsigned char*	pucDongleId,		//锁ID
									   unsigned char	keyIdx1,
									   unsigned char	keyIdx2,
									   unsigned char*	pucInKeyData,		//外部认证秘钥
									   unsigned char*	pucPlaintextKey);	//明文flash key
//********************************************************************************************************//
//*函数：SENC_CMD_Dongle_SetEncryptedKey()
//*功能：设置密文key|| Set the encrypted key;
//*参数：SENCryptCard*		sencDev 							//加密卡设备handle
//		unsigned char*		pucEncKeyData						//密文key
//*日期：2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_SetEncryptedKey(SENCryptCard*	sencDev,			//加密卡设备handle
											 unsigned char*	pucEncKeyData);		//密文key
//********************************************************************************************************//
//*函数：SENC_CMD_Dongle_Delete()
//*功能：删除锁|| Delete the bound key dongle;
//*参数：SENCryptCard*		sencDev				//加密卡设备handle
//		unsigned char*		KeyId,				//待删除锁ID
//*日期：2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_Delete(SENCryptCard*	sencDev,					//加密卡设备handle
									unsigned char*	KeyId);						//待删除锁ID
//********************************************************************************************************//
//*函数：SENC_CMD_Dongle_GetVerifyRand()
//*功能：获取验证随机数|| Get verification random number;
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//		unsigned char*		pucDongleId				//锁ID
//		unsigned char*		pucRetRandNum			//返回验证随机数
//		unsigned char*		pucEncFlashKey			//密文flash key
//*日期：2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_GetVerifyRand(SENCryptCard*	sencDev,			//加密卡设备handle
										   unsigned char*	pucDongleId,		//锁ID
										   unsigned char*	keyIdx1,
										   unsigned char*	keyIdx2,
										   unsigned char*	pucRetRandNum,		//返回验证随机数
										   unsigned char*	pucEncFlashKey);	//密文flash key
//********************************************************************************************************//
//*函数：SENC_CMD_Dongle_Verify()
//*功能：验证锁|| Verify the inserted key dongle;
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
//		unsigned char*		pucDongleId					//锁ID
//		unsigned char*		pucInKeyVerifyData			//验证锁的数据
//		unsigned char*		pucDecFlashKey				//解密后flash key
//*日期：2017/02/14
//by Wangjf
unsigned int SENC_CMD_Dongle_Verify(SENCryptCard*	sencDev,				//加密卡设备handle
									unsigned char*	pucDongleId,			//锁ID
									unsigned char*	pucInKeyVerifyData,		//验证锁的数据
									unsigned char*	pucDecFlashKey);		//解密后flash key{
//********************************************************************************************************//
//*函数：SENC_CMD_Get_Dongle_ID()
//*功能：获取锁ID|| Get dongles ID which bound with senc card
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
//		unsigned char*		pucRetData					//返回ID数据
//*日期：2017/02/14
//by Wangjf
unsigned int SENC_CMD_Get_Dongle_ID(SENCryptCard*	sencDev,				//加密卡设备handle
									unsigned char*	pucRetData);			//返回ID数据
//********************************************************************************************************//
//*函数：SENC_CMD_Dongle_Quit()
//*功能：退出操作模式|| Quit from operation state;
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Dongle_Quit(SENCryptCard*		IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_CMD_AES_Encrypt()
//*功能：AES加密|| Encrypt in AES
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//		unsigned char*		CBCiv					//cbc初始向量
//		unsigned char*		pucInData				//待加密数据
//		unsigned int		uiInDataLen				//待加密数据长度
//		unsigned char*		pucCipherData			//加密返回数据
//		unsigned int*		uiCipherDataLen			//待加密数据长度
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_AES_Encrypt(SENCryptCard*		IN		sencDev,
								  EncryptAttr*		EncAttributes,
								  unsigned char*	IN		CBCiv,
								  unsigned char*	IN		pucInData,
								  unsigned int		IN		uiInDataLen,
								  unsigned char*	OUT		pucCipherData,
								  unsigned int*		OUT		uiCipherDataLen);
//********************************************************************************************************//
//*函数：SENC_CMD_AES_Decrypt()
//*功能：AES解密|| Decrypt in AES
//*参数：SENCryptCard*		sencDev					//加密卡设备handle
//		unsigned char*		CBCiv					//cbc初始向量
//		unsigned char*		pucInData				//待解密数据
//		unsigned int		uiInDataLen				//待解密数据长度
//		unsigned char*		pucDecryptedData		//解密返回数据
//		unsigned int*		uiDecryptedDataLen		//待解密数据长度
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_AES_Decrypt(SENCryptCard*		IN		sencDev,
								  EncryptAttr*		EncAttributes,
								  unsigned char*	IN		CBCiv,
								  unsigned char*	IN		pucInData,
								  unsigned int		IN		uiInDataLen,
								  unsigned char*	OUT		pucDecryptedData,
								  unsigned int*		OUT		uiDecryptedDataLen);
//********************************************************************************************************//
//*函数：SENC_CMD_RSA_Signature_External()
//*功能：外部RSA签名|| Signature by RSA encryption
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucRsaKey						//签名用RSA秘钥数据
//		unsigned char*		pucInData						//待签名数据
//		unsigned char*		pucSignedData					//签名返回数据
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_RSA_Signature_External(SENCryptCard*	IN	sencDev,
											 EncryptAttr*		EncAttributes,
											 unsigned char* IN	pucIV,
											 unsigned char*	IN	pucMac,
											 unsigned char*	IN	pucRsaKey,
											 unsigned char*	IN	pucInData,
											 unsigned char*	OUT	pucSignedData);
//********************************************************************************************************//
//*函数：SENC_CMD_RSA_Signature_Internal()
//*功能：RSA内部秘钥签名|| Signature by RSA encryption with internal key
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucInData						//待签名数据
//		unsigned char*		pucSignedData					//返回数据
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_RSA_Signature_Internal(SENCryptCard*		IN	sencDev,
											 EncryptAttr*		EncAttributes,
											 unsigned char*		IN	pucInData,
											 unsigned char*		OUT	pucSignedData);
//********************************************************************************************************//
//*函数：SENC_CMD_RSA_Decrypt_External()
//*功能：外部RSA解密|| Decryption by RSA encryption
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucEncRsaPrivKey				//加密RSA秘钥数据
//		unsigned char*		pucInEncData					//待解密数据
//		unsigned char*		pucOutDecData					//返回已解密数据
//*日期：2017/02/16
//by Wangjf
unsigned int SENC_CMD_RSA_Decrypt_External(SENCryptCard*	sencDev,
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucIV,
										   unsigned char*	pucMac,
										   unsigned char*	pucEncRsaPrivKey,
										   unsigned char*	pucInEncData,
										   unsigned char*	pucOutDecData);
//********************************************************************************************************//
//*函数：SENC_CMD_RSA_Decrypt_Internal()
//*功能：RSA内部秘钥解密|| RSA Decryption with internal key
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucInEncData					//待解密数据
//		unsigned char*		pucOutDecData					//返回已解密数据
//*日期：2017/02/16
//by Wangjf
unsigned int SENC_CMD_RSA_Decrypt_Internal(SENCryptCard*	sencDev,
										   EncryptAttr*		EncAttributes,
										   unsigned char*	pucInEncData,
										   unsigned char*	pucOutDecData);

//********************************************************************************************************//
//*函数：SENC_CMD_Key_RSA_Generate_Ret()
//*功能：RSA秘钥生成并导出|| Generate an RSA key and export;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucRetRsaPrivKey				//返回已加密私钥数据
//		unsigned char*		pucRetRsaPubKey					//返回已加密公钥数据
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_Generate_Ret(SENCryptCard*	IN	sencDev,
										   EncryptAttr*		EncAttributes,
										   unsigned char*	IN	pucIV,
										   unsigned char*	OUT	pucMAC,
										   unsigned char*	OUT	pucRetRsaPrivKey,
										   unsigned char*	OUT	pucRetRsaPubKey);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_RSA_Generate_Internal()
//*功能：RSA秘钥生成并存储卡内|| Generate an RSA key and storage in encrypt card;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		EncryptLength					//加密长度1024|2048
//		unsigned char		RsaKeyIdx						//返回RSA秘钥存储索引
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_Generate_Internal(SENCryptCard*	IN	sencDev,
												unsigned char	IN	EncryptLength,
												unsigned char	IN	RsaKeyIdx);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_RSA_GetPublicKey()
//*功能：获取目标RSA公钥|| Get RSA public key;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		EncryptLength					//加密长度1024|2048
//		unsigned char		KeyIndex						//目标秘钥索引
//		unsigned char*		pucRetRsaPubKey					//返回RSA公钥
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_RSA_GetPublicKey(SENCryptCard*	IN	sencDev,
										   unsigned char	IN	EncryptLength,
										   unsigned char	IN	KeyIndex,
										   unsigned char*	OUT	pucRetRsaPubKey);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_Symmetric_Key_Generate()
//*功能：对称秘钥生成并存储卡内|| Generate an symmetric key and storage in encrypt card;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		EncryptLength					//加密长度128|256
//		unsigned char		InAesKeyIndex					//AES秘钥存储索引
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Symmetric_Key_Generate(SENCryptCard*	IN	sencDev,		//加密卡设备handle
												 unsigned char	IN	EncryptLength,	//加密长度128|256
												 unsigned char	IN	InAesKeyIndex);	//AES秘钥存储索引
//********************************************************************************************************//
//*函数：SENC_CMD_Key_Import()
//*功能：秘钥导入|| Import keys
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		InAlgorithmType					//导入秘钥算法
//		unsigned char		InKeyIndex						//导入秘钥目标索引
//		unsigned char*		InKeyData						//导入秘钥数据
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_Key_Import(SENCryptCard*	IN	sencDev,
								 unsigned char	IN	InAlgorithmType,
								 unsigned char	IN	InKeyIndex,
								 unsigned char*	IN	InKeyData);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_Delete()
//*功能：秘钥删除|| Delete a key;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		EncryptLength					//删除秘钥类型
//		unsigned char		ucDelKeyIndex					//删除秘钥索引
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Delete(SENCryptCard*	IN	sencDev,
								 unsigned char	IN	EncryptType,
								 unsigned char	IN	ucDelKeyIndex);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_Query()
//*功能：秘钥查询|| Query for keys;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucAES128State					//返回AES128秘钥状态码
//		unsigned char*		pucAES256State					//返回AES256秘钥状态码
// 		unsigned char*		pucSM4State						//返回SM4秘钥状态码
// 		unsigned char*		pucRSA2048State					//返回RSA2048秘钥状态码
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Query(SENCryptCard*	IN	sencDev,
								unsigned char*	OUT	pucAES128State,
								unsigned char*	OUT	pucAES256State,
								unsigned char*	OUT	pucSM4State,
								unsigned char*	OUT	pucRSA2048State);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_Backup()
//*功能：秘钥备份|| Backup a key;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		EncryptType						//加密方式
//		unsigned char		ucBakKeyIndex					//备份秘钥索引
//		unsigned char*		pucBakKeyData					//返回备份秘钥数据
//		unsigned int*		pucBakKeyDataLength				//返回备份秘钥数据长度
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Backup(SENCryptCard*		IN	sencDev,
								 unsigned char		IN	EncryptType,
								 unsigned char		IN	ucBakKeyIndex,
								 unsigned char*		OUT	pucBakKeyData,
								 unsigned int*		OUT	pucBakKeyDataLength);
//********************************************************************************************************//
//*函数：SENC_CMD_Key_Recover()
//*功能：秘钥恢复|| Recover a key;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char		EncryptType						//加密方式
// 		unsigned char		ucBakKeyIndex					//备份目标秘钥索引
// 		unsigned int		ucBakKeyDataLength				//备份目标秘钥数据长度
// 		unsigned char*		pucBakKeyData					//备份目标秘钥数据
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Key_Recover(SENCryptCard*		IN	sencDev,
								  unsigned char		IN	EncryptType,
								  unsigned char		IN	ucBakKeyIndex,
								  unsigned int		IN	ucBakKeyDataLength,
								  unsigned char*	IN	pucBakKeyData);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_SetCardId()
//*功能：设置加密卡ID|| Set the ID of encrypt card;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
// 		unsigned char*		pucEcardId						//设置加密卡ID
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetCardId(SENCryptCard*	IN	sencDev,
										unsigned char*	IN	pucEcardId);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_SetCardVersion()
//*功能：设置加密卡版本号|| Set hardware and firmware version of encrypt card;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
// 		unsigned char*		pucEcardHardwareVer				//设置加密卡硬件版本
// 		unsigned char*		pucEcardFirmwareVer				//设置加密卡固件版本
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetCardVersion(SENCryptCard*		IN	sencDev,
											 unsigned char*		IN	pucEcardHardwareVer,
											 unsigned char*		IN	pucEcardFirmwareVer);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_GenerateFlashKey()
//*功能：生成FLASH秘钥|| Generate FLASH key;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_GenerateFlashKey(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_SetDHAttributes()
//*功能：设置Diffie Hellman秘钥交换的P,G参数|| Set P&G for Diffie-Hellman key exchange;
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
// 		unsigned char*		pucP						//DH秘钥交换参数P
// 		unsigned char*		pucG						//DH秘钥交换参数G
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetDHAttributes(SENCryptCard*		IN	sencDev,
											  unsigned char*	IN	pucP,
											  unsigned char*	IN	pucG);

//********************************************************************************************************//
//*函数：SENC_CMD_Product_SM2_Generate()
//*功能：生成板卡设备密钥对|| Generate Senc Card RSA Keys;
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
// 		 uint8_t			EncryptLength				//加密长度
// 		 uint8_t			RsaKeyIdx					//RSA密钥存储索引
//*日期：2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_SM2_Generate(SENCryptCard*	IN	sencDev,
										   uint8_t			IN	EncryptLength,
										   uint8_t			IN	RsaKeyIdx);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_RequestCSR()
//*功能：向设备请求CSR|| Request CSR From Device;
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
// 		 uint32_t*			CsrLen						//返回CSR长度
// 		 uint8_t*			Csr							//返回CSR数据
//*日期：2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_RequestCSR(SENCryptCard*	IN	sencDev,
										 uint32_t*		OUT CsrLen,
										 uint8_t*		OUT Csr);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_DownLoadCert()
//*功能：下载证书|| Download Certification;
//*参数：SENCryptCard*		sencDev						//加密卡设备handle
// 		 uint8_t			CertType					//证书类型
// 		 uint32_t			CertLen						//证书长度
// 		 uint8_t*			Cert						//证书内容
//*日期：2018/11/1
//by Zhang Tao
unsigned int SENC_CMD_Product_DownLoadCert(SENCryptCard*	IN	sencDev,
										   uint8_t			IN CertType,
										   uint32_t			IN CertLen,
										   uint8_t*			IN Cert);
//********************************************************************************************************//
//*函数：SENC_CMD_Product_SetDefault()
//*功能：设置为出厂状态|| Set to default state;
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//*日期：2016/10/25
//by Wangjf
unsigned int SENC_CMD_Product_SetDefault(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_CMD_ProTest_RSA_Signature()
//*功能：生产测试RSA签名|| Signature by RSA in production
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		rsaKey							//rsa private key
//		unsigned char*		pucInData						//待签名数据
//		unsigned char*		pucSignedData					//签名返回数据
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_RSA_Signature(SENCryptCard*	IN	sencDev,
											unsigned char*	IN	rsaKey,
											unsigned char*	IN	pucInData,
											unsigned char*	OUT	pucSignedData);	
//********************************************************************************************************//
//*函数：SENC_CMD_ProTest_AES_Encrypt()
//*功能：生产测试AES加密(256 ECB)|| AES encryption test in production (256 ECB)
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pwkey							//AES key
//		unsigned char*		pucInData						//待加密数据
//		unsigned char*		pucSignedData					//返回加密数据(256 ECB)
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_AES_Encrypt(SENCryptCard*		IN	sencDev,
										  unsigned char*	IN	pwkey,
										  unsigned char*	IN	pucInData,
										  unsigned char*	OUT	pucSignedData);
//********************************************************************************************************//
//*函数：SENC_CMD_ProTest_Write_NoEP()
//*功能：写数据测试(退防拔)|| data write test without eject-proof
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucInData						//写入测试数据
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Write_NoEP(SENCryptCard*	IN	sencDev,
										 unsigned char*	IN	pucInData);
//********************************************************************************************************//
//*函数：SENC_CMD_ProTest_Write_EP()
//*功能：写数据测试(未退防拔)|| data write test with eject-proof
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucInData						//写入测试数据
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Write_EP(SENCryptCard*	IN	sencDev,
									   unsigned char*	IN	pucInData);
//********************************************************************************************************//
//*函数：SENC_CMD_ProTest_Read()
//*功能：读数据测试|| data read test
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//		unsigned char*		pucRetData						//返回读取数据
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Read(SENCryptCard*	IN	sencDev,
								   unsigned char*	OUT	pucRetData);
//********************************************************************************************************//
//*函数：SENC_CMD_ProTest_Flash_sweep()
//*功能：FLASH数据擦除|| flash memory sweeper
//*参数：SENCryptCard*		sencDev							//加密卡设备handle
//*日期：2016/11/15
//by Wangjf
unsigned int SENC_CMD_ProTest_Flash_sweep(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
#if defined __ALTER_ON__

unsigned int SENC_CMD_Alternative_Hash(SENCryptCard*	sencDev,				//加密卡设备handle
									   unsigned char hashAlgo,
									   const unsigned char* inData,
									   unsigned int inDataLen,
									   unsigned char*	pucRetData,
									   unsigned int* pucRetDataLen)	;			//返回读取数据

unsigned int SENC_CMD_Alternative_GenRsaKeyPair(SENCryptCard*	sencDev,				//加密卡设备handle
												unsigned char keyBits,
												unsigned char EncAlgo,
												unsigned char EncIdx,
												unsigned char*	pucIV,
												unsigned char*	pucMAC,
												unsigned char*	pucRetRsaPrivKey,		//返回已加密私钥数据
												unsigned char*	pucRetRsaPubKey);		//返回已加密公钥数据

unsigned int SENC_CMD_Alternative_SignatureExternal(SENCryptCard*	sencDev,				//加密卡设备handle
													unsigned char keyBits,
													unsigned char EncAlgo,
													unsigned char EncIdx,
													unsigned char*	pucIV,
													unsigned char*	pucMAC,
													unsigned char*	pucRsaPrivKey,		//返回已加密私钥数据
													unsigned char*	inData,
													unsigned char* retSignedData);	//返回已加密公钥数据

unsigned int SENC_CMD_Alternative_VerifyExternal(SENCryptCard*	sencDev,				//加密卡设备handle
												 unsigned char keyBits,
												 unsigned char*	pucRsaPubKey,		//返回已加密私钥数据
												 unsigned char*	inSignedData,
												 unsigned char* retDecrypto);		//返回已加密公钥数据


unsigned int SENC_CMD_Alternative_SignatureInternal(SENCryptCard*	sencDev,				//加密卡设备handle
													unsigned char keyBits,
													unsigned char KeyIdx,
													unsigned char*	inData,
													unsigned char* retSignedData);	//返回已加密公钥数据

unsigned int SENC_CMD_Alternative_VerifyInternal(SENCryptCard*	sencDev,				//加密卡设备handle
												 unsigned char keyBits,
												 unsigned char KeyIdx,
												 unsigned char* inSignedData,
												 unsigned char* retDecrypto);		//返回已加密公钥数据


unsigned int SENC_CMD_Alternative_PBKDF2Encrypt(SENCryptCard*	sencDev,				//加密卡设备handle
												unsigned char hashAlgo,
												unsigned char hashSaltAttr,
												unsigned int iteration,
												unsigned int outputKeyLen,
												unsigned char* inSaltData,
												unsigned int inSaltLen,
												unsigned char* inKeyData,
												unsigned int inKeyLen,
												unsigned char* outputKey);		//返回已加密公钥数据

#endif

#if defined __DATA_PROTECTOR_ON__
//签发用户公钥
unsigned int SENC_CMD_DataProtector_SignUserPubKey(SENCryptCard* IN	sencDev,
												   UserPubKey* IN  userkey,
												   UserPubKey* OUT userkey_new);
//生成云端秘钥
unsigned int SENC_CMD_DataProtector_GenWebKey(SENCryptCard*	IN sencDev,
											  KeyRecordRequest* IN req, 
											  UserPubKey* IN userPubKey,
											  KeyRecord* OUT key);
//设置云端秘钥有效期
unsigned int SENC_CMD_DataProtector_SetWebKeyPeriod(SENCryptCard* IN sencDev,
													KeyRecord* IN key,
													UserPubKey*	IN userPubKey,
													KeyPeriod*	IN keyPeriod,
													KeyRecord*	OUT key_new);
//生成秘钥种子S1
unsigned int SENC_CMD_DataProtector_GenS1(SENCryptCard*	IN sencDev,
										  KeyRecord* IN key, 
										  UserPubKey* IN userkey,
										  License* IN license,
										  S1Cipher* OUT S1_E_Kc,
										  S1Cipher* OUT S1_E_Ku,
										  License* OUT license_new);
//签发许可
unsigned int SENC_CMD_DataProtector_IssueLicense(SENCryptCard* IN sencDev,
												 KeyRecord* IN key, 
												 UserPubKey* IN userkey,
												 uint8_t* IN LicID,
												 License* IN fatherLic,
												 LicenseRequest* IN LicReq,
												 License* OUT Lic);
//转换密文
unsigned int SENC_CMD_DataProtector_CipherConvert(SENCryptCard*	IN sencDev,
												  KeyRecord* IN key,
												  UserPubKey* IN userkey,
												  License* IN Lic,
												  S1Cipher* IN S1_E_Kc,
												  S1Cipher* IN S1_E_Ku,
												  License* OUT Lic_new);

unsigned int SENC_CMD_DataProtector_SetMacCalculateKey(SENCryptCard* IN sencDev,
													   uint8_t* data, 
													   uint32_t datalen);

unsigned int SENC_CMD_DataProtector_GetRTCTime(SENCryptCard* IN sencDev,
											   uint64_t* OUT RTCTime);

unsigned int SENC_CMD_DataProtector_GetSupportedAlgorithm(SENCryptCard*	IN sencDev,
														  uint8_t* OUT supportedAlgorithm);

unsigned int SENC_CMD_DataProtector_SetRTCTime(SENCryptCard* IN sencDev,
											   uint8_t* IN PinCode,
											   uint64_t* IN TimeStamp);


//获取板卡初始化状态
unsigned int SENC_CMD_DataProtector_GetChipInitStatus(SENCryptCard* IN sencDev,
													  unsigned char*	OUT	pucRetState);

//从板卡获取初始化请求包
unsigned int SENC_CMD_DataProtector_GetInitReq(SENCryptCard* IN sencDev,
											   ChipInitRequest* OUT Req,
											   uint8_t* OUT CaCert,
											   uint32_t* OUT CaCertLen,
											   uint8_t* OUT Cert,
											   uint32_t* OUT CertLen,
											   uint8_t* OUT Pri,
											   uint8_t* OUT Pub);

//板卡执行初始化请求包
unsigned int SENC_CMD_DataProtector_ChipInit(SENCryptCard* IN sencDev,
											 ChipInitCommand IN Cmd,
											 uint8_t * IN CaCert,
											 uint32_t IN CaCertLen,
											 uint8_t * IN Cert,
											 uint32_t IN CertLen);
//从板卡获取认证管理员锁数据包
unsigned int SENC_CMD_DataProtector_GetAuthPackage(SENCryptCard* IN sencDev,
												   AuthAdminKey* OUT pkg);
//创建KeyChain
unsigned int SENC_CMD_KeyManager_CreateKeyChain(SENCryptCard* IN sencDev, 
												KeychainCreateReq IN KCCreateReq,
												uint32_t IN KCCreateReqLen,
												uint8_t* IN CaCert,
												uint32_t IN CaCertLen,
												uint8_t* IN FirmailCert,
												uint32_t IN FirmailCertLen,
												uint8_t* IN KeyBagId,
												KeychainCreateCode* OUT KCCreateCode,
												uint32_t* OUT KCCreateCodeLen);

//签发BindCode
unsigned int SENC_CMD_KeyManager_BindCode(SENCryptCard* IN sencDev,
										  KeybagBindCode IN KBBindCode,
										  uint32_t IN KBBindCodeLen,
										  uint8_t* IN CaCert,
										  uint32_t IN CaCertLen,
										  uint8_t* IN KeyBagCert,
										  uint32_t IN KeyBagCertLen,
										  uint8_t* OUT BindCodePlain,
										  uint8_t* OUT PhoneNumber,
										  uint8_t* OUT BindCodeCipher,
										  uint32_t* OUT BindCodeCipherLen);

//创建Circle
unsigned int SENC_CMD_KeyManager_CreateCircle(SENCryptCard* IN sencDev,
											  uint8_t* IN circle_id,
											  KeybagCreateCircleReq IN KBCreateCircleReq,
											  uint32_t IN KBCreateCircleReqLen,
											  uint8_t* IN BindCodeVrfPkgCipher,
											  uint32_t IN BindCodeVrfPkgCipherLen,
											  uint32_t* OUT TimeStamp,
											  KeybagCircle* OUT KBCircle,
											  uint32_t* OUT KBCircleLen);

//加入Circle
unsigned int SENC_CMD_KeyManager_JoinCircle(SENCryptCard* IN sencDev,
											KeybagCircle IN KBOldCircle,
											uint32_t IN KBOldCircleLen,
											KeybagJoinCircleApprove IN KBJoinCircleApprove,
											uint32_t IN KBJoinCircleApproveLen,
											uint8_t* IN BindCodeVrfPkgCipher,
											uint32_t IN BindCodeVrfPkgCipherLen,
											uint32_t* OUT TimeStamp,
											KeybagCircle* OUT KBNewCircle,
											uint32_t* OUT KBNewCircleLen);


#endif
#endif //LIBSENC_SENC_CMD_FRAME_H_