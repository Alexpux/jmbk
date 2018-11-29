/************************************************************************/
//  iToken.h
//
//	(C)2002 Beijing Senselock Inc.
//
/************************************************************************/
#ifndef _ITOKEN_API_H_
#define _ITOKEN_API_H_

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
 #define ITOKENAPI __stdcall
#else
 #define ITOKENAPI
#endif

typedef void* SKEYHANDLE;
 
#define MAX_ATR_LENGTH	64

typedef enum _DEVICE_STATUS_CODE {
	DEVICE_STATUS_UNKNOW	      = -1,
	DEVICE_STATUS_CARD_UNKNOW     = 0,
	DEVICE_STATUS_CARD_ABSENT,
	DEVICE_STATUS_CARD_PRESENT,
	DEVICE_STATUS_CARD_SWALLOWED,
	DEVICE_STATUS_CARD_POWERED,
	DEVICE_STATUS_CARD_NEGOTIABLE,
	DEVICE_STATUS_CARD_SPECIFIC
}DEVICE_STATUS_CODE;

typedef enum{
	CARD_TYPE_UNKNOW	 = -1,
	CARD_TYPE_XCOS_V1_00 = 0,
	CARD_TYPE_XCOS_V1_01,
	CARD_TYPE_XCOS_V1_10,
	CARD_TYPE_XCOS_V1_11,
	CARD_TYPE_SMARTCOS	 = 0x10,
	CARD_TYPE_XCOS_V2_00 = 0x20,
	CARD_TYPE_XCOS_V2_30 = 0x00020300,
	CARD_TYPE_XCOS_V3_00 = 0x00030000,
} CARD_TYPE;

/* for sense4 update */
#define CARD_TYPE_XCOS_V1_02	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_03	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_04	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_05	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_06	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_07	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_08	CARD_TYPE_XCOS_V1_01
#define CARD_TYPE_XCOS_V1_09	CARD_TYPE_XCOS_V1_01

typedef struct {
	unsigned char atr[MAX_ATR_LENGTH];
	unsigned long atrLen;
} ITOKEN_INFO, *PITOKEN_INFO;

typedef struct {
	unsigned	long index;			// device index
	unsigned	long deviceType;	// device type
	SKEYHANDLE	hKey;				// device handle
	unsigned	long status;		// device status
	unsigned	long protocol;		// selected protocol
	unsigned	long baudrate;		// current baudrate
	ITOKEN_INFO	info;				// card info
} ITOKEN_CONTEXT, *PITOKEN_CONTEXT;

/* -- protocol -- */
#define SKEY_PROTOCOL_T0			0x00000001
#define SKEY_PROTOCOL_T1			0x00000002
#define SKEY_PROTOCOL_USB			0x00000004

/* -- control code -- */
#define	SKEY_LEAVE					0xffffffff
#define	SKEY_UNPOWER				0x00000001
#define SKEY_RESET					0x00000002
#define SKEY_LED1					0x00000004
#define SKEY_LED2					0x00000008
#define SKEY_BAUDRATE				0x00000010

#define SKEY_CHANGING_WI			0x20  // the control code of changing WI is 0x20


/* define for itoken v2.0 */
#define SKEY_LED_UP					0x00000004
#define SKEY_LED_DOWN				0x00000008


/* -- 	return code  -- */
#define	SKEY_SUCCESS				0x00000000
#define SKEY_UNPOWERED				0x00000001
#define	SKEY_INVALID_PARAMETER		0x00000002
#define SKEY_COMM_ERROR				0x00000003
#define SKEY_PROTOCOL_ERROR			0x00000004
#define SKEY_DEVICE_BUSY			0x00000005
#define SKEY_KEY_REMOVED			0x00000006
#define SKEY_INSUFFICIENT_BUFFER	0x00000011
#define SKEY_NO_LIST				0x00000012
#define SKEY_GENERAL_ERROR			0x00000013
#define SKEY_UNSUPPORTED			0x00000014
#define SKEY_RSAVERIFY_FAILED		0x00006a80

/* --   open mode -- */
#define SKEY_SHARE_READ				0x00000001
#define SKEY_SHARE_WRITE			0x00000002


#ifdef __cplusplus
extern "C" {
#endif

/*
//	List all of the key connected.
*/
unsigned long ITOKENAPI SKeyListKey(
	ITOKEN_CONTEXT *ctxList,			//[in,out], key context list buffer
	unsigned long *ctxLen				//[in,out], buffer length
);

/*
//	Establish a connection between the calling app and the key
*/
unsigned long ITOKENAPI SKeyConnect(
	ITOKEN_CONTEXT *ctx,				//[in,out], indicates which key to connect
	unsigned long shareMode,			//[in], indicates the share mode
	unsigned long preferredProtocols,	//[in], possible protocols 
	unsigned long *activeProtocol		//[out], established active protocol.
);

/*
//	Terminates a connection previously opened between the calling app and a key
*/
unsigned long ITOKENAPI SKeyDisconnect(
	ITOKEN_CONTEXT *ctx,				//[in,out], indicate the key to disconnect
	unsigned long disposition			//[in], what to do with the key after disconnect
); 

/*
//	Send Control Code to control the key directly
*/
unsigned long ITOKENAPI SKeyControl(
	ITOKEN_CONTEXT *ctx,				//[in,out], indicate the key
	unsigned long ctlCode,				//[in], control code
	unsigned char *inBuff,				//[in], buffer needed with this control code
	unsigned long inBuffLen,			//[in], buffer len
	unsigned char *outBuff,				//[out], output buffer
	unsigned long outBuffLen,			//[in], buffer len
	unsigned long *bytesReturned		//[out], data stored into the out buffer 
);	

/*
//	provides the current status of the key 
*/
unsigned long ITOKENAPI SKeyStatus(
	ITOKEN_CONTEXT *ctx,				//[in], indicate the key
	unsigned long *state,				//[out], current status
	unsigned long *protocol,			//[out], current protocol
	unsigned char *atr,					//[out], ATR if availible
	unsigned long *atrLen				//[out], ATR len if availible
);

/*
//	Send a service request to the key, and expect to receive 
//	data back from the key.
*/
unsigned long ITOKENAPI SKeyTransmit(
	ITOKEN_CONTEXT *ctx,				//[in], indicate the key
	unsigned char *sendBuf,				//[in], data buffer write to the key
	unsigned long sendLen,				//[in], buffer length
	unsigned char *recvBuf,				//[out], data buffer returned from the key
	unsigned long *recvLen				//[in,out], returned data length
);

/*
//	Send a service request to the key, and expect to receive 
//	data back from the key.
*/
unsigned long ITOKENAPI SKeyTransmitEx(
									   ITOKEN_CONTEXT *ctx,				//[in], indicate the key
									   unsigned char *sendBuf,				//[in], data buffer write to the key
									   unsigned long sendLen,				//[in], buffer length
									   unsigned char *recvBuf,				//[out], data buffer returned from the key
									   unsigned long *recvLen,				//[in,out], returned data length
									   unsigned long secondTime
									 );
/*
//	Encrypt plaintext with RSAES-PKCS1-v1_5 by default
//	Use SHA-1 as hash funtion by default.
*/
unsigned long ITOKENAPI SKeyRSAEncrypt(
	ITOKEN_CONTEXT *ctx,				//[in], indicate the key
	unsigned char *pubKeyFID,			//[in], receiver's public key file ID
	unsigned char *plaintext,			//[in], plaintext
	unsigned long plaintextLen,			//[in], plaintext length
	unsigned char *ciphertext,			//[out], ciphertext
	unsigned long *ciphertextLen,		//[in,out], ciphertext length
	void *algID							//[in], reserved for future use
);

/*
//	Decrypt ciphertext with RSAES-PKCS1-v1_5 by default
//	Use SHA-1 as hash funtion by default.
*/
unsigned long ITOKENAPI SKeyRSADecrypt(
	ITOKEN_CONTEXT *ctx,				//[in], indicate the key
	unsigned char *priKeyFID,			//[in], receiver's private key file ID
	unsigned char *ciphertext,			//[in], ciphertext 
	unsigned long ciphertextLen,		//[in], ciphertext length
	unsigned char *plaintext,			//[out], plaintext
	unsigned long *plaintextLen,		//[in,out], plaintext length
	void *algID							//[in], reserved for future use
);

/*
//	Make signature with RSASSA-PKCS1-v1_5 by default
//	Use SHA-1 as hash funtion by default.
*/
unsigned long ITOKENAPI SKeyRSASign(
	ITOKEN_CONTEXT *ctx,				//[in], indicate the key
	unsigned char *priKeyFID,			//[in], signer's private key file ID
	unsigned char *plaintext,			//[in], plaintext
	unsigned long plaintextLen,			//[in], plaintext length
	unsigned char *signature,			//[out], signature
	unsigned long *signatureLen,		//[in,out], signature length
	void *algID							//[in], reserved for future use
);

/*
//	Verify signature with RSASSA-PKCS1-v1_5 by default
//	Use SHA-1 as hash funtion by default.
*/
unsigned long ITOKENAPI SKeyRSAVerify(
	ITOKEN_CONTEXT *ctx,				//[in], indicate the keyv
	unsigned char *pubKeyFID,			//[in], signer's public key file ID
	unsigned char *plaintext,			//[in], plaintext
	unsigned long plaintextLen,			//[in], plaintext length
	unsigned char *signature,			//[in], singature
	unsigned long signatureLen,			//[in], signature length
	void *algID							//[in], reserved for future use
);

/*
// reserved for future use(RFU)
*/
unsigned long ITOKENAPI SKeyStartup(void* rfu);
unsigned long ITOKENAPI SKeyCleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* _ITOKEN_API_H_ */

