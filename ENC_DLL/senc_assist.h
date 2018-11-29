#ifndef LIBSENC_SENC_ASSIST_H_
#define LIBSENC_SENC_ASSIST_H_

#include "libsenc.h"
#include "lock.h"
#include "senc_error.h"

//线程锁
#if defined (WIN32) || defined (_WIN32) || defined (_WIN64)
#include <Windows.h>

#define _sleep_ms(x) Sleep(x)
#define INNER_ATOMIC_LOCK(x) {while(InterlockedCompareExchange(&x, 1, 0) == x){Sleep(10);}}
#define INNER_ATOMIC_UNLOCK(x) {InterlockedCompareExchange(&x, 0, 1);}

#elif defined (linux) || defined (__linux__)
#include <unistd.h>

#define _sleep_ms(x) usleep(1000*(x))
#define INNER_ATOMIC_LOCK(x) {while(!__sync_bool_compare_and_swap(&x, 0, 1)){usleep(10000);}}
#define INNER_ATOMIC_UNLOCK(x) {__sync_bool_compare_and_swap(&x, 1, 0);}

#endif

#if defined (linux) || defined (__linux__)
typedef		ThreadMutex		MUTEX_TYPE;
#endif



#define			SENC_CMD_SUCCESS												0x00

#define			SENC_BULK_ENDPOINT_WRITE_1K										0x02
#define			SENC_BULK_ENDPOINT_READ_1K										0x82
#define			SENC_BULK_ENDPOINT_WRITE_2K										0x01
#define			SENC_BULK_ENDPOINT_READ_2K										0x81
#define			SENC_TRANSFER_LENGTH_1K											1024
#define			SENC_TRANSFER_LENGTH_2K											2048

#define			SENC_BUFFER_SIZE												2048


typedef     char                SINT8;
typedef     unsigned char       SUINT8;
typedef     short               SINT16;
typedef     unsigned short      SUINT16;
typedef     int                 SINT32;
typedef     unsigned  int       SUINT32;


#define MAX_CARD_NUM 16
#define MAX_HASH_SHA_SIZE 32
#define MAX_RSA_PADDING_SIZE (2048 >> 3)
#define MAX_RSA_SHA_DER_SIZE 64


typedef struct tagKeyData
{
	//DH秘钥交换秘钥
	unsigned char DHPrivKey[4];
	//通信密钥
	unsigned char CommKey[16];
	//会话秘钥
	unsigned char SessionKey[16];

}KeyData;

//加密板卡结构体
typedef struct tagSENCryptCard{

	void*					dev_handle;		//libusb操作句柄
	int						Dev_Path[16];	//设备地址
	void*					ctx;			//libusb操作容器
	int						OpenSign;		//调用打开标识
	void*					DevCtx;			//设备数据容器
	void*					DevLock;		//设备并发锁

} SENCryptCard;

//enum
enum key_bits
{
	KEY_BITS_128 = 128,
	KEY_BITS_192 = 192,
	KEY_BITS_256 = 256,
	KEY_BITS_1024 = 1024,
	KEY_BITS_2048 = 2048
};

enum hash_algorithm_type
{
	HASH_SHA1 = 1,
	HASH_SHA256 = 2
};

enum pad_mode
{
	PAD_MODE_NONE = 1,
	PAD_MODE_PKCS_1_V1_5 = 2
};



//错误码匹配
unsigned int ErrCheck(unsigned char *Buf);
//板卡错误码匹配
unsigned int RetCheck(unsigned char *Buf, unsigned int *ReceiveLength, unsigned int CheckCode);
//usb错误码匹配
int usbErrorCheck(int cc);
//LE-BE大小端转换
void reverse(unsigned char *a, int s);
//DH秘钥交换
unsigned int SENC_DH_KeyExchange(SENCryptCard* sencDev);

void RandGenerator(unsigned char* buf,int len);
void RandSeed();
void dumpHex(unsigned char *buf, int len);

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#define SENC_INT unsigned int
#define SENC_API
#elif defined(linux) || defined(__linux__)
#define SENC_INT unsigned long
#define SENC_API extern "C" 
#endif

#endif //LIBSENC_SENC_ASSIST_H_