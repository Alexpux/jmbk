#include "senc_assist.h"
#include "senc_cmd_frame.h"
#include "libsenc.h"
#include "senc_usbapi.h"
#include "senc_diffiehellman.h"
#include "senc_aes.h"
#include "senc_error.h"
// #include "lock.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>


unsigned int ErrCheck(unsigned char *Buf){return SencErrCheck(Buf);}
//板卡错误码匹配
unsigned int RetCheck(unsigned char *Buf, unsigned int *ReceiveLength, unsigned int CheckCode){return SencRetCheck(Buf, ReceiveLength, CheckCode);}
//usb错误码匹配
int usbErrorCheck(int cc){return SencUsbErrorCheck(cc);}


//LE-BE转换
void reverse(unsigned char *a, int s){
	int i=0,j=s-1;
	unsigned char tmp;
	for(i=0;i<j;++i,--j){
		tmp=*(a+i);
		*(a+i)=*(a+j);
		*(a+j)=tmp;
	}
}


//*函数：SENC_DH_KeyExchange()
//*功能：Diffie Hellman秘钥交换||Key exchange in DiffieHellman
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//		unsigned char*	pucSendData					//待发送数据
// 		unsigned int	uiSendLength				//待发送数据长度
// 		unsigned char*	pucReadData					//接收数据
//		unsigned int	uiReadLength				//接收数据长度
//*日期：2016/10/24
//by Wangjf
unsigned int SENC_DH_KeyExchange(	SENCryptCard*			sencDev)						//加密卡设备handle
{
	unsigned long RndN,SendA,RecvB,PrivKey;
	unsigned char ucSendA[4]={0};
	unsigned char ucRecvB[4]={0};
	unsigned char ucRecvEncKey[16]={0};

	unsigned int ucRet = 0;
	if(!sencDev) return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Key Exchange Error: Device Not Found");

	//generate random number
	RndN=(unsigned long)DH_GenerateRandomNumber();

	SendA=(unsigned long)DH_CmpPubKey(RndN);
	ucSendA[0]=(SendA>>24)&0xff;
	ucSendA[1]=(SendA>>16)&0xff;
	ucSendA[2]=(SendA>>8)&0xff;
	ucSendA[3]=SendA&0xff;

	//exchange with card
	ucRet=SENC_CMD_KEX_KeyExchange(sencDev,ucSendA,ucRecvB,ucRecvEncKey);
	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	RecvB=(ucRecvB[0]<<24)|(ucRecvB[1]<<16)|(ucRecvB[2]<<8)|ucRecvB[3];

	//calculate private key
	PrivKey=(unsigned long)DH_CmpPrivKey(RndN,RecvB);

	((KeyData*)(sencDev->DevCtx))->DHPrivKey[0]=(PrivKey>>24)&0xff;
	((KeyData*)(sencDev->DevCtx))->DHPrivKey[1]=(PrivKey>>16)&0xff;
	((KeyData*)(sencDev->DevCtx))->DHPrivKey[2]=(PrivKey>>8)&0xff;
	((KeyData*)(sencDev->DevCtx))->DHPrivKey[3]=PrivKey&0xff;

	//calculate comm key and save
	ucRet=SENC_AES_DHPrivCal(sencDev,ucRecvEncKey);

	if(ucRet!=SENC_SUCCESS)
		return ucRet;

	return SENC_SUCCESS;
}

void RandSeed(){
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	srand((unsigned int)time(0));
#elif defined(linux) || defined(__linux__)
	srand((long)time(0));
#endif
	return;
}

//Rand num generator
void RandGenerator(unsigned char* buf,int len){
	for(int i=0;i<len;i++){
		buf[i]=rand()&0xff;
	}
	return;
}

void dumpHex(unsigned char *buf, int len)
{
    unsigned int i =0,j = 0;
    unsigned int cur = 0;
    unsigned int linemax =0;
    unsigned int nprinted = 0 ;
    int flag = 0;
    if (0 == len) {
        return;
    }
    printf("hex_view = %u bytes\r\noffset 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\r\n",len);
    i=0;j=0;flag = 1;
    do {
        printf("%04X | ",(nprinted / 16) );
        if (nprinted >= (unsigned int)len) {
            flag = 0;
            break;
        }
        linemax = 16;
        for (j = 0; j < linemax; ++j) {
            cur = i  + j ;
            if (cur >= (unsigned int)len ) {
                flag = 0;
                printf("   ");
            } else {
                printf("%02X ", buf[cur]);
                ++nprinted;
            }
        }
        printf("| ");
        for (j = 0; j < linemax; ++j) {
            cur = i  + j ;
            if (cur >= (unsigned int)len) {
                flag = 0;
                break;
            }
            if (buf[cur] > 30 && buf[cur] < 127) {
                printf("%c", buf[cur]);
            } else {
                printf(".");
            }
        }
        i += 16;
        printf("\r\n");
    } while (flag);
    printf("\r\n");
}

