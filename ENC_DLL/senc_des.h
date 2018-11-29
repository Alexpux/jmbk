#ifndef LIBSENC_SENC_DES_H_
#define LIBSENC_SENC_DES_H_

#include "libsenc.h"

//*函数：API_calculateMAC()
//*功能：MAC计算||Calculate MAC
unsigned int API_calculateMAC(unsigned char *srcBuf, unsigned int len, unsigned char *key, unsigned char *init);


#endif //LIBSENC_SENC_DES_H_