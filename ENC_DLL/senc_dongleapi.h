#ifndef LIBSENC_SENC_DONGLEAPI_H_
#define LIBSENC_SENC_DONGLEAPI_H_

#include "libsenc.h"

#define			SENC_ERROR_DONGLES												0x20000000


#define CMD_READ_FILE			"\x00\xB0\x00\x00\x88"
#define PUBKEY_FID				0x01

#define CMD_GET_ID				"\x80\xCA\x02\x00\x08"

#define CMD_SIGN				"\x80\xC8\x01\x00\x80"
#define PRIKEY_FID				0x02

#define CMD_TDES_ENC			"\x80\xF8\x00\x00\x08"
#define CMD_TDES_DEC			"\x80\xF8\x01\x00\x08"
#define CMD_INTAUTH				"\x00\x88\x00\x00\x08"
#define CMD_FLASH_KEY_ENC		"\x80\xF8\x00\x01\x08"
#define CMD_FLASH_KEY_DEC		"\x80\xF8\x01\x01\x08"

#define CMD_CREATE_FLIE_SYSTEM	"\x80\xE0\x00\x00\x11\x5A\x36\x5A\x36\x5A\x36\x5A\x36\xF0\x88\x00\x1E\x4F\x70\x65\x72\x61"

#define CMD_CREATE_KEY_FILE		"\x80\xE0\x02\x05\x08\xEF\x01\x0F\xF0\x00\x00\x09\x18"

#define CMD_INSTALL_PIN			"\x80\xD4\x00\x00\x0F\x00\x00\x05\x0F\xF0\x80\x0F\x3F\x71\x74\x9C\xFA\xC7\x47\xB1"

#define CMD_INSTALL_KEY			"\x80\xD4\x00\x00\x17\x00\x00\x01\x0F\xF0\x01\x00"


#define CMD_ENABLE_SECURE		"\x80\xE0\x00\x01\x00"

unsigned int SENC_DongleAPI_NewDongle(SENCryptCard*	sencDev);

unsigned int SENC_DongleAPI_GetRndNum(SENCryptCard*	sencDev,unsigned char* keyIdx1, unsigned char* keyIdx2,unsigned char* RandNum,unsigned char* EncFlashKey);
unsigned int SENC_DongleAPI_VerifyStep(SENCryptCard* sencDev,unsigned char keyidx1, unsigned char keyidx2,unsigned char* inRndNum,unsigned char* inEncFlashKey);
unsigned int SENC_DongleAPI_Verify(SENCryptCard* sencDev);
unsigned int SENC_DongleAPI_DeletePlugDongle(SENCryptCard*	sencDev);
unsigned int SENC_DongleAPI_NewDongle_Group(SENCryptCardList* DevList);

//key for test
#define CMD_TEST_AUTHKEY		"\x0B\x15\x48\xB4\x24\xCF\x4B\x58\xB7\x91\x17\x1A\x3D\xBA\x8A\xC1"
#define CMD_TEST_FLASHKEY		"\xAD\x87\x49\x80\x8F\xAB\x69\xAD\x87\x49\x80\x8F\xAB\x69\xAB\x69"


#endif //LIBSENC_SENC_DONGLEAPI_H_