#ifndef LIBSENC_PTRCONVERTER_H_
#define LIBSENC_PTRCONVERTER_H_

#include "libsenc.h"
#include "senc_assist.h"



#define			SENC_MAGIC_CODE													0x7fff124E
static SENCHANDLE Ptr2SencHandle(SENCryptCard* pstPointer){
	return (SENCHANDLE)(((SENC_INT) (pstPointer))^ SENC_MAGIC_CODE);
}
static SENCryptCard* SencHandle2Ptr(SENCHANDLE hSencHandle){
	SENCryptCard* pstRetDev = NULL;
	if(hSencHandle == NULL) return NULL;
	pstRetDev = (SENCryptCard*)(((SENC_INT)(hSencHandle))^SENC_MAGIC_CODE);
	return pstRetDev;
}

#endif //LIBSENC_PTRCONVERTER_H_