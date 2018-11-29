#include "senc_diffiehellman.h"

#if defined(linux) || defined(__linux__)
#include <time.h>
#include <stdlib.h>
#endif

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
//generate RTSC, only works in WIN os
SENC_LONG GetRTSC(void)
{
	int tmp1 = 0;
	int tmp2 = 0;

	__asm
	{
		RDTSC;// Clock cycles since CPU started
		mov tmp1, eax;
		mov tmp2, edx;
	}
	return ((SENC_LONG)tmp1 * (SENC_LONG)tmp2);
}
#endif

//random number generation
unsigned SENC_LONG DH_GenerateRandomNumber(void)
{

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	static unsigned long rnd = 0x41594c49;
	static unsigned long x = 0x94c49514;
	LFSR(x);
	rnd ^= GetRTSC() ^ x;
	ROT(rnd, 7);
	return (unsigned SENC_LONG)GetRTSC() + rnd;
#elif defined(linux) || defined(__linux__)
	return rand();
#endif

}


SENC_LONG XpowYmodN(SENC_LONG x, SENC_LONG y, SENC_LONG N)
{
	SENC_LONG tmp = 0;
	if (y == 1) return (x % N);
	if ((y & 1) == 0)
	{
		tmp = XpowYmodN(x, y / 2, N);
		return ((tmp * tmp) % N);
	}
	else
	{
		tmp = XpowYmodN(x, (y - 1) / 2, N);
		tmp = ((tmp * tmp) % N);
		tmp = ((tmp * x) % N);
		return (tmp);
	}
}

//calculate A
unsigned SENC_LONG DH_CmpPubKey(unsigned SENC_LONG Rand_a){
	unsigned SENC_LONG p=DIFFIE_HELLMAN_P,g=DIFFIE_HELLMAN_G,A;
	A=XpowYmodN(g,Rand_a,p);
	return A;
}

//calculate the key
unsigned SENC_LONG DH_CmpPrivKey(unsigned SENC_LONG Rand_a,unsigned SENC_LONG ReceivedB){
	unsigned SENC_LONG p=DIFFIE_HELLMAN_P,PKey;
	PKey=XpowYmodN(ReceivedB,Rand_a,p);
	return PKey;
}


