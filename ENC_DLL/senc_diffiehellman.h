#ifndef LIBSENC_SENC_DIFFIEHELLMAN_H_
#define LIBSENC_SENC_DIFFIEHELLMAN_H_

#define		DIFFIE_HELLMAN_P		0x3D13EEA5
#define		DIFFIE_HELLMAN_G		0x07

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#define SENC_LONG __int64
#elif defined(linux) || defined(__linux__)
#define SENC_LONG long long
#endif

#define LFSR(n) {if (n&1) n=((n^0x80000055)>>1)|0x80000000; else n>>=1;}
#define ROT(x, y) (x=(x<<y)|(x>>(32-y)))
#define MAX_RANDOM_INTEGER 2147483648 //Should make these numbers massive to be more secure
#define MAX_PRIME_NUMBER 2147483648 //Bigger the number the slower the algorithm


unsigned SENC_LONG DH_GenerateRandomNumber(void);
unsigned SENC_LONG DH_CmpPubKey(unsigned SENC_LONG Rand_a);
unsigned SENC_LONG DH_CmpPrivKey(unsigned SENC_LONG Rand_a,unsigned SENC_LONG ReceivedB);

#endif //LIBSENC_SENC_DIFFIEHELLMAN_H_