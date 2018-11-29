#ifndef LIBSENC_SENC_RSA_H_
#define LIBSENC_SENC_RSA_H_

#include <stdint.h>

enum pkcs_1_v1_5_blocks
{
	PKCS_1_V1_5_EMSA = 1,    // Block type 1 (PKCS #1 v1.5 signature padding) 
	PKCS_1_V1_5_EME  = 2     // Block type 2 (PKCS #1 v1.5 encryption padding) 
};

enum pkcs_1_paddings
{
	PKCS_1_V1_5 = 1,         // PKCS #1 v1.5 padding (\sa pkcs_1_v1_5_blocks) 
	PKCS_1_OAEP = 2,         // PKCS #1 v2.0 encryption padding 
	PKCS_1_PSS  = 3          // PKCS #1 v2.1 signature padding 
};

unsigned int pkcs_1_v1_5_encode(int block_type, const unsigned char *from, unsigned int flen, unsigned char *to, unsigned int tlen);
unsigned int pkcs_1_v1_5_decode(int block_type, const unsigned char *from, unsigned int flen, unsigned char *to, unsigned int tlen, unsigned int *olen);
void sha1(const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);
void sha256(const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);

// int der_rsa_pub_key_decrypt(unsigned char *pubkey, unsigned int keylen, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);
int pure_rsa_pub_key_encrypt(unsigned char *pubkey, unsigned int keylen, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);
int pure_rsa_pub_key_decrypt(unsigned char *pubkey, unsigned int keylen, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);

#endif // LIBSENC_SENC_RSA_H_ 
