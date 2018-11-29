
#include "libsenc.h"
#include "senc_rsa.h"
#include "senc_assist.h"
#include "senc_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#elif defined(linux) || defined(__linux__)
#include "openssl/rsa.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "openssl/objects.h"
#include "openssl/bn.h"
#endif


int new_bignum_4_openssl(BIGNUM **outbn, unsigned char *data, int bitlen){
	int bytelen = bitlen >> 3;
	BIGNUM *bn = BN_new();
	if (NULL == bn) {
		return ERROR_LOG(SENC_ERROR_OPENSSL_BN_NEW,"OpenSSL Error: New BigNum Failed");
	}
	if (NULL == bn_expand(bn, bitlen)) {
		BN_free(bn);
		return ERROR_LOG(SENC_ERROR_OPENSSL_BN_EXPAND,"OpenSSL Error: Expand BigNum Failed");
	}
	memcpy(bn->d, data, bytelen);
	bn->top = bytelen / BN_BYTES;
	bn_fix_top(bn);
	*outbn = bn;
	return SENC_SUCCESS;
}


int new_rsa_from_pure_public_key(RSA **outrsa, unsigned char *key, unsigned int keylen)
{
	int ret_code = SENC_SUCCESS;
	RSA *rsa = NULL;
	int key_unit = keylen >> 1;

	rsa = RSA_new();
	if (NULL == rsa) {
		return ERROR_LOG(SENC_ERROR_OPENSSL_RSA_NEW,"OpenSSL Error: New RSA struct Failed");
	}
	ret_code = new_bignum_4_openssl(&rsa->n, key, key_unit << 3);
	if (ret_code != SENC_SUCCESS) {
		RSA_free(rsa);
		return ret_code;
	}
	ret_code = new_bignum_4_openssl(&rsa->e, key+key_unit, key_unit << 3);
	if (ret_code != SENC_SUCCESS) {
		RSA_free(rsa);
	} else {
		*outrsa = rsa;
	}
	return ret_code;
}

unsigned int pkcs_1_v1_5_encode(int block_type, const unsigned char *from, unsigned int flen, unsigned char *to, unsigned int tlen)
{
	int i, j;
	unsigned char *p;

	if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
		return ERROR_LOG(1,"PKCS Encode Error: Data Too Long");
	}

	p = to;

	*(p++) = 0;
	*(p++) = (unsigned char)block_type; // Public Key BT (Block Type) 

	// pad out with non-zero random data 
	j = tlen - 3 - flen;

	if (PKCS_1_V1_5_EME == block_type) {
		if (RAND_bytes(p, j) <= 0)
			return ERROR_LOG(2,"PKCS Encode Error: Random Data Is Negative");
		for (i = 0; i < j; ++i) {
			if (*p == '\0')
				do {
					if (RAND_bytes(p, 1) <= 0)
						return ERROR_LOG(3,"PKCS Encode Error: Random Data Is Negative");
				} while (*p == '\0');
			p++;
		}
		*(p++) = '\0';
	} else {
		memset(p, 0xFF, j);
	}
	to[2+j] = 0;

	memcpy(&to[2+j+1], from, flen);
	return 0;
}


unsigned int pkcs_1_v1_5_decode(int block_type, const unsigned char *from, unsigned int flen, unsigned char *to, unsigned int tlen, unsigned int *olen)
{
	int i, j;
	// 	unsigned char *p;

	if (flen > (tlen + RSA_PKCS1_PADDING_SIZE)) {
		return ERROR_LOG(0x0a,"PKCS Decode Error: Data Length Error");
	}
	if (from[0] != 0 && from[1] != (unsigned char)block_type) {
		return ERROR_LOG(0x0b,"PKCS Decode Error: Data Header Error");
	}

	if (PKCS_1_V1_5_EME == block_type) {
		for (i = 2; i <(int) flen; ++i) {
			if (from[i] == 0x00)
				break;
		}
		j = i++ - 2;
		if (i >=(int) flen || j < 8) {
			return ERROR_LOG(0x0c,"PKCS Decode Error: Data Length Error");
		}
	} else {
		for (i = 2; i < (int)flen; ++i) {
			if (from[i] != 0xFF)
				break;
		}
		if (from[i] != 0x00)
			return ERROR_LOG(0x0d,"PKCS Decode Error: Data End Error");
		j = i - 2;
	}

	if (*olen < (flen - (2 + j + 1))) {
		*olen = flen - (2 + j + 1);
		return ERROR_LOG(0x0e,"PKCS Decode Error: Decoded Data Length Error");
	}
	*olen = flen - (2 + j + 1);
	memcpy(to, &from[2+j+1], *olen);
	return 0;
}

void sha1(const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen)
{
	SHA1(in, inlen, out);
	*outlen = SHA_DIGEST_LENGTH;
}

void sha256(const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen)
{
	SHA256(in, inlen, out);
	*outlen = SHA256_DIGEST_LENGTH;
}

int pure_rsa_pub_key_encrypt(unsigned char *pubkey, unsigned int keylen, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen)
{
	int ret_code = SENC_SUCCESS;
	int openssl_ret = 0;
	RSA *rsa = NULL;
	ret_code = new_rsa_from_pure_public_key(&rsa, pubkey, keylen);
	if (SENC_SUCCESS != ret_code) {
		return ret_code;
	}
	openssl_ret = RSA_public_encrypt(inlen, in, out, rsa, RSA_NO_PADDING);
	RSA_free(rsa);
	if (-1 == openssl_ret) {
		return ERROR_LOG(SENC_ERROR_OPENSSL_RSA_PUBLIC_ENCRYPT,"OpenSSL Error: RSA Public Key Encrypt Failed");
	}
	*outlen = openssl_ret;
	return SENC_SUCCESS;
}

int pure_rsa_pub_key_decrypt(unsigned char *pubkey, unsigned int keylen, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen)
{
	int ret_code = SENC_SUCCESS;
	int openssl_ret = 0;
	RSA *rsa = NULL;
	ret_code = new_rsa_from_pure_public_key(&rsa, pubkey, keylen);
	if (SENC_SUCCESS != ret_code) {
		return ret_code;
	}
	openssl_ret = RSA_public_decrypt(inlen, in, out, rsa, RSA_NO_PADDING);
	RSA_free(rsa);
	if (-1 == openssl_ret) {
		return ERROR_LOG(SENC_ERROR_OPENSSL_RSA_PUBLIC_DECRYPT,"OpenSSL Error: RSA Public Key Decrypt Failed");
	}
	*outlen = openssl_ret;
	return SENC_SUCCESS;
}