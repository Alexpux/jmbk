#ifndef _DEV_CA_CLI_PROXY_H_
#define _DEV_CA_CLI_PROXY_H_

#include <stdint.h>

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#define DCC_RESP_DESC_BUF_SIZE                     (64)
#define DCC_RESP_CERT_BUF_SIZE                     (4096)

#define DCC_ERR_CA_SVC_CODE_BASE                   0x00001000
#define DCC_ERR_SOAP_CODE_BASE                     0x00002000

#define DCC_ERR_OK                                 0x00000000
#define DCC_ERR_INVALID_PARAM                      0x00000001
#define DCC_ERR_MALLOC_FAIL                        0x00000002
#define DCC_ERR_SET_SOAP_SSL_CLI_CTX_FAIL          0x00000003
#define DCC_ERR_CHAR_TO_WCHAR_FAIL                 0x00000004
#define DCC_ERR_WCHAR_TO_CHAR_FAIL                 0x00000005
#define DCC_ERR_BASE64_ENCODE_FAIL                 0x00000006
#define DCC_ERR_BASE64_DECODE_FAIL                 0x00000007
#define DCC_ERR_CAN_NOT_FIND_CERT_IN_RESP          0x00000008

#define DCC_REDIRECT_SVC_CODE(svccode)             ((DCC_ERR_CA_SVC_CODE_BASE) | (svccode))
#define DCC_REDIRECT_SOAP_CODE(soapcode)           ((DCC_ERR_SOAP_CODE_BASE) | (soapcode))

#ifdef __cplusplus
extern "C" {
#endif
	
	typedef struct _dcc_cert_resp {
		char desc[DCC_RESP_DESC_BUF_SIZE];
		uint32_t cert_len;
		uint8_t cert[DCC_RESP_CERT_BUF_SIZE];
	} dcc_cert_resp;

	int32_t dcc_init(
		IN const char *url,
		IN const uint32_t conn_timeout,//2s
		IN const uint32_t sock_timeout);//90s

	void dcc_release();

	int32_t dcc_request_cert(
		IN const uint32_t csr_len,
		IN uint8_t *csr,
		IN OUT dcc_cert_resp *resp);

#ifdef __cplusplus
}
#endif

#endif