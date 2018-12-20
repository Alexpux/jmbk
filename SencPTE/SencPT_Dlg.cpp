// SencPT_Dlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "SencPT.h"
#include "SencPT_Dlg.h"
#include "afxdialogex.h"
#include <stdio.h>
#include "libsenc.h"

#include "openssl/rsa.h"
#include "openssl/aes.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"

#include "sm2.h"
#include "sm3.h"
#include "sm4.h"


extern "C"
{
#include "openssl/applink.c"
}
#include <string>
#include <direct.h>
#include "devcacli.h"

#define WM_MSG_LOG (WM_USER + 1)
#define WM_MSG_ERROR (WM_USER + 2)
#define WM_MSG_FINISH (WM_USER + 3)
#define WM_MSG_START (WM_USER + 4)
#define WM_MSG_TRANSMIT (WM_USER + 5)
#define WM_MSG_CLRS (WM_USER + 6)
#define WM_MSG_FFFF (WM_USER + 7)

#define SENC_RSA_PARAMETER_LEN 128

#define	JMBK_CERT_PATH			"./֤��/mock-card.cer"		//���ܰ忨�豸֤��
#define	JMBK_CERT_CSR_PATH		"./֤��/devcertcsr"			//���ܰ忨�豸CSR
#define	DEVICECA_CERT_PATH		"./֤��/st.device.ca.cer"	//�豸CA֤��
#define	ROOTCA_CERT_PATH		"./֤��/st.root.ca.cer"		//��֤��

#define	JMJ_CERT_PATH			"./֤��/st.device.cer"		//���ܻ��豸֤��
#define	JMJ_PRIKEY_PATH			"./֤��/st.device.pri"		//���ܻ�˽Կ

#define DEFAULT_SM2_SIGN_USER_ID			"1234567812345678"
#define DEFAULT_SM2_SIGN_USER_ID_LEN		16
#define SM3_DIGEST_LENGTH					32

#define RTC_TIME_PIN_CODE					"\x00\x11\x22\x33\x44\x55\x66\x77"
#define RTC_TIME_PIN_CODE_LEN				8
// IMPLEMENT_DYNAMIC(SencPT_Dlg, CDialogEx)

#define SM2_PUBKEY_LEN						64						//SM2��Կ����
#define SM2_PRIKEY_LEN						32						//SM2˽Կ����

//�Զ���д������
const static unsigned char _seed[] =
"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";
const static unsigned char _seed1[] = { 
	0xA4, 0x8F, 0xC8, 0x6D, 0x02, 0x22, 0xEF, 0x9E, 0xB2, 0x6F, 0x2B, 0xB9, 0x44, 0x4F, 0xBC, 0xCD, 
	0x89, 0xA4, 0x32, 0x7E, 0x97, 0xDE, 0xCF, 0xAE, 0x4A, 0x83, 0xF5, 0x65, 0x37, 0x98, 0x6E, 0xA6 };
const static unsigned char _seed2[] = { 
	0x56, 0xD5, 0x5C, 0x3B, 0x40, 0x72, 0x7B, 0xC1, 0x58, 0xE2, 0xF5, 0x5E, 0x6D, 0x85, 0x5B, 0xBB, 
	0xA1, 0x8E, 0x27, 0xAA, 0x4C, 0xC7, 0xDB, 0x0A, 0xB3, 0xB7, 0xA0, 0x3D, 0x9E, 0xD8, 0x5C, 0x15 };

static unsigned char sm4_key[] = {
	0x54, 0x5D, 0xBA, 0x6B, 0xE5, 0xA2, 0x45, 0x40, 0xA1, 0xCE, 0x99, 0xC6, 0xFB, 0xED, 0xCC, 0xE8 };
static unsigned char sm4_iv[16] = {
	0x3E, 0x62, 0xBB, 0x39, 0x1F, 0xDF, 0xDB, 0x2F, 0x33, 0x08, 0x71, 0x04, 0xEF, 0xC9, 0xB5, 0xF7};

static unsigned char jmjpri[] =
{ 0x78, 0x6E, 0xEA, 0xED, 0x28, 0xD1, 0x60, 0x24, 0xD4, 0xA7, 0xB6, 0xB6, 0x75, 0xC8, 0x64, 0x54,
  0x10, 0xAC, 0x30, 0xF9, 0xC8, 0x10, 0x27, 0x86, 0xEF, 0x60, 0x16, 0x6C, 0xDB, 0xAB, 0xFF, 0x00 };

static unsigned char jmjpub[65] =
{
	0x04, 0x09, 0xFB, 0x73, 0xA1, 0x7D, 0xE3, 0x26, 0x05, 0x22, 0x70, 0xE6, 0xDB, 0xD8, 0xB7, 0x9A,
	0xD3, 0x28, 0x89, 0x46, 0x92, 0xF4, 0x39, 0xBA, 0x71, 0x8F, 0x8D, 0x24, 0xC9, 0xF4, 0x47, 0xE2,
	0x6B, 0x7D, 0x46, 0x5D, 0xDD, 0x84, 0x13, 0x74, 0x3A, 0x36, 0xCF, 0xEC, 0x16, 0xBD, 0x42, 0x5D,
	0xB6, 0x2E, 0x01, 0x3A, 0x37, 0xC1, 0x8B, 0x8B, 0x45, 0xF8, 0x0E, 0xE9, 0x52, 0x13, 0xB8, 0x9E,
	0xDC
};

unsigned char Pri[33] = { 0 };
unsigned char Pub[66] = { 0 };

unsigned char kenc[32] = { 0 };
unsigned char kmac[32] = { 0 };

EC_GROUP *group = NULL;
EC_KEY	*eckey = NULL;


SencPT_Dlg::SencPT_Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(SencPT_Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

SencPT_Dlg::~SencPT_Dlg()
{
	delete sn;
	delete fn;
	delete tn;
	SENC_FreeDevList(&gDevList);
}

void SencPT_Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_SNUM, SNumCtr);
	DDX_Control(pDX, IDC_EDIT_FNUM, FNumCtr);
	DDX_Control(pDX, IDC_EDIT_TNUM, TNumCtr);
	DDX_Control(pDX, IDC_EDIT_LOG, LogCtr);
	DDX_Control(pDX, IDC_BUTTON_PRODUCTION, StartBtnCtr);
	DDX_Control(pDX, IDC_PROGRESS, mPrgsCtr);
}


BEGIN_MESSAGE_MAP(SencPT_Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_CTLCOLOR()

	ON_BN_CLICKED(IDC_BUTTON_PRODUCTION, &SencPT_Dlg::OnBnClickedButtonProduction)
	ON_BN_CLICKED(IDC_BUTTON_FLASH_ERASE, &SencPT_Dlg::OnBnClickedButtonFlashErase)
	ON_BN_CLICKED(IDC_BUTTON_GET_LIST, &SencPT_Dlg::OnBnClickedButtonGetList)
	ON_BN_CLICKED(IDC_BUTTON_INIT, &SencPT_Dlg::OnBnClickedButtonInit)
END_MESSAGE_MAP()


// SencPT_Dlg ��Ϣ�������
BOOL SencPT_Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	sn=new CFont;
	tn=new CFont;
	fn=new CFont;

	sn->CreateFont(80,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,UNICODE,OUT_DEFAULT_PRECIS,OUT_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH|FF_SWISS,_T("Arial"));
	fn->CreateFont(80,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,UNICODE,OUT_DEFAULT_PRECIS,OUT_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH|FF_SWISS,_T("Arial"));
	tn->CreateFont(80,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,UNICODE,OUT_DEFAULT_PRECIS,OUT_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH|FF_SWISS,_T("Arial"));

	SuccussTimes=0;
	FailedTimes=0;
	TotalTimes=0;

	CString tMsg;

	tMsg.Format(_T("%d"),SuccussTimes);
	SNumCtr.SetWindowTextW(tMsg);
	tMsg.Format(_T("%d"),FailedTimes);
	FNumCtr.SetWindowTextW(tMsg);
	tMsg.Format(_T("%d"),TotalTimes);
	TNumCtr.SetWindowTextW(tMsg);
	SNumCtr.SetFont(sn);
	FNumCtr.SetFont(fn);
	TNumCtr.SetFont(tn);

	mPrgsCtr.SetRange(0,100);
	mPrgsCtr.SetStep(5);
	mPrgsCtr.SetPos(100);

	GetModuleFileName(NULL,szFilePath,MAX_PATH);
	(_tcsrchr(szFilePath,_T('\\')))[1]=0;
	iniUrl=szFilePath;
	iniUrl.Append(_T("config.ini"));

	productCount=1;

	tardev=0;
	SENC_NewDevList(&gDevList);

	CString temp=szFilePath;
	temp.Append(_T("Logs"));
	CreateDirectory(temp,NULL);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE

}

void SencPT_Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{

	CDialogEx::OnSysCommand(nID, lParam);
}

void SencPT_Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR SencPT_Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

HBRUSH SencPT_Dlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

	switch (nCtlColor)
	{
	case CTLCOLOR_STATIC:
		switch (pWnd->GetDlgCtrlID())
		{
		case IDC_EDIT_SNUM:
			pDC->SetTextColor(RGB(0, 128, 0));
			break;
		case IDC_EDIT_FNUM:
			pDC->SetTextColor(RGB(255, 0, 0));
			break;
		case IDC_EDIT_TNUM:
			pDC->SetTextColor(RGB(0, 0, 0));
			break;
		default:
			hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);
			break;
		}

		break;
	}	// TODO:  ���Ĭ�ϵĲ������軭�ʣ��򷵻���һ������
	return hbr;
}

LRESULT SencPT_Dlg::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	CString logstr;
	//////////////

	if(message == WM_MSG_LOG){
		CString *pMsgStr = (CString*) wParam;
		logstr = pMsgStr->GetBuffer();
		LogCtr.SetWindowTextW(logstr);
		delete pMsgStr;
	}


	if(message == WM_MSG_FINISH)
	{
		CString *pMsgStr = (CString*)wParam;

		SuccussTimes++;
		logstr = pMsgStr->GetBuffer();
		LogCtr.SetWindowTextW(logstr);
		CountUpdate();
		delete pMsgStr;
	}


	if(message == WM_MSG_START)
	{
		CString *pMsgStr = (CString*)wParam;

		TotalTimes++;
		logstr = pMsgStr->GetBuffer();
		LogCtr.SetWindowTextW(logstr);
		CountUpdate();
		delete pMsgStr;
	}


	if(message == WM_MSG_ERROR)
	{
		CString *pMsgStr = (CString*)wParam;

		FailedTimes++;
		logstr = pMsgStr->GetBuffer();
		LogCtr.SetWindowTextW(logstr);
		CountUpdate();

		CTime tTime=CTime::GetCurrentTime();
		CString LogFile,tempmsg;
		LogFile = szFilePath;
		LogFile += tTime.Format(_T("Logs\\SencLog_%Y%m%d.txt"));
		FILE *fp;
		_wfopen_s(&fp,LogFile,_T("a+"));
		tempmsg = tTime.Format(_T("%Y��%m��%d�� %H:%M:%S  ��������"));
		tempmsg += logstr;

		USES_CONVERSION;
		CStringA tStr = W2A(tempmsg);
		if(fp){
			fwrite(tStr.GetBuffer(),tStr.GetLength(),1,fp);
			fclose(fp);
		}

		delete pMsgStr;
	}

	logstr.ReleaseBuffer();

	return CDialogEx::WindowProc(message, wParam, lParam);

}

void SencPT_Dlg::PostLog(const CString & _log)
{
	CString *pLog = new CString(_log);
	PostMessage(WM_MSG_LOG, (WPARAM)pLog, NULL);
}

void SencPT_Dlg::PostErr(const CString & _log)
{
	CString *pLog = new CString(_log);
	PostMessage(WM_MSG_ERROR, (WPARAM)pLog, NULL);
}

void SencPT_Dlg::PostFin(const CString & _log)
{
	CString *pLog = new CString(_log);
	PostMessage(WM_MSG_FINISH, (WPARAM)pLog, NULL);

}

void SencPT_Dlg::PostStart(const CString & _log)
{
	CString *pLog = new CString(_log);
	PostMessage(WM_MSG_START, (WPARAM)pLog, NULL);

}

void SencPT_Dlg::PostFFFF()
{
	// 	SENC_Close(&gHandle);
	PostMessage(WM_MSG_FFFF, NULL, NULL);
	// 	init();
}

void SencPT_Dlg::CountUpdate(){
	CString tMsg;

	tMsg.Format(_T("%d"), SuccussTimes);
	SNumCtr.SetWindowTextW(tMsg);
	tMsg.Format(_T("%d"), FailedTimes);
	FNumCtr.SetWindowTextW(tMsg);
	tMsg.Format(_T("%d"), TotalTimes);
	TNumCtr.SetWindowTextW(tMsg);

}

void invert(unsigned char* buf, int len)
{
	int i;
	for (i = 0; i < len / 2; i++)
	{
		buf[i] ^= buf[len - i - 1];
		buf[len - i - 1] ^= buf[i];
		buf[i] ^= buf[len - i - 1];
	}
}


#define SIGN_KEY_SHA256_RSA2048        1
#define ENC_KEY_RSA2048				   2
#define AES_128_ECB                    3
#define AES_256_EBC                    4
#define AES_256_CBC                    5
#define SM4_CBC						   6

#define SEED_CODE_LEN              (32) //�����볤��
#define KSEED_LEN_32               (32)
#define AES_KEY_LEN_32             (32)
#define KENC_KEY_LEN               AES_KEY_LEN_32
#define KMAC_KEY_LEN               (16)
#define H5_FIXED_HEAD_LEN          (12)
#define RANDOM_SIZE_32             (32)
#define H5_RSA_STD_HEAD_LEN        (12)

#define SESSIONKEY_BITS_128        (128)
#define PUBKEY_BITS_256            (256)
#define PUBKEY_BITS_2048           (2048)
#define PRIKEY_BITS_256            (256)
#define PRIKEY_BITS_512            (512)
#define PRIKEY_BITS_2048           (2048)
#define AES_BITS_256               (256)

typedef struct tagRsaData{
	unsigned char n[256];
	unsigned char e[256];
	unsigned char d[256];
	unsigned char p[128];
	unsigned char q[128];
	unsigned char dmp[128];
	unsigned char dmq[128];
	unsigned char iqmp[128];
} RsaData;


void bn2hex(uint8_t *bin, uint32_t len, char *hex)
{
	uint32_t i;

	for (i = 0; i < len; i++)
	{
		sprintf(hex, "%02X", bin[i]);
		hex += 2;
	}
}

//sm2ǩ�������ʹ��
const UINT8 TAG_CLASS_CONTEXT = 0xA0;
const UINT8 TAG_INTEGER = 0x02;
const UINT8 TAG_BIT_STRING = 0x03;
const UINT8 TAG_OCTET_STRING = 0x04;
const UINT8 TAG_OID = 0x06;
const UINT8 TAG_SEQUENCE = 0x30;

//*������eccDerEncodeSignature
//*���ܣ�sm2ǩ��Der����
//*��������
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
UINT16 eccDerEncodeSignature(UINT8 *pu8Sig, UINT16 u16SigLen, UINT8 *pu8DerSig, UINT16 *pu16DerSigLen)
{
	UINT16 u16Index;
	UINT16 u16DerSigLen;
	UINT16 u16RLen, u16SLen;
	UINT16 i;

	u16RLen = u16SLen = u16SigLen / 2;

	if (pu8Sig[0] & 0x80)
		u16RLen++;

	i = 0;
	while ((pu8Sig[i++] == 0) && !(pu8Sig[i] & 0x80))
		u16RLen--;

	if (pu8Sig[u16SigLen / 2] & 0x80)
		u16SLen++;

	i = u16SigLen / 2;
	while ((pu8Sig[i++] == 0) && !(pu8Sig[i] & 0x80))
		u16SLen--;

	u16DerSigLen = u16RLen + u16SLen + 6;

	if (*pu16DerSigLen < u16DerSigLen)
	{
		*pu16DerSigLen = u16DerSigLen;
		return 1;
	}

	*pu16DerSigLen = u16DerSigLen;

	// sequence
	pu8DerSig[0] = TAG_SEQUENCE;
	pu8DerSig[1] = u16DerSigLen - 2;

	// integer r
	pu8DerSig[2] = TAG_INTEGER;
	pu8DerSig[3] = (UINT8)u16RLen;

	u16Index = 4;

	if (pu8Sig[0] & 0x80)
	{
		pu8DerSig[4] = 0;
		u16Index++;
	}

	memcpy(pu8DerSig + u16Index,
		pu8Sig + (u16SigLen / 2 > u16RLen ? u16SigLen / 2 - u16RLen : 0),
		u16SigLen / 2 < u16RLen ? u16SigLen / 2 : u16RLen);

	u16Index += u16SigLen / 2 < u16RLen ? u16SigLen / 2 : u16RLen;

	// integer s
	pu8DerSig[u16Index] = TAG_INTEGER;
	pu8DerSig[u16Index + 1] = (UINT8)u16SLen;

	if (pu8Sig[u16SigLen / 2] & 0x80)
	{
		pu8DerSig[u16Index + 2] = 0;
		u16Index++;
	}

	u16Index += 2;

	memcpy(pu8DerSig + u16Index,
		pu8Sig + u16SigLen / 2 + (u16SigLen / 2 > u16SLen ? u16SigLen / 2 - u16SLen : 0),
		u16SigLen / 2 < u16SLen ? u16SigLen / 2 : u16SLen);

	return 0;
}

//*������eccDerDecodeSignature
//*���ܣ�sm2ǩ��Der����
//*��������
//*���ڣ�2018/12/19  by ZhangTao
UINT16 eccDerDecodeSignature(UINT8 *pu8DerSig, UINT16 u16DerSigLen, UINT8 *pu8Sig, UINT16 u16SigLen)
{
	UINT16 u16Index = 0;
	UINT16 u16Slen = 0;

	// check outer sequence
	if (pu8DerSig[0] != TAG_SEQUENCE)
		return 1;

	if ((pu8DerSig[1] != u16DerSigLen - 2)
		|| (pu8DerSig[1] != 4 + pu8DerSig[3] + pu8DerSig[4 + pu8DerSig[3] + 1]))
		return 1;

	// check integer r
	if (pu8DerSig[2] != TAG_INTEGER)
		return 1;

	if ((pu8DerSig[4] != 0) && (pu8DerSig[3] > u16SigLen / 2))
		return 1;

	u16Index = 4;

	if (pu8DerSig[3] == u16SigLen / 2 + 1)
		u16Index++;

	if (pu8DerSig[3] < u16SigLen / 2)
	{
		memset(pu8Sig, 0, u16SigLen / 2 - pu8DerSig[3]);
		memcpy(pu8Sig + u16SigLen / 2 - pu8DerSig[3], pu8DerSig + u16Index, pu8DerSig[3]);

		u16Index += pu8DerSig[3];
	}
	else
	{
		memcpy(pu8Sig, pu8DerSig + u16Index, u16SigLen / 2);

		u16Index += u16SigLen / 2;
	}

	// check integer s
	if (pu8DerSig[u16Index] != TAG_INTEGER)
		return 1;

	u16Slen = pu8DerSig[u16Index + 1];
	if ((pu8DerSig[u16Index + 2] != 0) && (u16Slen > u16SigLen / 2))
		return 1;

	if (u16Slen == u16SigLen / 2 + 1)
		u16Index++;

	u16Index += 2;

	if (u16Slen < u16SigLen / 2)
	{
		memset(pu8Sig + u16SigLen / 2, 0, u16SigLen / 2 - u16Slen);
		memcpy(pu8Sig + u16SigLen - u16Slen, pu8DerSig + u16Index, u16Slen);
	}
	else
	{
		memcpy(pu8Sig + u16SigLen / 2, pu8DerSig + u16Index, u16SigLen / 2);
	}

	return 0;
}

//*������sm2SignMsg
//*���ܣ�sm2ǩ��
//*������prikey		˽Կ
//		 prikeylen	˽Կ����
//		 pubkey		��Կ
//		 pubkeylen	��Կ����
//		 msg		��Ϣ����
//		 msglen		��Ϣ���ĳ���
//		 sig		ǩ��	 
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
int sm2SignMsg(
	uint8_t *prikey,
	uint32_t prikeylen,
	uint8_t *pubkey,
	uint32_t pubkeylen,
	void *msg,
	uint32_t msglen,
	uint8_t *sig)
{
	int ret;
	BIGNUM *bnPrikey = NULL;
	EC_POINT *ecPubkey = NULL;
	char vkey[65];
	char pkey[131];
	unsigned char digest[32];
	unsigned char dersig[256];
	unsigned int digestlen, dersiglen;

	bn2hex(prikey, prikeylen, vkey);
	bn2hex(pubkey, pubkeylen, pkey);

	BN_hex2bn(&bnPrikey, vkey);
	EC_KEY_set_private_key(eckey, bnPrikey);
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	EC_KEY_set_public_key(eckey, ecPubkey);

	//��Կ����ժҪ
	digestlen = sizeof(digest);
	ret = SM2_digest(
		(unsigned char*)DEFAULT_SM2_SIGN_USER_ID,
		DEFAULT_SM2_SIGN_USER_ID_LEN,
		msg,
		msglen,
		digest,
		&digestlen,
		eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_digest Failed��\n"));
		return 1;
	}

	//˽Կǩ��
	dersiglen = 256;
	ret = SM2_sign(1, digest, sizeof(digest), dersig, &dersiglen, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_sign Failed��\n"));
		return 1;
	}

	ret = eccDerDecodeSignature(dersig, dersiglen, sig, 64);

	//ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	//if (ret != 1)
	//{
	//	AfxMessageBox(_T("SM2_verify Failed��\n"));
	//	return 1;
	//}

	return 0;
}

//*������sm2Verify
//*���ܣ�sm2��ǩ
//*������pubkey		��Կ
//		 pubkeylen	��Կ����
//		 msg		��Ϣ����
//		 msglen		��Ϣ���ĳ���
//		 sig		ǩ��	 
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
int sm2Verify(
	uint8_t *pubkey,
	uint32_t pubkeylen,
	void *msg,
	uint32_t msglen,
	uint8_t *sig)
{
	int ret;
	EC_POINT *ecPubkey = NULL;
	char pkey[131];
	unsigned char digest[32];
	unsigned char dersig[256];
	unsigned int digestlen, dersiglen;

	//��Կbyte����תhex�ַ���
	bn2hex(pubkey, pubkeylen, pkey);
	//��Կhex�ַ���תEC_POINT				group��ȫ�ֱ���EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//ͨ��EC_POINT����EC_KEY�Ĺ�Կ          eckey��ȫ�ֱ���EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey);

	//��������ժҪ
	digestlen = sizeof(digest);
	ret = SM2_digest(
		(unsigned char*)DEFAULT_SM2_SIGN_USER_ID,
		DEFAULT_SM2_SIGN_USER_ID_LEN,
		msg,
		msglen,
		digest,
		&digestlen,
		eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_digest Failed��\n"));
		return 1;
	}
	//sm2ǩ��der���룬��ǩ�ӿ��õ���der������ǩ��
	dersiglen = sizeof(dersig);
	eccDerEncodeSignature(sig, 64, dersig, (UINT16*)&dersiglen);
	//��ǩ������1�ɹ�������0ʧ��,��һ������Ϊ����
	ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_verify Failed��\n"));
		return 1;
	}
	return 0;
}

//*������sm2EncMsg
//*���ܣ�sm����
//*������pubkey		��Կ
//		 pubkeylen	��Կ����
//		 msg		��Ϣ�����ģ�
//		 msglen		��Ϣ�����ģ�����
//		 cipher		����
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
int sm2EncMsg(
	uint8_t *pubkey,
	uint32_t pubkeylen,
	void *msg,
	uint32_t msglen,
	uint8_t *cipher)
{
	int ret;
	char pkey[131];
	EC_POINT *ecPubkey = NULL;
	uint32_t cipherlen;

	//��Կbyte����תhex�ַ���
	bn2hex(pubkey, pubkeylen, pkey);
	//��Կhex�ַ���תEC_POINT				group��ȫ�ֱ���EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//ͨ��EC_POINT����EC_KEY�Ĺ�Կ          eckey��ȫ�ֱ���EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey);

	//SM2����
	ret = SM2_encrypt_with_recommended(cipher, &cipherlen, (unsigned char*)msg, msglen, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_encrypt_with_recommended��\n"));
		return 1;
	}

	return 0;
}

//*������gen_pkg_init
//*���ܣ����ʼ���������ʼ��
//*��������
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
int gen_pkg_init()
{
	group = SM2_Init();
	if (group == NULL)
	{
		printf("SM2_Init Failed!\n");
		goto end;
	}

	eckey = EC_KEY_new();
	if (eckey == NULL)
	{
		printf("EC_KEY_new Failed!\n");
		goto end;
	}

	if (EC_KEY_set_group(eckey, group) == 0)
	{
		printf("EC_KEY_set_group Failed!\n");
		goto end;
	}

	return 0;

end:
	return 1;
}

//*������request_dev_cert
//*���ܣ�����csr�����豸֤��
//*������CsrLen		csr����
//		 Csr		csr
//		 Resp		֤��
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
unsigned int request_dev_cert(unsigned int IN CsrLen,unsigned char* IN Csr,dcc_cert_resp* OUT Resp)
{
	unsigned int ucRet = 0;
	CString tempmsg;

	if (!Csr || !Resp)
		return SENC_ERROR_PARAMETER_ERROR;

	dcc_init("http://10.10.40.132:8004/SenseDeviceInitService.asmx", 2, 30);
	ucRet = dcc_request_cert(CsrLen, Csr, Resp);
	if (ucRet != DCC_ERR_OK)
		return 1;

	return 0;
}

//*������gen_pkg_for_device
//*���ܣ��齨��ʼ�������
//*������ChipInitReq		��ʼ�������
//		 chip_init_cmd	��ʼ�������
//*����ֵ���ɹ�����0��ʧ�ܷ���1
//*���ڣ�2018/12/19  by ZhangTao
int gen_pkg_for_device(_In_ ChipInitRequest ChipInitReq, _Out_ ChipInitCommand *chip_init_cmd)
{
	/*
	1.	ʹ�ð忨�豸֤����֤������е�ǩ�� ֤����ǩ��
	2.	�������ݽṹ���幹��CHIP_INIT_CMD_INNER���ݰ���ʹ�ù���Ա���еļ��ܻ�˽Կǩ������ǩ����䵽���ݰ���ǩ���ֶΣ�SM3withSM2��
	3.	�������һ���Ự��Կ��IV+KEY����ʹ�ð忨�豸֤����ܻỰ��Կ(SM2)
	4.	ʹ�ûỰ��Կ����CHIP_INIT_CMD_INNER���ݰ�(SM4_CBC)
	5.	�������ݽṹ���幹��CHIP_INIT_CMD���ݰ�
	*/
	int ret = -1;
	FILE *fp = NULL;
	int msgl = 0;							//��Ϣ����
	unsigned char session_key[48] = { 0 }; //�Ự��Կ

	//���ʼ���������ʼ��
	ret = gen_pkg_init();
	if (ret)
	{
		AfxMessageBox(_T("���ʼ���������ʼ��ʧ�ܣ�\n"));
		return 1;
	}
	//1.�忨�豸֤����֤������е�ǩ��
	msgl = sizeof(ChipInitReq)-sizeof(ChipInitReq.Signaute);
	ret = sm2Verify(Pub, SM2_PUBKEY_LEN+1, &ChipInitReq, msgl, ChipInitReq.Signaute);
	if (ret){
		AfxMessageBox(_T("sm2��ǩʧ�ܣ�\n"));
		return 1;
	}

	//2.�������ݽṹ���幹��CHIP_INIT_CMD_INNER���ݰ���ʹ�ù���Ա���еļ��ܻ�˽Կǩ������ǩ����䵽���ݰ���ǩ���ֶΣ�SM3withSM2��
	// 2.1 CHIP_INIT_CMD_INNER���
	ChipInitCommandInner chip_init_cmd_inner;
	memset(&chip_init_cmd_inner, 0, sizeof(chip_init_cmd_inner));
	memcpy(chip_init_cmd_inner.chipId, ChipInitReq.chipId, CHIPID_LENGTH);	//�忨ID
	memcpy(chip_init_cmd_inner.Kseed, _seed, sizeof(_seed));				//Kseed
	memcpy(chip_init_cmd_inner.CryptorPri, jmjpri, sizeof(jmjpri));			//���ܻ�˽Կ   �Զ���д����˽Կ
	chip_init_cmd_inner.Flag = ALGID_SM2_PRI;								//��Կ���͡��㷨����Կ��SM2��
	chip_init_cmd_inner.bits = PRIKEY_BITS_256;

	// 2.2 ���ܻ�˽Կǩ��CHIP_INIT_CMD_INNER��
	msgl = sizeof(chip_init_cmd_inner)-sizeof(chip_init_cmd_inner.Signaute);
	ret = sm2SignMsg(jmjpri, SM2_PRIKEY_LEN, jmjpub, SM2_PUBKEY_LEN + 1, &chip_init_cmd_inner, msgl, chip_init_cmd_inner.Signaute);
	if (ret){
		AfxMessageBox(_T("SM2ǩ��ʧ��\n"));
		return 1;
	}

	//3.ʹ�ð忨�豸֤����ܻỰ��Կ(SM2)
	memcpy(session_key, sm4_iv, 16);
	memcpy(session_key + 16, sm4_key, 16);
	ret = sm2EncMsg(Pub, SM2_PUBKEY_LEN + 1, session_key, sizeof(session_key), chip_init_cmd->sessionKeyCipher);
	if (ret)
	{
		AfxMessageBox(_T("SM2����ʧ��\n"));
		goto ERR_OUT;
	}

	//4.ʹ�ûỰ��Կ����CHIP_INIT_CMD_INNER���ݰ�(SM4_CBC)
	int src_len = sizeof(chip_init_cmd_inner)+8;	//sm4_cbc����Ҫ����16�ı�����CHIP_INIT_CMD_INNER���Ȳ���16�ı�������8�ֽ�
	unsigned char *srcd = new unsigned char[src_len];
	memset(srcd, 0, src_len);
	memcpy(srcd, &chip_init_cmd_inner, sizeof(chip_init_cmd_inner));
	unsigned char sms4_cbc_ret[512] = { 0 };

	sm4_context ctx;
	sm4_setkey_enc(&ctx, sm4_key);
	sm4_crypt_cbc(&ctx, SM4_ENCRYPT, src_len, sm4_iv, srcd, sms4_cbc_ret);

	memcpy(chip_init_cmd->cmdCipher, sms4_cbc_ret, src_len);
	chip_init_cmd->cmdCipherLen = src_len;
	delete srcd;

	//5.ʹ�ð忨�������ݽṹ���幹��CHIP_INIT_CMD���ݰ�
	chip_init_cmd->Version = ChipInitReq.Version;
	chip_init_cmd->Flag = ALGID_SM2_PUB;
	chip_init_cmd->sessionKeyFlag = SM4_CBC;
	chip_init_cmd->bits = PUBKEY_BITS_256;
	chip_init_cmd->sessionKeyBits = SESSIONKEY_BITS_128;

	return 0;
ERR_OUT:
	if (eckey)
		EC_KEY_free(eckey);
	if (group)
		SM2_Cleanup(group);
	return 1;
}


DWORD WINAPI ProductionThread(LPVOID lpData)
{
	SencPT_Dlg *pThis = static_cast<SencPT_Dlg*>(lpData);
	HWND hwnd = pThis->GetSafeHwnd();
	CString tempmsg;
	int flag;
	unsigned char data1[64] = { 0 };
	unsigned char data2[64] = { 0 };
	unsigned char tdata[2048] = { 0 };
	unsigned char TestSend[256] = { 0 };
	unsigned char TestRcv[256] = { 0 };
	unsigned char TestDec[256] = { 0 };
	unsigned char TestBlock[256] = { 0 };
	unsigned char csr[2048] = { 0 };
	unsigned int recvlen;
	unsigned char devcert[2048] = { 0 };
	unsigned char devcacert[2048] = { 0 };
	unsigned char rootcert[2048] = { 0 };
	unsigned int devcertlen;
	unsigned int devcacertlen;
	unsigned int rootcertlen;
	unsigned int csrlen;
	dcc_cert_resp resp = {0};
	SENCryptCardList *dList;
	HANDLE dHandle;
	int trigger=pThis->tardev%16;
	//select the target dev if necessary
	trigger=0;
	FILE *fp = NULL;

	LPWSTR Fwver=new wchar_t[10];
	LPWSTR Hwver=new wchar_t[10];
 
	CTime cctime=CTime::GetCurrentTime();

	// 	SENC_NewDevList(&dList);
	dList=&pThis->gDevList;

	flag = SENC_GetDevList(dList);
	if(dList->DevNums == 0){
		tempmsg.Format(_T("δ���ּ��ܿ��豸\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		delete Fwver;
		delete Hwver;
		return 0xffff;
	}

	tempmsg.Format(_T("������ʼ\r\n"));
	pThis->PostStart(tempmsg);

	flag = SENC_Open(dList->devs[trigger], &dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.Format(_T("�����豸ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		delete Fwver;
		delete Hwver; 
		return flag;
	}

	pThis->mPrgsCtr.SetPos(0);

	do{
#if 1
#pragma region ��������	

		pThis->productCount++;
		flag = 0;

		//����ID ���������ڡ�ʱ�䡢�忨�������
		data1[0]=(cctime.GetYear()/1000)<<4|((cctime.GetYear()/100)%10);//ǧλ����data1[0]��4λ����λ����data1[0]��4λ
		data1[1]=((cctime.GetYear()/10)%10)<<4|(cctime.GetYear()%10);//ʮλ����data1[1]��4λ����λ����data1[1]��4λ
		data1[2]=(cctime.GetMonth()/10)<<4|(cctime.GetMonth()%10);
		data1[3]=(cctime.GetDay()/10)<<4|(cctime.GetDay()%10);
		data1[4]=(rand()*cctime.GetMinute())%0xff;
		data1[5]=(rand()*cctime.GetSecond())%0xff;
		data1[6]=pThis->productCount>>8&0xff;
		data1[7]=pThis->productCount&0xff;
		flag = SENC_Product_SetID(dHandle, data1, CHIPID_LENGTH);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("���ü��ܿ�IDʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//���ð汾��
		GetPrivateProfileString(_T("Version"),_T("Fwversion"),_T("00000000"),Fwver,10,(LPCTSTR)pThis->iniUrl);
		GetPrivateProfileString(_T("Version"),_T("Hwversion"),_T("00000000"),Hwver,10,(LPCTSTR)pThis->iniUrl);

		if(Fwver==_T("00000000")||Hwver==_T("00000000")){
			tempmsg.Format(_T("��ȡ�汾��Ϣʧ�ܣ�config.ini��ʧ���𻵣�\r\n"));
			flag=0xffff;
			break;
		}

		tempmsg=Fwver;
		memcpy(tdata,tempmsg.GetBuffer(),16);//���ַ�ת��ͨ�ַ�
		for(int i=0;i<8;i++){
			data1[i]=tdata[2*i];//���
		}

		tempmsg=Hwver;
		memcpy(tdata,tempmsg.GetBuffer(),16);
		for(int i=0;i<8;i++){
			data2[i]=tdata[2*i];
		}

		flag = SENC_Product_SetVersion(dHandle,data2,8,data1,8);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("���ü��ܿ��汾ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		
		//����flash��Կ
		flag = SENC_Product_GenerateFlashKey(dHandle);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("���ɼ��ܿ�flash��Կʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		
		//����D&H����
		unsigned char g = 0x07;
		unsigned char p[4] = {0x3d,0x13,0xee,0xa5};

		flag = SENC_Product_SetDHAttributes(dHandle,p,4,&g,1);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("����DH������Կʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//�����忨�豸��Կ��
		flag = SENC_Product_SM2KeyGenerate(dHandle, 2, 1);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("���ɰ忨�豸��Կ��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//�����豸֤��CSR
		flag = SENC_Product_RequestCSR(dHandle, &csrlen, csr);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("��ȡCSRʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		//��¼�豸֤��CSR  �����齣�����豸֤��
		fp = fopen(JMBK_CERT_CSR_PATH, "wb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("�豸֤��CSR�ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		int ret = fwrite(csr, sizeof(char), csrlen, fp);
		fclose(fp);

#if 0 //�������� ����CSR�����豸֤��
		//ʹ��CSR�����豸֤��
		flag = request_dev_cert(csrlen, csr, &resp);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�����豸֤��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		fp = fopen(JMBK_CERT_PATH, "wb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("�豸֤���ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		int ret = fwrite(resp.cert, sizeof(char), resp.cert_len, fp);
		fclose(fp);
		memset(csr, 0, sizeof(csr));
		csrlen = 0;

		//�����豸֤��
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_DEVICE, resp.cert_len, resp.cert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("	�����豸֤��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
#endif �������� ����CSR�����豸֤��

#if 1 //ģ������ ��ȡ���齣�ṩ���豸֤�鲢����
		//��ȡ�豸֤��
		fp = fopen(JMBK_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("�豸֤���ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		devcertlen = fread(devcert, sizeof(char), sizeof(devcert), fp);
		fclose(fp);
		//�����豸֤��
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_DEVICE, devcertlen, devcert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("	�����豸֤��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
#endif ģ������ ��ȡ���齣�ṩ���豸֤�鲢����

		//��ȡ�豸CA֤�飬�����豸CA֤��
		fp = fopen(DEVICECA_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("�豸CA�ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		devcacertlen = fread(devcacert, sizeof(char), sizeof(devcacert), fp);
		fclose(fp);
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_CA, devcacertlen, devcacert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("	�����豸CA֤��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		memset(devcacert, 0, sizeof(devcacert));
		devcacertlen = 0;

		//��ȡ��֤���ļ������ظ�֤��
		fp = fopen(ROOTCA_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("RootCA�ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		rootcertlen = fread(rootcert, sizeof(char), sizeof(rootcert), fp);
		fclose(fp);
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_ROOT, rootcertlen, rootcert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("����RootCA֤��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		memset(rootcert, 0, sizeof(rootcert));
		rootcertlen = 0;
#pragma endregion


#pragma region �������Թ���
		//��д����
		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}
		memset(TestBlock,0xff,256);
		flag = SENC_ProTest_WriteEp(dHandle,TestSend,256);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("д���ݲ���ʧ�ܣ�δ�˷��Σ���������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		flag = SENC_ProTest_Read(dHandle, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("�����ݲ���ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		if(memcmp(TestBlock, TestRcv, 256) != 0 ){
			tempmsg.Format(_T("��д����ʧ�ܣ�δ�˷��Σ������ݲ�һ�£�"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();

		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}
		flag = SENC_ProTest_WriteNp(dHandle,TestSend,256);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("д���ݲ���ʧ�ܣ��˷��Σ���������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		flag = SENC_ProTest_Read(dHandle, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("�����ݲ���ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		if(memcmp(TestSend, TestRcv, 256) != 0 ){
			tempmsg.Format(_T("��д����ʧ�ܣ��˷��Σ������ݲ�һ�£�"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();

		flag = SENC_Product_SetDefaultState(dHandle);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("����Ϊ����״̬ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
#pragma endregion

#endif
	}while(0);

#if 1
	SENC_Close(dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		delete Fwver;
		delete Hwver;
		return flag;
	}

	tempmsg.Format(_T("�������"));
	pThis->mPrgsCtr.SetPos(100);
	pThis->PostFin(tempmsg);

	pThis->tardev++;

	delete Fwver;
	delete Hwver;
#endif
	return 0;
}

DWORD WINAPI ProductionThreadInit(LPVOID lpData)
{
	SencPT_Dlg *pThis = static_cast<SencPT_Dlg*>(lpData);
	HWND hwnd = pThis->GetSafeHwnd();
	CString tempmsg;
	int flag;
	unsigned char devcert[2048] = { 0 };
	unsigned char devcacert[2048] = { 0 };
	unsigned char rootcert[2048] = { 0 };
	unsigned int devcertlen;
	unsigned int devcacertlen;
	unsigned int rootcertlen;
	FILE *fp = NULL;
	SENCryptCardList *dList;
	HANDLE dHandle;
	int trigger=pThis->tardev;
	trigger=0;
	CTime cctime=CTime::GetCurrentTime();
	dList=&pThis->gDevList;

	flag = SENC_GetDevList(dList);
	if(dList->DevNums == 0){
		tempmsg.Format(_T("δ���ּ��ܿ��豸\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return 0xffff;
	}

	tempmsg.Format(_T("��ʼ����ʼ\r\n"));
	pThis->PostLog(tempmsg);

	flag = SENC_Open(dList->devs[trigger], &dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.Format(_T("�����豸ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return flag;
	}


	do{
#pragma region �忨��ʼ������
#if 1
		//��ȡ�忨��ʼ��״̬
		unsigned char ECstate;
		unsigned int EClen;
		flag = SENC_DataProtector_GetChipInitStatus(dHandle, &ECstate, &EClen);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("��ȡ�忨��ʼ��״̬ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("��ȡ�忨��ʼ��״̬�ɹ�\r\n"));
		pThis->PostLog(tempmsg);

		//��ȡ�忨��ʼ�������
		ChipInitRequest ChipInitReq;
		fp = fopen(DEVICECA_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("�豸CA�ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		devcacertlen = fread(devcacert, sizeof(char), sizeof(devcacert), fp);
		fclose(fp);
		fp = fopen(JMBK_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("�豸֤���ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		devcertlen = fread(devcert, sizeof(char), sizeof(devcert), fp);
		fclose(fp);
		flag = SENC_DataProtector_GetInitReq(dHandle, &ChipInitReq, devcacert, &devcacertlen, devcert, &devcertlen, Pri, Pub);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("��ȡ��ʼ�������ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("��ȡ��ʼ��������ɹ�\r\n"));
		pThis->PostLog(tempmsg);


		//�齨��ʼ�������
		ChipInitCommand chip_init_cmd = { 0 };
		flag = gen_pkg_for_device(ChipInitReq, &chip_init_cmd);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�齨��ʼ�������ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("�齨��ʼ��������ɹ�\r\n"));
		pThis->PostLog(tempmsg);

		//�忨ִ�г�ʼ��
		unsigned char mock_key_cert[2048] = { 0 };
		int mock_key_len = 0;
		fp = fopen(JMJ_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("���ܻ�֤���ļ���ʧ�ܣ�\n"));
			exit(0);
		}
		mock_key_len = fread(mock_key_cert, 1, 2048, fp);
		flag = SENC_DataProtector_ChipInit(dHandle, chip_init_cmd, devcacert, devcacertlen, mock_key_cert, mock_key_len);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�忨ִ�г�ʼ��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("�忨ִ�г�ʼ���ɹ�\r\n"));
		pThis->PostLog(tempmsg);

		//�Ӱ忨��ȡ��֤����Ա�����ݰ�
		AuthAdminKey pkg = { 0 };
		flag = SENC_DataProtector_GetAuthPackage(dHandle, &pkg);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�Ӱ忨��ȡ��֤����Ա�����ݰ�ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("�Ӱ忨��ȡ��֤����Ա�����ݰ��ɹ�\r\n"));
		pThis->PostLog(tempmsg);

		//��֤���ݰ�
		unsigned char sm3buf[64] = { 0 };
		memcpy(sm3buf, _seed, 32);
		memcpy(sm3buf + 32, _seed1, 32);
		sm3_ex(sm3buf, 64, kenc);
		memcpy(sm3buf, _seed, 32);
		memcpy(sm3buf + 32, _seed2, 32);
		sm3_ex(sm3buf, 64, kmac);

		unsigned char sm4_out[128] = { 0 };
		sm4_context ctx;
		sm4_setkey_dec(&ctx, kenc);
		sm4_crypt_ecb(&ctx, SM4_DECRYPT, pkg.cipherLen, pkg.cipher, sm4_out);

		AuthAdminKeyInner* auth = (AuthAdminKeyInner *)sm4_out;
		unsigned char sm3_out[32] = { 0 };
		sm3_hmac(kmac, 32, auth->rand, 32, sm3_out);
		if (memcmp(auth->Mac, sm3_out, 32))
		{
			tempmsg.Format(_T("��֤��֤����Ա�����ݰ�ʧ��\r\n"));
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("��֤��֤����Ա�����ݰ��ɹ�\r\n"));
		pThis->PostLog(tempmsg);
#endif
#pragma endregion	
	}while(0);

	SENC_Close(dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return flag;
	}

	tempmsg.Format(_T("��ʼ�����"));
	pThis->mPrgsCtr.SetPos(100);
	pThis->PostLog(tempmsg);

	return 0;
}

DWORD WINAPI FlashSweeperThread(LPVOID lpData)
{
	SencPT_Dlg *pThis = static_cast<SencPT_Dlg*>(lpData);
	HWND hwnd = pThis->GetSafeHwnd();
	CString tempmsg;
	int flag;
	SENCHANDLE devhandle;
	SENCryptCardList *list;
	pThis->PostLog(L"Sweeping\r\n");	 

	list=&pThis->gDevList;

	flag = SENC_GetDevList(list);	 
	if(SENC_SUCCESS != flag)
	{
		tempmsg.Format(_T("get listʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return flag;
	}

	for(int i=0;i<(int)list->DevNums;i++){  //�ѷ��ֵ������豸������
		flag = SENC_Open(list->devs[i],&devhandle);
		if(SENC_SUCCESS != flag)
		{
			tempmsg.Format(_T("openʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			tempmsg.MakeUpper();
			pThis->PostErr(tempmsg);

			return flag;
		}

		flag = SENC_ProTest_FlashSweep(devhandle);
		if(SENC_SUCCESS != flag)
		{
			tempmsg.Format(_T("erase flash failed��������Ϊ��0x%.8x\r\n"), flag);
			tempmsg.MakeUpper();
			pThis->PostErr(tempmsg);

			return flag;
		}

		SENC_Close(devhandle);
		if(flag != SENC_SUCCESS)
		{
			tempmsg.Format(_T("�ر�ʧ��! 0x%.8x\r\n"),flag);
			pThis->PostErr(tempmsg);
			return flag;
		}
	}

	tempmsg.Format(_T("Sweept Successfully \r\n"));
	pThis->PostLog(tempmsg);
	// 	pThis->PostFin(tempmsg);

	return 0;

}

DWORD WINAPI GetListThread(LPVOID lpData)
{
	SencPT_Dlg *pThis = static_cast<SencPT_Dlg*>(lpData);
	HWND hwnd = pThis->GetSafeHwnd();
	CString tempmsg;
	int flag;
	pThis->PostLog(L"Getting List.\r\n");	 

	flag = SENC_GetDevList(&pThis->gDevList);	 
	if(SENC_SUCCESS != flag)
	{
		tempmsg.Format(_T("get listʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return flag;
	}

	tempmsg.Format(_T("Get List Successfully \r\n"));
	pThis->PostLog(tempmsg);
	// 	pThis->PostFin(tempmsg);

	return 0;

}


void SencPT_Dlg::OnBnClickedButtonProduction()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(TRUE);
	UpdateData(FALSE);
	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ProductionThread,this,0,NULL);
	if(hThread)
	{
		// 		CloseHandle(gHandle);
		CloseHandle(hThread);
	}

	WaitForSingleObject(hThread, 1000);
	return;
}

void SencPT_Dlg::OnBnClickedButtonInit()
{
	UpdateData(TRUE);
	UpdateData(FALSE);
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProductionThreadInit, this, 0, NULL);
	if (hThread)
	{
		CloseHandle(hThread);
	}

	WaitForSingleObject(hThread, 1000);
	return;
}

void SencPT_Dlg::OnBnClickedButtonFlashErase()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)FlashSweeperThread,this,0,NULL);
	if(hThread)
	{
		CloseHandle(hThread);
	}

	WaitForSingleObject(hThread, 1000);
	return;
}

void SencPT_Dlg::OnBnClickedButtonGetList()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)GetListThread,this,0,NULL);
	if(hThread)
	{
		// 		CloseHandle(gHandle);
		CloseHandle(hThread);
	}

	WaitForSingleObject(hThread, 1000);
	return;
}


