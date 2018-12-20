// SencPT_Dlg.cpp : 实现文件
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

#define	JMBK_CERT_PATH			"./证书/mock-card.cer"		//加密板卡设备证书
#define	JMBK_CERT_CSR_PATH		"./证书/devcertcsr"			//加密板卡设备CSR
#define	DEVICECA_CERT_PATH		"./证书/st.device.ca.cer"	//设备CA证书
#define	ROOTCA_CERT_PATH		"./证书/st.root.ca.cer"		//根证书

#define	JMJ_CERT_PATH			"./证书/st.device.cer"		//加密机设备证书
#define	JMJ_PRIKEY_PATH			"./证书/st.device.pri"		//加密机私钥

#define DEFAULT_SM2_SIGN_USER_ID			"1234567812345678"
#define DEFAULT_SM2_SIGN_USER_ID_LEN		16
#define SM3_DIGEST_LENGTH					32

#define RTC_TIME_PIN_CODE					"\x00\x11\x22\x33\x44\x55\x66\x77"
#define RTC_TIME_PIN_CODE_LEN				8
// IMPLEMENT_DYNAMIC(SencPT_Dlg, CDialogEx)

#define SM2_PUBKEY_LEN						64						//SM2公钥长度
#define SM2_PRIKEY_LEN						32						//SM2私钥长度

//自定义写死数据
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


// SencPT_Dlg 消息处理程序
BOOL SencPT_Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	// TODO: 在此添加额外的初始化代码
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

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE

}

void SencPT_Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{

	CDialogEx::OnSysCommand(nID, lParam);
}

void SencPT_Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
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
	}	// TODO:  如果默认的不是所需画笔，则返回另一个画笔
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
		tempmsg = tTime.Format(_T("%Y年%m月%d日 %H:%M:%S  发生错误："));
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

#define SEED_CODE_LEN              (32) //种子码长度
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

//sm2签名编解码使用
const UINT8 TAG_CLASS_CONTEXT = 0xA0;
const UINT8 TAG_INTEGER = 0x02;
const UINT8 TAG_BIT_STRING = 0x03;
const UINT8 TAG_OCTET_STRING = 0x04;
const UINT8 TAG_OID = 0x06;
const UINT8 TAG_SEQUENCE = 0x30;

//*函数：eccDerEncodeSignature
//*功能：sm2签名Der编码
//*参数：无
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
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

//*函数：eccDerDecodeSignature
//*功能：sm2签名Der解码
//*参数：无
//*日期：2018/12/19  by ZhangTao
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

//*函数：sm2SignMsg
//*功能：sm2签名
//*参数：prikey		私钥
//		 prikeylen	私钥长度
//		 pubkey		公钥
//		 pubkeylen	公钥长度
//		 msg		消息明文
//		 msglen		消息明文长度
//		 sig		签名	 
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
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

	//公钥计算摘要
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
		AfxMessageBox(_T("SM2_digest Failed！\n"));
		return 1;
	}

	//私钥签名
	dersiglen = 256;
	ret = SM2_sign(1, digest, sizeof(digest), dersig, &dersiglen, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_sign Failed！\n"));
		return 1;
	}

	ret = eccDerDecodeSignature(dersig, dersiglen, sig, 64);

	//ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	//if (ret != 1)
	//{
	//	AfxMessageBox(_T("SM2_verify Failed！\n"));
	//	return 1;
	//}

	return 0;
}

//*函数：sm2Verify
//*功能：sm2验签
//*参数：pubkey		公钥
//		 pubkeylen	公钥长度
//		 msg		消息明文
//		 msglen		消息明文长度
//		 sig		签名	 
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
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

	//公钥byte数组转hex字符串
	bn2hex(pubkey, pubkeylen, pkey);
	//公钥hex字符串转EC_POINT				group是全局变量EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//通过EC_POINT设置EC_KEY的公钥          eckey是全局变量EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey);

	//计算明文摘要
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
		AfxMessageBox(_T("SM2_digest Failed！\n"));
		return 1;
	}
	//sm2签名der编码，验签接口用的是der编码后的签名
	dersiglen = sizeof(dersig);
	eccDerEncodeSignature(sig, 64, dersig, (UINT16*)&dersiglen);
	//验签，返回1成功，返回0失败,第一个参数为类型
	ret = SM2_verify(1, digest, digestlen, dersig, dersiglen, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_verify Failed！\n"));
		return 1;
	}
	return 0;
}

//*函数：sm2EncMsg
//*功能：sm加密
//*参数：pubkey		公钥
//		 pubkeylen	公钥长度
//		 msg		消息（明文）
//		 msglen		消息（明文）长度
//		 cipher		密文
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
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

	//公钥byte数组转hex字符串
	bn2hex(pubkey, pubkeylen, pkey);
	//公钥hex字符串转EC_POINT				group是全局变量EC_GROUP
	ecPubkey = EC_POINT_hex2point(group, pkey, ecPubkey, NULL);
	//通过EC_POINT设置EC_KEY的公钥          eckey是全局变量EC_KEY
	EC_KEY_set_public_key(eckey, ecPubkey);

	//SM2加密
	ret = SM2_encrypt_with_recommended(cipher, &cipherlen, (unsigned char*)msg, msglen, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_encrypt_with_recommended！\n"));
		return 1;
	}

	return 0;
}

//*函数：gen_pkg_init
//*功能：组初始化命令包初始化
//*参数：无
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
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

//*函数：request_dev_cert
//*功能：根据csr请求设备证书
//*参数：CsrLen		csr长度
//		 Csr		csr
//		 Resp		证书
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
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

//*函数：gen_pkg_for_device
//*功能：组建初始化命令包
//*参数：ChipInitReq		初始化请求包
//		 chip_init_cmd	初始化命令包
//*返回值：成功返回0，失败返回1
//*日期：2018/12/19  by ZhangTao
int gen_pkg_for_device(_In_ ChipInitRequest ChipInitReq, _Out_ ChipInitCommand *chip_init_cmd)
{
	/*
	1.	使用板卡设备证书验证请求包中的签名 证书验签名
	2.	按照数据结构定义构造CHIP_INIT_CMD_INNER数据包，使用管理员锁中的加密机私钥签名并把签名填充到数据包的签名字段（SM3withSM2）
	3.	随机生成一个会话密钥（IV+KEY），使用板卡设备证书加密会话密钥(SM2)
	4.	使用会话密钥加密CHIP_INIT_CMD_INNER数据包(SM4_CBC)
	5.	按照数据结构定义构造CHIP_INIT_CMD数据包
	*/
	int ret = -1;
	FILE *fp = NULL;
	int msgl = 0;							//消息长度
	unsigned char session_key[48] = { 0 }; //会话密钥

	//组初始化命令包初始化
	ret = gen_pkg_init();
	if (ret)
	{
		AfxMessageBox(_T("组初始化命令包初始化失败！\n"));
		return 1;
	}
	//1.板卡设备证书验证请求包中的签名
	msgl = sizeof(ChipInitReq)-sizeof(ChipInitReq.Signaute);
	ret = sm2Verify(Pub, SM2_PUBKEY_LEN+1, &ChipInitReq, msgl, ChipInitReq.Signaute);
	if (ret){
		AfxMessageBox(_T("sm2验签失败！\n"));
		return 1;
	}

	//2.按照数据结构定义构造CHIP_INIT_CMD_INNER数据包，使用管理员锁中的加密机私钥签名并把签名填充到数据包的签名字段（SM3withSM2）
	// 2.1 CHIP_INIT_CMD_INNER组包
	ChipInitCommandInner chip_init_cmd_inner;
	memset(&chip_init_cmd_inner, 0, sizeof(chip_init_cmd_inner));
	memcpy(chip_init_cmd_inner.chipId, ChipInitReq.chipId, CHIPID_LENGTH);	//板卡ID
	memcpy(chip_init_cmd_inner.Kseed, _seed, sizeof(_seed));				//Kseed
	memcpy(chip_init_cmd_inner.CryptorPri, jmjpri, sizeof(jmjpri));			//加密机私钥   自定义写死公私钥
	chip_init_cmd_inner.Flag = ALGID_SM2_PRI;								//密钥类型、算法（公钥，SM2）
	chip_init_cmd_inner.bits = PRIKEY_BITS_256;

	// 2.2 加密机私钥签名CHIP_INIT_CMD_INNER包
	msgl = sizeof(chip_init_cmd_inner)-sizeof(chip_init_cmd_inner.Signaute);
	ret = sm2SignMsg(jmjpri, SM2_PRIKEY_LEN, jmjpub, SM2_PUBKEY_LEN + 1, &chip_init_cmd_inner, msgl, chip_init_cmd_inner.Signaute);
	if (ret){
		AfxMessageBox(_T("SM2签名失败\n"));
		return 1;
	}

	//3.使用板卡设备证书加密会话密钥(SM2)
	memcpy(session_key, sm4_iv, 16);
	memcpy(session_key + 16, sm4_key, 16);
	ret = sm2EncMsg(Pub, SM2_PUBKEY_LEN + 1, session_key, sizeof(session_key), chip_init_cmd->sessionKeyCipher);
	if (ret)
	{
		AfxMessageBox(_T("SM2加密失败\n"));
		goto ERR_OUT;
	}

	//4.使用会话密钥加密CHIP_INIT_CMD_INNER数据包(SM4_CBC)
	int src_len = sizeof(chip_init_cmd_inner)+8;	//sm4_cbc加密要求是16的倍数，CHIP_INIT_CMD_INNER长度不是16的倍数，差8字节
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

	//5.使用板卡按照数据结构定义构造CHIP_INIT_CMD数据包
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
		tempmsg.Format(_T("未发现加密卡设备\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		delete Fwver;
		delete Hwver;
		return 0xffff;
	}

	tempmsg.Format(_T("生产开始\r\n"));
	pThis->PostStart(tempmsg);

	flag = SENC_Open(dList->devs[trigger], &dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.Format(_T("开启设备失败，错误码为：0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		delete Fwver;
		delete Hwver; 
		return flag;
	}

	pThis->mPrgsCtr.SetPos(0);

	do{
#if 1
#pragma region 生产过程	

		pThis->productCount++;
		flag = 0;

		//设置ID ，根据日期、时间、板卡生产编号
		data1[0]=(cctime.GetYear()/1000)<<4|((cctime.GetYear()/100)%10);//千位放在data1[0]高4位，百位放在data1[0]低4位
		data1[1]=((cctime.GetYear()/10)%10)<<4|(cctime.GetYear()%10);//十位放在data1[1]高4位，个位放在data1[1]低4位
		data1[2]=(cctime.GetMonth()/10)<<4|(cctime.GetMonth()%10);
		data1[3]=(cctime.GetDay()/10)<<4|(cctime.GetDay()%10);
		data1[4]=(rand()*cctime.GetMinute())%0xff;
		data1[5]=(rand()*cctime.GetSecond())%0xff;
		data1[6]=pThis->productCount>>8&0xff;
		data1[7]=pThis->productCount&0xff;
		flag = SENC_Product_SetID(dHandle, data1, CHIPID_LENGTH);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("设置加密卡ID失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//设置版本号
		GetPrivateProfileString(_T("Version"),_T("Fwversion"),_T("00000000"),Fwver,10,(LPCTSTR)pThis->iniUrl);
		GetPrivateProfileString(_T("Version"),_T("Hwversion"),_T("00000000"),Hwver,10,(LPCTSTR)pThis->iniUrl);

		if(Fwver==_T("00000000")||Hwver==_T("00000000")){
			tempmsg.Format(_T("获取版本信息失败，config.ini丢失或损坏！\r\n"));
			flag=0xffff;
			break;
		}

		tempmsg=Fwver;
		memcpy(tdata,tempmsg.GetBuffer(),16);//宽字符转普通字符
		for(int i=0;i<8;i++){
			data1[i]=tdata[2*i];//大端
		}

		tempmsg=Hwver;
		memcpy(tdata,tempmsg.GetBuffer(),16);
		for(int i=0;i<8;i++){
			data2[i]=tdata[2*i];
		}

		flag = SENC_Product_SetVersion(dHandle,data2,8,data1,8);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("设置加密卡版本失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		
		//生成flash秘钥
		flag = SENC_Product_GenerateFlashKey(dHandle);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("生成加密卡flash秘钥失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		
		//设置D&H参数
		unsigned char g = 0x07;
		unsigned char p[4] = {0x3d,0x13,0xee,0xa5};

		flag = SENC_Product_SetDHAttributes(dHandle,p,4,&g,1);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("设置DH交换秘钥失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//生产板卡设备密钥对
		flag = SENC_Product_SM2KeyGenerate(dHandle, 2, 1);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("生成板卡设备密钥对失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//申请设备证书CSR
		flag = SENC_Product_RequestCSR(dHandle, &csrlen, csr);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("获取CSR失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		//记录设备证书CSR  找钟灵剑生成设备证书
		fp = fopen(JMBK_CERT_CSR_PATH, "wb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("设备证书CSR文件打开失败！\n"));
			exit(0);
		}
		int ret = fwrite(csr, sizeof(char), csrlen, fp);
		fclose(fp);

#if 0 //正常流程 根据CSR申请设备证书
		//使用CSR申请设备证书
		flag = request_dev_cert(csrlen, csr, &resp);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("申请设备证书失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		fp = fopen(JMBK_CERT_PATH, "wb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("设备证书文件打开失败！\n"));
			exit(0);
		}
		int ret = fwrite(resp.cert, sizeof(char), resp.cert_len, fp);
		fclose(fp);
		memset(csr, 0, sizeof(csr));
		csrlen = 0;

		//下载设备证书
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_DEVICE, resp.cert_len, resp.cert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("	下载设备证书失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
#endif 正常流程 根据CSR申请设备证书

#if 1 //模拟流程 读取钟灵剑提供的设备证书并下载
		//读取设备证书
		fp = fopen(JMBK_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("设备证书文件打开失败！\n"));
			exit(0);
		}
		devcertlen = fread(devcert, sizeof(char), sizeof(devcert), fp);
		fclose(fp);
		//下载设备证书
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_DEVICE, devcertlen, devcert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("	下载设备证书失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
#endif 模拟流程 读取钟灵剑提供的设备证书并下载

		//读取设备CA证书，下载设备CA证书
		fp = fopen(DEVICECA_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("设备CA文件打开失败！\n"));
			exit(0);
		}
		devcacertlen = fread(devcacert, sizeof(char), sizeof(devcacert), fp);
		fclose(fp);
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_CA, devcacertlen, devcacert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("	下载设备CA证书失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		memset(devcacert, 0, sizeof(devcacert));
		devcacertlen = 0;

		//读取根证书文件，下载根证书
		fp = fopen(ROOTCA_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("RootCA文件打开失败！\n"));
			exit(0);
		}
		rootcertlen = fread(rootcert, sizeof(char), sizeof(rootcert), fp);
		fclose(fp);
		flag = SENC_Product_DownLoadCert(dHandle, SENC_CERT_ROOT, rootcertlen, rootcert);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("下载RootCA证书失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		memset(rootcert, 0, sizeof(rootcert));
		rootcertlen = 0;
#pragma endregion


#pragma region 生产测试过程
		//读写测试
		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}
		memset(TestBlock,0xff,256);
		flag = SENC_ProTest_WriteEp(dHandle,TestSend,256);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("写数据测试失败（未退防拔），错误码为：0x%.8x\r\n"), flag);
			break;
		}
		flag = SENC_ProTest_Read(dHandle, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("读数据测试失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		if(memcmp(TestBlock, TestRcv, 256) != 0 ){
			tempmsg.Format(_T("读写测试失败（未退防拔），数据不一致！"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();

		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}
		flag = SENC_ProTest_WriteNp(dHandle,TestSend,256);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("写数据测试失败（退防拔），错误码为：0x%.8x\r\n"), flag);
			break;
		}
		flag = SENC_ProTest_Read(dHandle, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("读数据测试失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		if(memcmp(TestSend, TestRcv, 256) != 0 ){
			tempmsg.Format(_T("读写测试失败（退防拔），数据不一致！"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();

		flag = SENC_Product_SetDefaultState(dHandle);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("设置为出厂状态失败，错误码为：0x%.8x\r\n"), flag);
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

	tempmsg.Format(_T("生产完成"));
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
		tempmsg.Format(_T("未发现加密卡设备\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return 0xffff;
	}

	tempmsg.Format(_T("初始化开始\r\n"));
	pThis->PostLog(tempmsg);

	flag = SENC_Open(dList->devs[trigger], &dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.Format(_T("开启设备失败，错误码为：0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return flag;
	}


	do{
#pragma region 板卡初始化过程
#if 1
		//获取板卡初始化状态
		unsigned char ECstate;
		unsigned int EClen;
		flag = SENC_DataProtector_GetChipInitStatus(dHandle, &ECstate, &EClen);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("获取板卡初始化状态失败，错误码为：0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("获取板卡初始化状态成功\r\n"));
		pThis->PostLog(tempmsg);

		//获取板卡初始化请求包
		ChipInitRequest ChipInitReq;
		fp = fopen(DEVICECA_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("设备CA文件打开失败！\n"));
			exit(0);
		}
		devcacertlen = fread(devcacert, sizeof(char), sizeof(devcacert), fp);
		fclose(fp);
		fp = fopen(JMBK_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("设备证书文件打开失败！\n"));
			exit(0);
		}
		devcertlen = fread(devcert, sizeof(char), sizeof(devcert), fp);
		fclose(fp);
		flag = SENC_DataProtector_GetInitReq(dHandle, &ChipInitReq, devcacert, &devcacertlen, devcert, &devcertlen, Pri, Pub);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("获取初始化请求包失败，错误码为：0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("获取初始化请求包成功\r\n"));
		pThis->PostLog(tempmsg);


		//组建初始化命令包
		ChipInitCommand chip_init_cmd = { 0 };
		flag = gen_pkg_for_device(ChipInitReq, &chip_init_cmd);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("组建初始化命令包失败，错误码为：0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("组建初始化命令包成功\r\n"));
		pThis->PostLog(tempmsg);

		//板卡执行初始化
		unsigned char mock_key_cert[2048] = { 0 };
		int mock_key_len = 0;
		fp = fopen(JMJ_CERT_PATH, "rb");
		if (fp == NULL)
		{
			AfxMessageBox(_T("加密机证书文件打开失败！\n"));
			exit(0);
		}
		mock_key_len = fread(mock_key_cert, 1, 2048, fp);
		flag = SENC_DataProtector_ChipInit(dHandle, chip_init_cmd, devcacert, devcacertlen, mock_key_cert, mock_key_len);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("板卡执行初始化失败，错误码为：0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("板卡执行初始化成功\r\n"));
		pThis->PostLog(tempmsg);

		//从板卡获取认证管理员锁数据包
		AuthAdminKey pkg = { 0 };
		flag = SENC_DataProtector_GetAuthPackage(dHandle, &pkg);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("从板卡获取认证管理员锁数据包失败，错误码为：0x%.8x\r\n"), flag);
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("从板卡获取认证管理员锁数据包成功\r\n"));
		pThis->PostLog(tempmsg);

		//验证数据包
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
			tempmsg.Format(_T("验证认证管理员锁数据包失败\r\n"));
			pThis->PostErr(tempmsg);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		tempmsg.Format(_T("验证认证管理员锁数据包成功\r\n"));
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

	tempmsg.Format(_T("初始化完成"));
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
		tempmsg.Format(_T("get list失败，错误码为：0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		return flag;
	}

	for(int i=0;i<(int)list->DevNums;i++){  //把发现的所有设备都擦除
		flag = SENC_Open(list->devs[i],&devhandle);
		if(SENC_SUCCESS != flag)
		{
			tempmsg.Format(_T("open失败，错误码为：0x%.8x\r\n"), flag);
			tempmsg.MakeUpper();
			pThis->PostErr(tempmsg);

			return flag;
		}

		flag = SENC_ProTest_FlashSweep(devhandle);
		if(SENC_SUCCESS != flag)
		{
			tempmsg.Format(_T("erase flash failed，错误码为：0x%.8x\r\n"), flag);
			tempmsg.MakeUpper();
			pThis->PostErr(tempmsg);

			return flag;
		}

		SENC_Close(devhandle);
		if(flag != SENC_SUCCESS)
		{
			tempmsg.Format(_T("关闭失败! 0x%.8x\r\n"),flag);
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
		tempmsg.Format(_T("get list失败，错误码为：0x%.8x\r\n"), flag);
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
	// TODO: 在此添加控件通知处理程序代码
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
	// TODO: 在此添加控件通知处理程序代码
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
	// TODO: 在此添加控件通知处理程序代码
	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)GetListThread,this,0,NULL);
	if(hThread)
	{
		// 		CloseHandle(gHandle);
		CloseHandle(hThread);
	}

	WaitForSingleObject(hThread, 1000);
	return;
}


