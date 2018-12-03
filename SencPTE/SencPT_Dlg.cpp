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

#define		JMBK_CERT_PATH			"./证书/st.device.cer"		//加密板卡设备证书
#define		JMBK_CERT_CSR_PATH		"./证书/devcertcsr"			//加密板卡设备CSR
#define		DEVICECA_CERT_PATH		"./证书/st.device.ca.cer"	//设备CA证书
#define		ROOTCA_CERT_PATH		"./证书/st.root.ca.cer"		//根证书

#define		JMJ_CERT_PATH			"./证书/st.device.cer"		//加密板卡设备证书
#define		JMJ_PRIKEY_PATH			"./证书/st.device.pri"		//加密机私钥

#define DEFAULT_SM2_SIGN_USER_ID			"1234567812345678"
#define DEFAULT_SM2_SIGN_USER_ID_LEN		16
#define SM3_DIGEST_LENGTH					32
// IMPLEMENT_DYNAMIC(SencPT_Dlg, CDialogEx)

//自定义写死数据
static unsigned char innerkey1[] =
"\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44"
"\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44";
const static unsigned char _seed[] =
"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";
const static unsigned char _seed1[] = { 
	0xA4, 0x8F, 0xC8, 0x6D, 0x02, 0x22, 0xEF, 0x9E, 0xB2, 0x6F, 0x2B, 0xB9, 0x44, 0x4F, 0xBC, 0xCD, 
	0x89, 0xA4, 0x32, 0x7E, 0x97, 0xDE, 0xCF, 0xAE, 0x4A, 0x83, 0xF5, 0x65, 0x37, 0x98, 0x6E, 0xA6 };
const static unsigned char _seed2[] = { 
	0x56, 0xD5, 0x5C, 0x3B, 0x40, 0x72, 0x7B, 0xC1, 0x58, 0xE2, 0xF5, 0x5E, 0x6D, 0x85, 0x5B, 0xBB, 
	0xA1, 0x8E, 0x27, 0xAA, 0x4C, 0xC7, 0xDB, 0x0A, 0xB3, 0xB7, 0xA0, 0x3D, 0x9E, 0xD8, 0x5C, 0x15 };

static unsigned char aes_key[] = {
	0x54, 0x5D, 0xBA, 0x6B, 0xE5, 0xA2, 0x45, 0x40, 0xA1, 0xCE, 0x99, 0xC6, 0xFB, 0xED, 0xCC, 0xE8 };
static unsigned char aes_iv[16] = {
	0x3E, 0x62, 0xBB, 0x39, 0x1F, 0xDF, 0xDB, 0x2F, 0x33, 0x08, 0x71, 0x04, 0xEF, 0xC9, 0xB5, 0xF7};
static unsigned char aes_iv2[16] = {
	0x3E, 0x62, 0xBB, 0x39, 0x1F, 0xDF, 0xDB, 0x2F, 0x33, 0x08, 0x71, 0x04, 0xEF, 0xC9, 0xB5, 0xF7};
static unsigned char aes_data[376] = {
	0x20, 0x18, 0x11, 0x29, 0x20, 0xad, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 
	0x78, 0x6e, 0xea, 0xed, 0x28, 0xd1, 0x60, 0x24, 0xd4, 0xa7, 0xb6, 0xb6, 0x75, 0xc8, 0x64, 0x54, 
	0x10, 0xac, 0x30, 0xf9, 0xc8, 0x10, 0x27, 0x86, 0xef, 0x60, 0x16, 0x6c, 0xdb, 0xab, 0xff, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x48, 0xc1, 0x24, 0x9f, 0x50, 0xae, 0x11, 0xd6, 
	0xb0, 0x9f, 0x68, 0x18, 0xc1, 0xfd, 0x14, 0x17, 0xa2, 0x28, 0xa1, 0x07, 0x84, 0x90, 0xe3, 0x5e, 
	0xbf, 0x42, 0x96, 0x87, 0xa5, 0xce, 0x22, 0x44, 0x3c, 0x58, 0x14, 0x89, 0x62, 0x02, 0xa5, 0x31, 
	0xe5, 0x71, 0xd0, 0x65, 0xd4, 0x12, 0x79, 0x35, 0x01, 0x90, 0x47, 0xe3, 0x7d, 0xc1, 0x8a, 0x0f, 
	0x46, 0xa8, 0x11, 0x26, 0x7b, 0x04, 0x09, 0xca };

static unsigned char jmjpri[] =
{ 0x78, 0x6E, 0xEA, 0xED, 0x28, 0xD1, 0x60, 0x24, 0xD4, 0xA7, 0xB6, 
  0xB6, 0x75, 0xC8, 0x64, 0x54, 0x10, 0xAC, 0x30, 0xF9, 0xC8, 0x10, 
  0x27, 0x86, 0xEF, 0x60, 0x16, 0x6C, 0xDB, 0xAB, 0xFF, 0x00 };

unsigned char Pri[33] = { 0 };
unsigned char Pub[66] = { 0x04 };

unsigned char kenc[32] = { 0 };
unsigned char kmac[32] = { 0 };


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
	ON_BN_CLICKED(IDC_BUTTON_NONE_RAND, &SencPT_Dlg::OnBnClickedButtonNoneRand)
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
	mPrgsCtr.SetStep(10);
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

#define ALGO_AES 0x00000001
#define ALGO_RSA_PUB 0x00010100
#define ALGO_RSA_PRI 0x00020100
#define ALGO_SM2_PUB 0x00010200
#define ALGO_SM2_PRI 0x00020200

#define SIGN_KEY_SHA256_RSA2048        1
#define ENC_KEY_RSA2048				   2
#define AES_128_ECB                    3
#define AES_256_EBC                    4
#define AES_256_CBC                    5
#define SM4_CBC						   6

#define SEED_CODE_LEN              (32) //种子码长度
#define KSEED_LEN_32               (32)
#define AES_BLOCK_SIZE             (16)
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
/*单个字符转十六进制字符串，长度增大2被*/
static void Char2Hex(UCHAR IN ch, char* OUT szHex)
{
	UCHAR byte[2];
	byte[0] = ch / 16;//高4位 范围0x0-0xf
	byte[1] = ch % 16;//低4位 范围0x0-0xf
	for (int i = 0; i < 2; i++)
	{
		if (byte[i] >= 0 && byte[i] <= 9)
			szHex[i] = '0' + byte[i];
		else
			szHex[i] = 'a' + byte[i] - 10;//大端，先处理高位，再处理低位
	}
	szHex[2] = 0;
}

//////////////////////////////////////////////////////
//函数：CharStr2HexStr
//功能：普通字符串转16进制字符串
//参数： src:普通字符串
//		 slen:普通字符串长度
//       dst:16进制字符串
//返回值：无返回值
//作者：zhangtao
//日期：2018-11-21
//////////////////////////////////////////////////////
void CharStr2HexStr(const UCHAR* IN src, int IN srcl, char* OUT dest)
{
	char szHex[3];
	for (int i = 0; i < srcl; i++)
	{
		Char2Hex(src[i], szHex);//一个字节16进制数据转换成两个字符
		strcat(dest, szHex);//附加，szHex以0结束
	}
}

const UINT8 TAG_CLASS_CONTEXT = 0xA0;
const UINT8 TAG_INTEGER = 0x02;
const UINT8 TAG_BIT_STRING = 0x03;
const UINT8 TAG_OCTET_STRING = 0x04;
const UINT8 TAG_OID = 0x06;
const UINT8 TAG_SEQUENCE = 0x30;

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


//请求设备证书
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

	return SENC_SUCCESS;
}

//组建初始化命令包
int gen_pkg_for_device(_In_ ChipInitRequest ChipInitReq, _Out_ ChipInitCommand *chip_init_cmd)
{
	/*
	1.	使用板卡设备证书验证请求包中的签名 证书验签名   暂时省去
	2.	使用内部密钥1解密Kseed（SM4_ECB）
	3.	按照数据结构定义构造CHIP_INIT_CMD_INNER数据包，使用管理员锁中的加密机私钥签名并把签名填充到数据包的签名字段（SM3withSM2）
	4.	随机生成一个会话密钥（IV+KEY），使用板卡设备证书加密会话密钥(SM2)
	5.	使用会话密钥加密CHIP_INIT_CMD_INNER数据包(SM4_CBC)
	6.	按照数据结构定义构造CHIP_INIT_CMD数据包
	7.	返回命令包
	*/
	int ret = -1;
	FILE *fp = NULL;
	EC_GROUP *group = NULL;
	EC_KEY	*eckey = NULL;
	BIGNUM *prikey = NULL;
	EC_POINT *pubkey = NULL;
	EC_GROUP *group2 = NULL;
	EC_KEY	*eckey2 = NULL;
	BIGNUM *prikey2 = NULL;
	EC_POINT *pubkey2 = NULL;

	int msgl = 0;					//计算摘要源数据长度
	unsigned char digest[32] = { 0 };		//摘要
	unsigned int digest_len = 32;			//摘要长度
	unsigned char sign_ret[512] = { 0 };	//签名
	unsigned int sign_len = sizeof(sign_ret);//签名长度

	char Jmbkbuf[2048] = { 0 };			   //加密板卡设备证书
	int buflen = 0;						   //缓存长度
	char Bjmbkpub[65] = { 0 };			   //Binary加密板卡公钥
	char HexJmbkPub[131] = { 0 };		   //Hex加密板卡公钥

	unsigned char session_key[48] = { 0 }; //会话密钥
	size_t sesKeyCipherL = 256;			   //会话密钥长度
	memcpy(session_key, aes_iv, 16);
	memcpy(session_key + 16, aes_key, 16);

	group = SM2_Init();
	if (group == NULL)
	{
		AfxMessageBox(_T("SM2_Init Failed!\n"));
		goto ERR_OUT;
	}

	eckey = EC_KEY_new();
	if (eckey == NULL)
	{
		AfxMessageBox(_T("EC_KEY_new Failed!\n"));
		goto ERR_OUT;
	}

	if (EC_KEY_set_group(eckey, group) == 0)
	{
		AfxMessageBox(_T("EC_KEY_set_group Failed!\n"));
		goto ERR_OUT;
	}
	group2 = SM2_Init();
	if (group2 == NULL)
	{
		AfxMessageBox(_T("SM2_Init Failed!\n"));
		goto ERR_OUT;
	}
	eckey2 = EC_KEY_new();
	if (eckey2 == NULL)
	{
		AfxMessageBox(_T("EC_KEY_new Failed!\n"));
		goto ERR_OUT;
	}
	if (EC_KEY_set_group(eckey2, group2) == 0)
	{
		AfxMessageBox(_T("EC_KEY_set_group Failed!\n"));
		goto ERR_OUT;
	}
	//2.使用内部密钥1解密Kseed（SM4_ECB）

	//2.按照数据结构定义构造CHIP_INIT_CMD_INNER数据包，使用管理员锁中的加密机私钥签名并把签名填充到数据包的签名字段（SM3withSM2）
	// 2.1 CHIP_INIT_CMD_INNER组包
	ChipInitCommandInner chip_init_cmd_inner;
	memset(&chip_init_cmd_inner, 0, sizeof(chip_init_cmd_inner));
	//板卡ID
	memcpy(chip_init_cmd_inner.chipId, ChipInitReq.chipId, CHIPID_LENGTH);
	//Kseed
	memcpy(chip_init_cmd_inner.Kseed, _seed, sizeof(_seed));
	//加密机私钥   自定义写死公私钥
	memcpy(chip_init_cmd_inner.CryptorPri, jmjpri, sizeof(jmjpri));
	//密钥类型、算法（公钥，SM2）
	chip_init_cmd_inner.Flag = ALGO_SM2_PRI;
	chip_init_cmd_inner.bits = PRIKEY_BITS_256;

	// 2.2 使用加密机私钥签名
#if 0  根据加密机设备证书和私钥文件获取加密机公钥和私钥
	FILE* fp = fopen(JMJ_PRIKEY_PATH, "rb");
	if (fp == NULL)
		goto ERR_OUT;
	eckey = d2i_ECPrivateKey_fp(fp, &eckey);
	fclose(fp);

	char buf1[2048] = { 0 };
	char Bjmjpub[65] = { 0 };
	char HexJmjPub[131] = { 0 };
	FILE *fp1 = fopen(JMJ_CERT_PATH, "rb");
	if (fp1 == NULL)
		goto ERR_OUT;
	int len1 = fread(buf1, 1, sizeof(buf1), fp1);
	fclose(fp1);
	char *p1 = buf1;
	X509 *x1 = X509_new();
	d2i_X509(&x1, (const unsigned char **)&p1, len1);
	memcpy(Bjmjpub, x1->cert_info->key->public_key->data, x1->cert_info->key->public_key->length);
	CharStr2HexStr((unsigned char*)Bjmjpub, 65, HexJmjPub);
	X509_free(x1);
	pubkey = EC_POINT_hex2point(group, HexJmjPub, pubkey, NULL);
	EC_KEY_set_public_key(eckey, pubkey);
#endif 


#if 1 自定义写死加密机公私钥
	BN_hex2bn(&prikey, "786EEAED28D16024D4A7B6B675C8645410AC30F9C8102786EF60166CDBABFF00");
	EC_KEY_set_private_key(eckey, prikey);
	pubkey = EC_POINT_hex2point(group, "0409FB73A17DE326052270E6DBD8B79AD328894692F439BA718F8D24C9F447E26B7D465DDD8413743A36CFEC16BD425DB62E013A37C18B8B45F80EE95213B89EDC", pubkey, NULL);
	EC_KEY_set_public_key(eckey, pubkey);
#endif

#if 1
	msgl = sizeof(ChipInitCommandInner)-sizeof(chip_init_cmd_inner.Signaute);
	ret = SM2_digest(
		(unsigned char*)DEFAULT_SM2_SIGN_USER_ID,
		DEFAULT_SM2_SIGN_USER_ID_LEN,
		&chip_init_cmd_inner,
		msgl,
		digest,
		&digest_len,
		eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_digest Failed:0x%08X\n", ret));
		return 1;
	}

	ret = SM2_sign(1, digest, digest_len, (unsigned char*)sign_ret, (unsigned int*)&sign_len, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_sign Failed!"));
		goto ERR_OUT;
	}
	unsigned char out1[64] = { 0 };

	ret = eccDerDecodeSignature(sign_ret, sign_len, out1, 64);

#endif

#if 0
	BN_hex2bn(&prikey, "5316CABD1C86123443B97781C28A2F62CA7887E0344F3C15320A0E9212CA86C9");
	EC_KEY_set_private_key(eckey, prikey);
	pubkey = EC_POINT_hex2point(group, "04F6E8CA88185C155EB766E68BD1EEBACBFDB93349B0A2B5DCE1DCCBA0AD3EE22DD62EEB365DFD474C9533638DE93D5201EF9296F24AB0D9B52DC2A30195903729", pubkey, NULL);
	EC_KEY_set_public_key(eckey, pubkey);

	digest_len = sizeof(digest);
	ret = SM2_digest(
		(unsigned char*)DEFAULT_SM2_SIGN_USER_ID,
		DEFAULT_SM2_SIGN_USER_ID_LEN,
		msg,
		sizeof(msg),
		digest,
		&digest_len,
		eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_digest Failed:0x%08X\n", ret));
		return 1;
	}

	sign_len = 256;
	ret = SM2_sign(1, digest, sizeof(digest), sign_ret, &sign_len, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_sign Failed!"));
		return 1;
	}
	ret = SM2_verify(1, digest, digest_len, (unsigned char*)sign_ret, sign_len, eckey);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_sign Failed!"));
		goto ERR_OUT;
	}

	unsigned char out1[64] = { 0 };

	ret = eccDerDecodeSignature(sign_ret, sign_len, out1, 64);
#endif

	// 2.3把签名填充到数据包的签名字段
	memcpy(chip_init_cmd_inner.Signaute, out1, 64);

	//3.随机生成一个会话密钥（IV+KEY），使用板卡设备证书加密会话密钥(SM2)
	//3.1从加密板卡设备证书中获取公钥
#if 0
	fp = fopen(JMBK_CERT_PATH, "rb");
	if (fp == NULL)
		goto ERR_OUT;
	buflen = fread(Jmbkbuf, 1, sizeof(Jmbkbuf), fp);
	fclose(fp);
	char *p = Jmbkbuf;
	X509 *x = X509_new();
	d2i_X509(&x, (const unsigned char **)&p, buflen);
	memcpy(Bjmbkpub, x->cert_info->key->public_key->data, x->cert_info->key->public_key->length);
	CharStr2HexStr((unsigned char*)Bjmbkpub, 65, HexJmbkPub);
	X509_free(x);
#endif


	CharStr2HexStr((unsigned char*)Pub, 65, HexJmbkPub);
	pubkey2 = EC_POINT_hex2point(group2, HexJmbkPub, pubkey2, NULL);
	EC_KEY_set_public_key(eckey2, pubkey2);

	//3.2用加密板卡公钥加密会话秘钥
	ret = SM2_encrypt_with_recommended(chip_init_cmd->sessionKeyCipher, &sesKeyCipherL, session_key, sizeof(session_key), eckey2);
	if (ret != 1)
	{
		AfxMessageBox(_T("SM2_encrypt_with_recommended Failed!"));
		goto ERR_OUT;
	}

	//4.使用会话密钥加密CHIP_INIT_CMD_INNER数据包(SM4_CBC)
	int src_len = sizeof(chip_init_cmd_inner)+8;
	unsigned char sms4_cbc_ret[1024] = { 0 };

	unsigned char *srcd = new unsigned char[src_len];
	memset(srcd, 0, src_len);
	memcpy(srcd, &chip_init_cmd_inner, sizeof(chip_init_cmd_inner));
	sm4_context ctx;
	sm4_setkey_enc(&ctx, aes_key);
	sm4_crypt_cbc(&ctx, SM4_ENCRYPT, src_len, aes_iv, srcd, sms4_cbc_ret);

	memcpy(chip_init_cmd->cmdCipher, sms4_cbc_ret, src_len);
	chip_init_cmd->cmdCipherLen = src_len;
	delete srcd;

	//5.使用板卡按照数据结构定义构造CHIP_INIT_CMD数据包
	chip_init_cmd->Version = ChipInitReq.Version;
	chip_init_cmd->Flag = ALGO_SM2_PUB;
	chip_init_cmd->sessionKeyFlag = SM4_CBC;
	chip_init_cmd->bits = PUBKEY_BITS_256;
	chip_init_cmd->sessionKeyBits = SESSIONKEY_BITS_128;

	return 0;
ERR_OUT:
	if (eckey)
		EC_KEY_free(eckey);
	if (group)
		SM2_Cleanup(group);
	if (eckey2)
		EC_KEY_free(eckey2);
	if (group2)
		SM2_Cleanup(group2);
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
	unsigned char devcert[2048] = { 0 };
	unsigned char devcacert[2048] = { 0 };
	unsigned char rootcert[2048] = { 0 };
	unsigned char csr[2048] = { 0 };
	unsigned int recvlen;
	unsigned int devcertlen;
	unsigned int devcacertlen;
	unsigned int rootcertlen;
	unsigned int csrlen;
	dcc_cert_resp resp = {0};
	SENCryptCardList *dList;
	HANDLE dHandle;
	AES_KEY aeskey;
	int trigger=pThis->tardev%16;
	//select the target dev if necessary
	trigger=0;
	FILE *fp = NULL;

	LPWSTR Fwver=new wchar_t[10];
	LPWSTR Hwver=new wchar_t[10];
 
	CTime cctime=CTime::GetCurrentTime();

#if 1
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
		tempmsg.Format(_T("开启设备s失败，错误码为：0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		delete Fwver;
		delete Hwver; 
		return flag;
	}
#endif

	pThis->mPrgsCtr.SetPos(0);

	do{
#if 1
#pragma region 生产过程	
		//设置ID ，根据日期、时间、板卡生产编号
		// 	data1[0]=(cctime.GetYear())>>8&0xff;
		// 	data1[1]=(cctime.GetYear())&0xff;
		// 	data1[2]=cctime.GetMonth()&0xff;
		// 	data1[3]=cctime.GetDay()&0xff;
		// 	data1[4]=(rand()*cctime.GetMinute())%0xff;
		// 	data1[5]=(rand()*cctime.GetSecond())%0xff;
		// 	data1[6]=pThis->productCount>>8&0xff;
		// 	data1[7]=pThis->productCount&0xff;
		data1[0]=(cctime.GetYear()/1000)<<4|((cctime.GetYear()/100)%10);//千位放在data1[0]高4位，百位放在data1[0]低4位
		data1[1]=((cctime.GetYear()/10)%10)<<4|(cctime.GetYear()%10);//十位放在data1[1]高4位，个位放在data1[1]低4位
		data1[2]=(cctime.GetMonth()/10)<<4|(cctime.GetMonth()%10);
		data1[3]=(cctime.GetDay()/10)<<4|(cctime.GetDay()%10);
		data1[4]=(rand()*cctime.GetMinute())%0xff;
		data1[5]=(rand()*cctime.GetSecond())%0xff;
		data1[6]=pThis->productCount>>8&0xff;
		data1[7]=pThis->productCount&0xff;

		pThis->productCount++;

		flag = 0;
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
			printf("设备证书CSR文件打开失败！\n");
			exit(0);
		}
		int ret = fwrite(csr, sizeof(char), csrlen, fp);
		fclose(fp);

#if 0 正常流程 根据CSR申请设备证书
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
			printf("设备证书文件打开失败！\n");
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

#if 1 模拟流程 读取钟灵剑提供的设备证书并下载
		//读取设备证书
		fp = fopen(JMBK_CERT_PATH, "rb");
		if (fp == NULL)
		{
			printf("设备证书文件打开失败！\n");
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
			printf("设备CA文件打开失败！\n");
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
			printf("RootCA文件打开失败！\n");
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


		/*memset(tdata,0,sizeof(tdata));


		unsigned int bits=2048;

		memcpy(tdata, &bits, 4);
		memcpy(tdata+4, rsakey->n->d,SENC_RSA_PARAMETER_LEN*2);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*2, rsakey->e->d,4);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*4, rsakey->d->d,SENC_RSA_PARAMETER_LEN*2);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*6, rsakey->p->d,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*7, rsakey->q->d,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*8, rsakey->dmp1->d,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*9, rsakey->dmq1->d,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*10, rsakey->iqmp->d,SENC_RSA_PARAMETER_LEN);

		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}
		TestSend[0] = 0x00;
		TestSend[255] = 0x00;

		int t=0;
		
		while(t++<500){
			flag = SENC_ProTest_RsaSignature(dHandle, tdata,1412, TestSend,256, TestRcv,&recvlen);
			if(flag != SENC_SUCCESS){
				tempmsg.Format(_T("RSA签名测试失败，错误码为：0x%.8x\r\n"), flag);
				break;
			}	


			RSA_public_decrypt(256, TestRcv, TestDec, rsakey, RSA_NO_PADDING);
			if(memcmp(TestSend, TestDec, 256) != 0){
				tempmsg.Format(_T("RSA签名测试失败，解密数据不一致！"));
				flag=0xffff;
				break;
			}
		}
		if(flag!=SENC_SUCCESS)
			break;

		pThis->mPrgsCtr.StepIt();

		//aes
		for(int i = 0 ; i < 32 ; i++ ){
			tdata[i] = rand() & 0xff;
		}
		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}

		flag = SENC_ProTest_AesEncrypt(dHandle, tdata,32, TestSend,256, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("AES加密测试失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

		AES_set_decrypt_key(tdata, 256, &aeskey);
		for(int i = 0 ; i < 256 ; i += 16 ){
			AES_ecb_encrypt(TestRcv+i, TestDec+i, &aeskey, AES_DECRYPT);
		}
		if(memcmp(TestSend, TestDec, 256) != 0){
			tempmsg.Format(_T("AES加密测试失败，解密数据不一致！"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();
		*/

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

#pragma region 板卡初始化过程
#if 1
		//获取板卡初始化状态
		unsigned char ECstate;
		unsigned int EClen;
		flag = SENC_DataProtector_GetChipInitStatus(dHandle, &ECstate, &EClen);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("获取板卡初始化状态失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

		//获取板卡初始化请求包
		ChipInitRequest ChipInitReq;
		flag = SENC_DataProtector_GetInitReq(dHandle, &ChipInitReq, devcacert, &devcacertlen, devcert, &devcertlen,Pri,Pub+1);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("获取初始化请求包失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
#endif
		//组建初始化命令包
		ChipInitCommand chip_init_cmd = {0};
		flag = gen_pkg_for_device(ChipInitReq, &chip_init_cmd);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("组建初始化命令包失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
#if 1
		//板卡执行初始化
		unsigned char mock_key_cert[2048] = { 0 };
		int mock_key_len = 0;
		fp = fopen(JMJ_CERT_PATH, "rb");
		mock_key_len = fread(mock_key_cert, 1, 2048, fp);
		flag = SENC_DataProtector_ChipInit(dHandle, chip_init_cmd, devcacert, devcacertlen, mock_key_cert,mock_key_len);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("板卡执行初始化失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

		//从板卡获取认证管理员锁数据包
		AuthAdminKey pkg = { 0 };
		flag = SENC_DataProtector_GetAuthPackage(dHandle, &pkg);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("从板卡获取认证管理员锁数据包失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

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
			printf("Failed!");
#pragma endregion
#endif
	}while(0);

#if 0
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

DWORD WINAPI ProductionThreadNoneRand(LPVOID lpData)
{
	SencPT_Dlg *pThis = static_cast<SencPT_Dlg*>(lpData);
	HWND hwnd = pThis->GetSafeHwnd();
	CString tempmsg;
	int flag;
	unsigned char data1[64];
	unsigned char data2[64];
	unsigned char tdata[2048];
	unsigned char TestSend[256];
	unsigned char TestRcv[256];
	unsigned char TestDec[256];
	unsigned char TestBlock[256];
	unsigned int recvlen;
	SENCryptCardList *dList;
	HANDLE dHandle;
	// 	RSA *rsakey;
	AES_KEY aeskey;
	int trigger=pThis->tardev;
	//select the target dev if necessary
	trigger=0;

	LPWSTR Fwver=new wchar_t[10];
	LPWSTR Hwver=new wchar_t[10];

	CTime cctime=CTime::GetCurrentTime();


	// 	SENC_NewDevList(&dList);
	dList=&pThis->gDevList;

	// 	rsakey = RSA_new();
	// 	rsakey = RSA_generate_key(2048,0x10001,NULL,NULL);

	flag = SENC_GetDevList(dList);
	if(dList->DevNums == 0){
		tempmsg.Format(_T("未发现加密卡设备\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		// 		RSA_free(rsakey);
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
		// 		RSA_free(rsakey);
		delete Fwver;
		delete Hwver;
		return flag;
	}


	do{

		/**/

		pThis->mPrgsCtr.SetPos(0);
		//set ID
		// 	data1[0]=(cctime.GetYear())>>8&0xff;
		// 	data1[1]=(cctime.GetYear())&0xff;
		// 	data1[2]=cctime.GetMonth()&0xff;
		// 	data1[3]=cctime.GetDay()&0xff;
		// 	data1[4]=(rand()*cctime.GetMinute())%0xff;
		// 	data1[5]=(rand()*cctime.GetSecond())%0xff;
		// 	data1[6]=pThis->productCount>>8&0xff;
		// 	data1[7]=pThis->productCount&0xff;
		data1[0]=(cctime.GetYear()/1000)<<4|((cctime.GetYear()/100)%10);
		data1[1]=((cctime.GetYear()/10)%10)<<4|(cctime.GetYear()%10);
		data1[2]=(cctime.GetMonth()/10)<<4|(cctime.GetMonth()%10);
		data1[3]=(cctime.GetDay()/10)<<4|(cctime.GetDay()%10);
		data1[4]=(rand()*cctime.GetMinute())%0xff;
		data1[5]=(rand()*cctime.GetSecond())%0xff;
		data1[6]=pThis->productCount>>8&0xff;
		data1[7]=pThis->productCount&0xff;

		pThis->productCount++;

		flag = SENC_Product_SetID(dHandle,data1,8);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("设置加密卡ID失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

		pThis->mPrgsCtr.StepIt();
		//set version

		GetPrivateProfileString(_T("Version"),_T("Fwversion"),_T("00000000"),Fwver,10,(LPCTSTR)pThis->iniUrl);
		GetPrivateProfileString(_T("Version"),_T("Hwversion"),_T("00000000"),Hwver,10,(LPCTSTR)pThis->iniUrl);

		if(Fwver==_T("00000000")||Hwver==_T("00000000")){
			tempmsg.Format(_T("获取版本信息失败，config.ini丢失或损坏！\r\n"));
			flag=0xffff;
			break;
		}

		tempmsg=Fwver;

		memcpy(tdata,tempmsg.GetBuffer(),16);
		for(int i=0;i<8;i++){
			data1[i]=tdata[2*i];
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

		//generate flash key
		flag = SENC_Product_GenerateFlashKey(dHandle);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("生成加密卡flash秘钥失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//set d-h keys
		unsigned char g = 0x07;
		unsigned char p[4] = {0x3d,0x13,0xee,0xa5};

		flag = SENC_Product_SetDHAttributes(dHandle,p,4,&g,1);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("设置DH交换秘钥失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//production tests

		//aes
		for(int i = 0 ; i < 32 ; i++ ){
			tdata[i] = rand() & 0xff;
		}
		for(int i = 0 ; i < 256 ; i++ ){
			TestSend[i] = rand() & 0xff;
		}

		flag = SENC_ProTest_AesEncrypt(dHandle, tdata,32, TestSend,256, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("AES加密测试失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

		AES_set_decrypt_key(tdata, 256, &aeskey);
		for(int i = 0 ; i < 256 ; i += 16 ){
			AES_ecb_encrypt(TestRcv+i, TestDec+i, &aeskey, AES_DECRYPT);
		}
		if(memcmp(TestSend, TestDec, 256) != 0){
			tempmsg.Format(_T("AES加密测试失败，解密数据不一致！"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();


		//rsa
		FILE *fp;
		RsaData rsadata;
		fopen_s(&fp,"rsakey.data","rb");
		fread(rsadata.n,1,256,fp);
		fread(rsadata.e,1,256,fp);
		fread(rsadata.d,1,256,fp);
		fread(rsadata.p,1,128,fp);
		fread(rsadata.q,1,128,fp);
		fread(rsadata.dmp,1,128,fp);
		fread(rsadata.dmq,1,128,fp);
		fread(rsadata.iqmp,1,128,fp);
		fclose(fp);

		// 		memcpy(rsakey->n->d,rsadata.n,SENC_RSA_PARAMETER_LEN*2);
		// 		memcpy(rsakey->e->d,rsadata.e,SENC_RSA_PARAMETER_LEN*2);
		// 		memcpy(rsakey->d->d,rsadata.d,SENC_RSA_PARAMETER_LEN*2);
		// 		memcpy(rsakey->p->d,rsadata.p,SENC_RSA_PARAMETER_LEN);
		// 		memcpy(rsakey->q->d,rsadata.q,SENC_RSA_PARAMETER_LEN);
		// 		memcpy(rsakey->dmp1->d,rsadata.dmp,SENC_RSA_PARAMETER_LEN);
		// 		memcpy(rsakey->dmq1->d,rsadata.dmq,SENC_RSA_PARAMETER_LEN);
		// 		memcpy(rsakey->iqmp->d,rsadata.iqmp,SENC_RSA_PARAMETER_LEN);


		unsigned int bits=2048;

		memcpy(tdata, &bits, 4);
		memcpy(tdata+4, rsadata.n,SENC_RSA_PARAMETER_LEN*2);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*2, rsadata.e,SENC_RSA_PARAMETER_LEN*2);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*4, rsadata.d,SENC_RSA_PARAMETER_LEN*2);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*6, rsadata.p,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*7, rsadata.q,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*8, rsadata.dmp,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*9, rsadata.dmq,SENC_RSA_PARAMETER_LEN);
		memcpy(tdata+4+SENC_RSA_PARAMETER_LEN*10, rsadata.iqmp,SENC_RSA_PARAMETER_LEN);

		memset(TestSend,0x11,256);
		TestSend[0] = 0x00;
		TestSend[255] = 0x00;

		//while(1){
		flag = SENC_ProTest_RsaSignature(dHandle, tdata,1412, TestSend,256, TestRcv,&recvlen);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("RSA签名测试失败，错误码为：0x%.8x\r\n"), flag);
			break;
		}

		fopen_s(&fp,"Correct.data","rb");
		fread(TestDec,1,256,fp);
		fclose(fp);

		fopen_s(&fp,"datatest.data","wb");
		fwrite(TestRcv,1,256,fp);
		fclose(fp);

		if(memcmp(TestRcv, TestDec, 256) != 0){
			tempmsg.Format(_T("RSA签名测试失败，解密数据不一致！"));
			flag=0xffff;
			break;
		}


		pThis->mPrgsCtr.StepIt();

		//write&read
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


		/**/
	}while(0);

	SENC_Close(dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		// 		RSA_free(rsakey);
		delete Fwver;
		delete Hwver;
		return flag;
	}
	//close??
	tempmsg.Format(_T("生产完成"));
	pThis->mPrgsCtr.SetPos(100);
	pThis->PostFin(tempmsg);

	pThis->tardev++;

	delete Fwver;
	delete Hwver;

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


void SencPT_Dlg::OnBnClickedButtonFlashErase()
{
	// TODO: 在此添加控件通知处理程序代码
	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)FlashSweeperThread,this,0,NULL);
	if(hThread)
	{
		// 		CloseHandle(gHandle);
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


void SencPT_Dlg::OnBnClickedButtonNoneRand()
{
	UpdateData(TRUE);
	UpdateData(FALSE);
	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ProductionThreadNoneRand,this,0,NULL);
	if(hThread)
	{
		// 		CloseHandle(gHandle);
		CloseHandle(hThread);
	}

	WaitForSingleObject(hThread, 1000);
	return;
}
