// SencPT_Dlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "SencPT.h"
#include "SencPT_Dlg.h"
#include "afxdialogex.h"
#include <stdio.h>
#include "libsenc.h"
//#include <vld.h>
#include "openssl/rsa.h"
#include "openssl/aes.h"
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

#define		DEVICE_CERT_PATH		"./֤��/st.device.cer"
#define		DEVICECA_CERT_PATH		"./֤��/st.device.ca.cer"
#define		ROOTCA_CERT_PATH		"./֤��/st.root.ca.cer"
#define		DEVICE_CERT_CSR_PATH	"./֤��/devcertcsr"
#define		MACHINE_PRIKEY_PATH		"./֤��/st.device.pri"

// IMPLEMENT_DYNAMIC(SencPT_Dlg, CDialogEx)

//�Զ���д������
static unsigned char innerkey1[] =
"\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44"
"\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44";
static unsigned char _seed[] =
"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";
static unsigned char aes_key[] =
"\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
"\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22";
static unsigned char aes_iv[] =
"\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33";


typedef struct _RSA_PRIKEY_st
{
	unsigned int bits;
	unsigned char n[256];
	unsigned char e[256];
	unsigned char d[256];
	unsigned char p[128];
	unsigned char q[128];
	unsigned char dp[128];
	unsigned char dq[128];
	unsigned char qinv[128];
}RSA_PRIKEY;


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

#define WM_MSG_LOG (WM_USER + 1)
#define WM_MSG_ERROR (WM_USER + 2)
#define WM_MSG_FINISH (WM_USER + 3)
#define WM_MSG_START (WM_USER + 4)
#define WM_MSG_TRANSMIT (WM_USER + 5)
#define WM_MSG_CLRS (WM_USER + 6)
#define WM_MSG_FFFF (WM_USER + 7)


#define SENC_RSA_PARAMETER_LEN 128

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

#define SEED_CODE_LEN              (32) //�����볤��
#define KSEED_LEN_32               (32)
#define AES_BLOCK_SIZE             (16)
#define AES_KEY_LEN_32             (32)
#define KENC_KEY_LEN               AES_KEY_LEN_32
#define KMAC_KEY_LEN               (16)
#define H5_FIXED_HEAD_LEN          (12)
#define RANDOM_SIZE_32             (32)
#define H5_RSA_STD_HEAD_LEN        (12)

#define SESSIONKEY_BITS_384        (384)
#define PUBKEY_BITS_256            (256)
#define PUBKEY_BITS_512            (512)
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

//�����豸֤��
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

//�齨��ʼ�������
int gen_pkg_for_device(_In_ ChipInitRequest ChipInitReq, _Out_ ChipInitCommand *chip_init_cmd)
{
	/*
	1.	ʹ�ð忨�豸֤����֤������е�ǩ�� ֤����ǩ��   ��ʱʡȥ
	2.	ʹ���ڲ���Կ1����Kseed��SM4_ECB��
	3.	�������ݽṹ���幹��CHIP_INIT_CMD_INNER���ݰ���ʹ�ù���Ա���еļ��ܻ�˽Կǩ������ǩ����䵽���ݰ���ǩ���ֶΣ�SM3withSM2��
	4.	�������һ���Ự��Կ��IV+KEY����ʹ�ûỰ��Կ����CHIP_INIT_CMD_INNER���ݰ�(SM4_CBC)
	5.	ʹ�ð忨�豸֤����ܻỰ��Կ(SM2)
	6.	�������ݽṹ���幹��CHIP_INIT_CMD���ݰ�
	7.	���������
	*/
	int ret = -1;
	//2.ʹ���ڲ���Կ1����Kseed��SM4_ECB��

	//2.�������ݽṹ���幹��CHIP_INIT_CMD_INNER���ݰ���ʹ�ù���Ա���еļ��ܻ�˽Կǩ������ǩ����䵽���ݰ���ǩ���ֶΣ�SM3withSM2��
	// 2.1 CHIP_INIT_CMD_INNER���
	ChipInitCommandInner chip_init_cmd_inner;
	memset(&chip_init_cmd_inner, 0, sizeof(chip_init_cmd_inner));
	//chipId
	memcpy(chip_init_cmd_inner.chipId, ChipInitReq.chipId, CHIPID_LENGTH);
	//Kseed
	memcpy(chip_init_cmd_inner.Kseed, _seed, sizeof(_seed));
	//��Կ���͡��㷨����Կ��SM2��
	chip_init_cmd_inner.Flag = ALGO_SM2_PRI;
	chip_init_cmd_inner.bits = PRIKEY_BITS_256;
	// 2.2 ʹ�ü��ܻ�˽Կǩ��
	unsigned char sign_ret[512] = { 0 };
	unsigned int sign_len = sizeof(sign_ret);
	FILE *fp = fopen(MACHINE_PRIKEY_PATH, "rb");
	if (!fp)
	{
		goto ERR_OUT;
	}
	EC_KEY *k = d2i_ECPrivateKey_fp(fp, NULL);
	//i2d_EC_PUBKEY_fp(fp, k);
	if (!k)
	{
		goto ERR_OUT;
	}
	int data_len = sizeof(ChipInitCommandInner) - sizeof(chip_init_cmd_inner.Signaute);
	
	unsigned char digest[SM3_DIGEST_LENGTH];
	unsigned int digest_len = SM3_DIGEST_LENGTH;
	// ��������ժҪ
	ret = SM2_compute_message_digest(EVP_sm3(), EVP_sm3(), &chip_init_cmd_inner, data_len, digest, &digest_len, k);
	if (ret != 1)
	{
		goto ERR_OUT;
	}
	data_len = 128;
	ret = SM2_sign(NID_sm3, digest, digest_len, (unsigned char*)&chip_init_cmd_inner, (unsigned int*)&data_len, k);
	if (ret != 1)
	{
		goto ERR_OUT;
	}

	unsigned char src[10] = "abc";
	unsigned int srcl = strlen((char*)src);
	unsigned char digest[32] = { 0 };
	unsigned int digest_len = 32;
	unsigned char sign_ret[512] = { 0 };
	unsigned int sign_len = sizeof(sign_ret);
	sm3(src, srcl, digest);
	ret = SM2_sign(1, digest, sizeof(digest), (unsigned char*)sign_ret, (unsigned int*)&sign_len, eckey);
	if (ret != 1)
	{
		printf("SM2_sign Failed!");
		goto end;
	}
	ret = SM2_verify(1, digest, sizeof(digest), (unsigned char*)sign_ret, sign_len, eckey);
	if (ret != 1)
	{
		printf("SM2_verify Failed!\n");
		goto end;
	}

	// 2.3��ǩ����䵽���ݰ���ǩ���ֶ�
	//memcpy(chip_init_cmd_inner.Signaute, sign_ret, sign_len);

	//3.�������һ���Ự��Կ��IV+KEY����ʹ�ûỰ��Կ����CHIP_INIT_CMD_INNER���ݰ�(SM4_CBC)
	unsigned char sms4_cbc_ret[1024] = { 0 };
	int sms4_cbc_len = sizeof(sms4_cbc_ret);
	int src_len = sizeof(ChipInitCommandInner);
	int last_len = 0;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX_init(&ctx);
	cipher = EVP_sm4_cbc();
	
	EVP_EncryptInit_ex(&ctx, cipher, NULL, aes_key, aes_iv);
	EVP_EncryptUpdate(&ctx, sms4_cbc_ret, &sms4_cbc_len, (unsigned char*)&chip_init_cmd_inner, src_len);
	EVP_EncryptFinal_ex(&ctx, sms4_cbc_ret + sms4_cbc_len, &last_len);
	sms4_cbc_len += last_len;

	memcpy(&chip_init_cmd->cmdCipher, sms4_cbc_ret, sms4_cbc_len);
	chip_init_cmd->cmdCipherLen = sms4_cbc_len;


	//4.ʹ�ð忨�豸֤����ܻỰ��Կ(SM2)
	//���豸֤���л�ȡ��Կ
	fp = fopen(DEVICE_CERT_PATH, "rb");
	if (fp == NULL)
		goto ERR_OUT;
	
	k = d2i_EC_PUBKEY_fp(fp, NULL);
	if (!k)
	{
		goto ERR_OUT;
	}
	//i2d_EC_PUBKEY_fp(fp, k);
	fclose(fp);

	unsigned char session_key[48] = { 0 };	
	memcpy(session_key, aes_iv, 16);
	memcpy(session_key+16, aes_key, 32);

	size_t sesKeyCipherL = 0;
	//SM2_ENC_PARAMS sm2_enc_params;
	//SM2_ENC_PARAMS_init_with_recommended(&sm2_enc_params);
	//SM2_encrypt(&sm2_enc_params, chip_init_cmd->sessionKeyCipher, &sesKeyCipherL, session_key, sizeof(session_key), k);
	SM2_encrypt_with_recommended(chip_init_cmd->sessionKeyCipher, &sesKeyCipherL, session_key, sizeof(session_key), k);
	//EC_KEY_free(k);

	//5.ʹ�ð忨�������ݽṹ���幹��CHIP_INIT_CMD���ݰ�
	chip_init_cmd->Version = ChipInitReq.Version;
	chip_init_cmd->Flag = ALGO_SM2_PUB;
	chip_init_cmd->sessionKeyFlag = SM4_CBC;
	chip_init_cmd->bits = PUBKEY_BITS_512;
	chip_init_cmd->sessionKeyBits = SESSIONKEY_BITS_384;
	//memcpy(&chip_init_cmd.sessionKeyCipher, encryptedText, len);

	return 0;
ERR_OUT:
	EC_KEY_free(k);
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
	RSA *rsakey;
	AES_KEY aeskey;
	int trigger=pThis->tardev%16;
	//select the target dev if necessary
	trigger=0;
	FILE *fp = NULL;

	LPWSTR Fwver=new wchar_t[10];
	LPWSTR Hwver=new wchar_t[10];
 
	CTime cctime=CTime::GetCurrentTime();


	// 	SENC_NewDevList(&dList);
	dList=&pThis->gDevList;

	rsakey = RSA_new();
	rsakey = RSA_generate_key(2048,0x10001,NULL,NULL);
	flag = SENC_GetDevList(dList);
	if(dList->DevNums == 0){
		tempmsg.Format(_T("δ���ּ��ܿ��豸\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		RSA_free(rsakey);
		delete Fwver;
		delete Hwver;
		return 0xffff;
	}

	tempmsg.Format(_T("������ʼ\r\n"));
	pThis->PostStart(tempmsg);

	flag = SENC_Open(dList->devs[trigger], &dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.Format(_T("�����豸sʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		RSA_free(rsakey);
		delete Fwver;
		delete Hwver; 
		return flag;
	}


	do{
			

		pThis->mPrgsCtr.SetPos(0);
#pragma region ��������	
		//����ID ���������ڡ�ʱ�䡢�忨�������
		// 	data1[0]=(cctime.GetYear())>>8&0xff;
		// 	data1[1]=(cctime.GetYear())&0xff;
		// 	data1[2]=cctime.GetMonth()&0xff;
		// 	data1[3]=cctime.GetDay()&0xff;
		// 	data1[4]=(rand()*cctime.GetMinute())%0xff;
		// 	data1[5]=(rand()*cctime.GetSecond())%0xff;
		// 	data1[6]=pThis->productCount>>8&0xff;
		// 	data1[7]=pThis->productCount&0xff;
		data1[0]=(cctime.GetYear()/1000)<<4|((cctime.GetYear()/100)%10);//ǧλ����data1[0]��4λ����λ����data1[0]��4λ
		data1[1]=((cctime.GetYear()/10)%10)<<4|(cctime.GetYear()%10);//ʮλ����data1[1]��4λ����λ����data1[1]��4λ
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
		fp = fopen(DEVICE_CERT_CSR_PATH, "wb");
		if (fp == NULL)
		{
			printf("�豸֤��CSR�ļ���ʧ�ܣ�\n");
			exit(0);
		}
		int ret = fwrite(csr, sizeof(char), csrlen, fp);
		fclose(fp);

#if 0 �������� ����CSR�����豸֤��
		//ʹ��CSR�����豸֤��
		flag = request_dev_cert(csrlen, csr, &resp);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�����豸֤��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();
		fp = fopen(DEVICE_CERT_PATH, "wb");
		if (fp == NULL)
		{
			printf("�豸֤���ļ���ʧ�ܣ�\n");
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

#if 1 ģ������ ��ȡ���齣�ṩ���豸֤�鲢����
		//��ȡ�豸֤��
		fp = fopen(DEVICE_CERT_PATH, "rb");
		if (fp == NULL)
		{
			printf("�豸֤���ļ���ʧ�ܣ�\n");
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
			printf("�豸CA�ļ���ʧ�ܣ�\n");
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
			printf("RootCA�ļ���ʧ�ܣ�\n");
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
				tempmsg.Format(_T("RSAǩ������ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
				break;
			}	


			RSA_public_decrypt(256, TestRcv, TestDec, rsakey, RSA_NO_PADDING);
			if(memcmp(TestSend, TestDec, 256) != 0){
				tempmsg.Format(_T("RSAǩ������ʧ�ܣ��������ݲ�һ�£�"));
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
			tempmsg.Format(_T("AES���ܲ���ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		AES_set_decrypt_key(tdata, 256, &aeskey);
		for(int i = 0 ; i < 256 ; i += 16 ){
			AES_ecb_encrypt(TestRcv+i, TestDec+i, &aeskey, AES_DECRYPT);
		}
		if(memcmp(TestSend, TestDec, 256) != 0){
			tempmsg.Format(_T("AES���ܲ���ʧ�ܣ��������ݲ�һ�£�"));
			flag=0xffff;
			break;
		}
		pThis->mPrgsCtr.StepIt();
		*/

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

#pragma region �忨��ʼ������
		//��ȡ�忨��ʼ��״̬
		unsigned char ECstate;
		unsigned int EClen;
		flag = SENC_DataProtector_GetChipInitStatus(dHandle, &ECstate, &EClen);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("��ȡ�忨��ʼ��״̬ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		//��ȡ�忨��ʼ�������
		ChipInitRequest ChipInitReq;
		flag = SENC_DataProtector_GetInitReq(dHandle, &ChipInitReq, devcacert, &devcacertlen, devcert, &devcertlen);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("��ȡ��ʼ�������ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		//�齨��ʼ�������
		ChipInitCommand chip_init_cmd = {0};
		flag = gen_pkg_for_device(ChipInitReq, &chip_init_cmd);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�齨��ʼ�������ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		//�忨ִ�г�ʼ��
		unsigned char mock_key_cert[2048] = { 0 };
		int mock_key_len = 0;
		fp = fopen("./֤��/mock_key.cer", "rb");
		mock_key_len = fread(mock_key_cert, 1, 2048, fp);
		flag = SENC_DataProtector_ChipInit(dHandle, chip_init_cmd, devcacert, devcacertlen, mock_key_cert,mock_key_len);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�忨ִ�г�ʼ��ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		//�Ӱ忨��ȡ��֤����Ա�����ݰ�
		AuthAdminKey pkg = { 0 };
		flag = SENC_DataProtector_GetAuthPackage(dHandle, &pkg);
		if (flag != SENC_SUCCESS){
			tempmsg.Format(_T("�Ӱ忨��ȡ��֤����Ա�����ݰ�ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		//��֤���ݰ�
		unsigned char _seed1[] = { 0xA4, 0x8F, 0xC8, 0x6D, 0x02, 0x22, 0xEF, 0x9E, 0xB2, 0x6F, 0x2B, 0xB9, 0x44, 0x4F, 0xBC, 0xCD, 0x89, 0xA4, 0x32, 0x7E, 0x97, 0xDE, 0xCF, 0xAE, 0x4A, 0x83, 0xF5, 0x65, 0x37, 0x98, 0x6E, 0xA6 };
		unsigned char sha256buf[64] = { 0 };
		memcpy(sha256buf, _seed, 32); 
		memcpy(sha256buf + 32, _seed1, 32);
		int out_len = 0;
		unsigned char kenc[SHA256_DIGEST_LENGTH] = { 0 };
		SHA256(sha256buf, 64, kenc);

		AES_KEY key;
		AES_set_decrypt_key(kenc, 32 * 8, &key);
		unsigned char aes_out[64] = { 0 };
		for (int i = 0; i < 64; i+=16)
		{
			AES_ecb_encrypt(pkg.cipher + i, aes_out + i, &key, AES_DECRYPT);
		}

// 		AES_ecb_encrypt(pkg.cipher , aes_out , &key, AES_DECRYPT);
// 		AES_ecb_encrypt(pkg.cipher+32, aes_out+32, &key, AES_DECRYPT);
		typedef struct AUTH_ADM_KEY_INNER_ST
		{
			UINT8 rand[32];
			UINT8 mac[32];
		}AUTH_ADM_KEY_INNER;
		AUTH_ADM_KEY_INNER *auth = (AUTH_ADM_KEY_INNER *)aes_out;
		unsigned char _kseed2[] = {0x56, 0xD5, 0x5C, 0x3B, 0x40, 0x72, 0x7B, 0xC1, 0x58, 0xE2, 0xF5, 0x5E, 0x6D, 0x85, 0x5B, 0xBB, 0xA1, 0x8E, 0x27, 0xAA, 0x4C, 0xC7, 0xDB, 0x0A, 0xB3, 0xB7, 0xA0, 0x3D, 0x9E, 0xD8, 0x5C, 0x15 };
		memcpy(sha256buf, _seed, 32);
		memcpy(sha256buf + 32, _kseed2, 32);
		//Kmac
		SHA256(sha256buf, 64, kenc);
#pragma endregion

	}while(0);

	SENC_Close(dHandle);
	if(flag != SENC_SUCCESS){
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		RSA_free(rsakey);
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
		tempmsg.Format(_T("δ���ּ��ܿ��豸\r\n"));
		tempmsg.MakeUpper();
		pThis->PostErr(tempmsg);
		// 		RSA_free(rsakey);
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
			tempmsg.Format(_T("���ü��ܿ�IDʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		pThis->mPrgsCtr.StepIt();
		//set version

		GetPrivateProfileString(_T("Version"),_T("Fwversion"),_T("00000000"),Fwver,10,(LPCTSTR)pThis->iniUrl);
		GetPrivateProfileString(_T("Version"),_T("Hwversion"),_T("00000000"),Hwver,10,(LPCTSTR)pThis->iniUrl);

		if(Fwver==_T("00000000")||Hwver==_T("00000000")){
			tempmsg.Format(_T("��ȡ�汾��Ϣʧ�ܣ�config.ini��ʧ���𻵣�\r\n"));
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
			tempmsg.Format(_T("���ü��ܿ��汾ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//generate flash key
		flag = SENC_Product_GenerateFlashKey(dHandle);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("���ɼ��ܿ�flash��Կʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}
		pThis->mPrgsCtr.StepIt();

		//set d-h keys
		unsigned char g = 0x07;
		unsigned char p[4] = {0x3d,0x13,0xee,0xa5};

		flag = SENC_Product_SetDHAttributes(dHandle,p,4,&g,1);
		if(flag != SENC_SUCCESS){
			tempmsg.Format(_T("����DH������Կʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
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
			tempmsg.Format(_T("AES���ܲ���ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		AES_set_decrypt_key(tdata, 256, &aeskey);
		for(int i = 0 ; i < 256 ; i += 16 ){
			AES_ecb_encrypt(TestRcv+i, TestDec+i, &aeskey, AES_DECRYPT);
		}
		if(memcmp(TestSend, TestDec, 256) != 0){
			tempmsg.Format(_T("AES���ܲ���ʧ�ܣ��������ݲ�һ�£�"));
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
			tempmsg.Format(_T("RSAǩ������ʧ�ܣ�������Ϊ��0x%.8x\r\n"), flag);
			break;
		}

		fopen_s(&fp,"Correct.data","rb");
		fread(TestDec,1,256,fp);
		fclose(fp);

		fopen_s(&fp,"datatest.data","wb");
		fwrite(TestRcv,1,256,fp);
		fclose(fp);

		if(memcmp(TestRcv, TestDec, 256) != 0){
			tempmsg.Format(_T("RSAǩ������ʧ�ܣ��������ݲ�һ�£�"));
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
	tempmsg.Format(_T("�������"));
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


void SencPT_Dlg::OnBnClickedButtonFlashErase()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
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
