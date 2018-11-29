
// SencPT.cpp : ����Ӧ�ó��������Ϊ��
//

#include "stdafx.h"
#include "afxwinappex.h"
#include "afxdialogex.h"
#include "SencPT.h"
#include "SencPT_Dlg.h"
// #include "MainFrm.h"
// 
// #include "SencPTDoc.h"
// #include "SencPTView.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CSencPTApp

BEGIN_MESSAGE_MAP(CSencPTApp, CWinApp)
// 	ON_COMMAND(ID_APP_ABOUT, &CSencPTApp::OnAppAbout)
// 	// �����ļ��ı�׼�ĵ�����
// 	ON_COMMAND(ID_FILE_NEW, &CWinApp::OnFileNew)
// 	ON_COMMAND(ID_FILE_OPEN, &CWinApp::OnFileOpen)
// 	// ��׼��ӡ��������
// 	ON_COMMAND(ID_FILE_PRINT_SETUP, &CWinApp::OnFilePrintSetup)
END_MESSAGE_MAP()


// CSencPTApp ����

CSencPTApp::CSencPTApp()
{
	// ֧����������������
// 	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_ALL_ASPECTS;
// #ifdef _MANAGED
// 	// ���Ӧ�ó��������ù�����������ʱ֧��(/clr)�����ģ���:
// 	//     1) �����д˸������ã�������������������֧�ֲ�������������
// 	//     2) ��������Ŀ�У������밴������˳���� System.Windows.Forms ������á�
// 	System::Windows::Forms::Application::SetUnhandledExceptionMode(System::Windows::Forms::UnhandledExceptionMode::ThrowException);
// #endif
// 
// 	// TODO: ������Ӧ�ó��� ID �ַ����滻ΪΨһ�� ID �ַ�����������ַ�����ʽ
// 	//Ϊ CompanyName.ProductName.SubProduct.VersionInformation
// 	SetAppID(_T("SencPT.AppID.NoVersion"));
// 
// 	// TODO: �ڴ˴���ӹ�����룬
// 	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;
}

// Ψһ��һ�� CSencPTApp ����

CSencPTApp theApp;


// CSencPTApp ��ʼ��

BOOL CSencPTApp::InitInstance()
{
	// ���һ�������� Windows XP �ϵ�Ӧ�ó����嵥ָ��Ҫ
	// ʹ�� ComCtl32.dll �汾 6 ����߰汾�����ÿ��ӻ���ʽ��
	//����Ҫ InitCommonControlsEx()�����򣬽��޷��������ڡ�
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// ��������Ϊ��������Ҫ��Ӧ�ó�����ʹ�õ�
	// �����ؼ��ࡣ
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


// 	// ��ʼ�� OLE ��
// 	if (!AfxOleInit())
// 	{
// 		AfxMessageBox(IDP_OLE_INIT_FAILED);
// 		return FALSE;
// 	}
// 
	AfxEnableControlContainer();

// 	EnableTaskbarInteraction(FALSE);
	CShellManager *pShellManager = new CShellManager;
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// ʹ�� RichEdit �ؼ���Ҫ  AfxInitRichEdit2()	
	// AfxInitRichEdit2();

	// ��׼��ʼ��
	// ���δʹ����Щ���ܲ�ϣ����С
	// ���տ�ִ���ļ��Ĵ�С����Ӧ�Ƴ�����
	// ����Ҫ���ض���ʼ������
	// �������ڴ洢���õ�ע�����
	// TODO: Ӧ�ʵ��޸ĸ��ַ�����
	// �����޸�Ϊ��˾����֯��
	SetRegistryKey(_T("Ӧ�ó��������ɵı���Ӧ�ó���"));
// 	LoadStdProfileSettings(4);  // ���ر�׼ INI �ļ�ѡ��(���� MRU)

	SencPT_Dlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{

	}
	
	else if (nResponse == IDCANCEL)
	{

	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "����: �Ի��򴴽�ʧ�ܣ�Ӧ�ó���������ֹ��\n");
		TRACE(traceAppMsg, 0, "����: ������ڶԻ�����ʹ�� MFC �ؼ������޷� #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS��\n");
	}

	if (pShellManager != NULL)
	{
		delete pShellManager;
	}


	// ���ڶԻ����ѹرգ����Խ����� FALSE �Ա��˳�Ӧ�ó���
	//  ����������Ӧ�ó������Ϣ�á�
	return FALSE;

}
// CSencPTApp ��Ϣ�������


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()



// CSencPTApp ��Ϣ�������



