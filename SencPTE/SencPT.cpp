
// SencPT.cpp : 定义应用程序的类行为。
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
// 	// 基于文件的标准文档命令
// 	ON_COMMAND(ID_FILE_NEW, &CWinApp::OnFileNew)
// 	ON_COMMAND(ID_FILE_OPEN, &CWinApp::OnFileOpen)
// 	// 标准打印设置命令
// 	ON_COMMAND(ID_FILE_PRINT_SETUP, &CWinApp::OnFilePrintSetup)
END_MESSAGE_MAP()


// CSencPTApp 构造

CSencPTApp::CSencPTApp()
{
	// 支持重新启动管理器
// 	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_ALL_ASPECTS;
// #ifdef _MANAGED
// 	// 如果应用程序是利用公共语言运行时支持(/clr)构建的，则:
// 	//     1) 必须有此附加设置，“重新启动管理器”支持才能正常工作。
// 	//     2) 在您的项目中，您必须按照生成顺序向 System.Windows.Forms 添加引用。
// 	System::Windows::Forms::Application::SetUnhandledExceptionMode(System::Windows::Forms::UnhandledExceptionMode::ThrowException);
// #endif
// 
// 	// TODO: 将以下应用程序 ID 字符串替换为唯一的 ID 字符串；建议的字符串格式
// 	//为 CompanyName.ProductName.SubProduct.VersionInformation
// 	SetAppID(_T("SencPT.AppID.NoVersion"));
// 
// 	// TODO: 在此处添加构造代码，
// 	// 将所有重要的初始化放置在 InitInstance 中
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;
}

// 唯一的一个 CSencPTApp 对象

CSencPTApp theApp;


// CSencPTApp 初始化

BOOL CSencPTApp::InitInstance()
{
	// 如果一个运行在 Windows XP 上的应用程序清单指定要
	// 使用 ComCtl32.dll 版本 6 或更高版本来启用可视化方式，
	//则需要 InitCommonControlsEx()。否则，将无法创建窗口。
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// 将它设置为包括所有要在应用程序中使用的
	// 公共控件类。
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


// 	// 初始化 OLE 库
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

	// 使用 RichEdit 控件需要  AfxInitRichEdit2()	
	// AfxInitRichEdit2();

	// 标准初始化
	// 如果未使用这些功能并希望减小
	// 最终可执行文件的大小，则应移除下列
	// 不需要的特定初始化例程
	// 更改用于存储设置的注册表项
	// TODO: 应适当修改该字符串，
	// 例如修改为公司或组织名
	SetRegistryKey(_T("应用程序向导生成的本地应用程序"));
// 	LoadStdProfileSettings(4);  // 加载标准 INI 文件选项(包括 MRU)

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
		TRACE(traceAppMsg, 0, "警告: 对话框创建失败，应用程序将意外终止。\n");
		TRACE(traceAppMsg, 0, "警告: 如果您在对话框上使用 MFC 控件，则无法 #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS。\n");
	}

	if (pShellManager != NULL)
	{
		delete pShellManager;
	}


	// 由于对话框已关闭，所以将返回 FALSE 以便退出应用程序，
	//  而不是启动应用程序的消息泵。
	return FALSE;

}
// CSencPTApp 消息处理程序


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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



// CSencPTApp 消息处理程序



