#pragma once
#include "afxwin.h"
#include "resource.h"
#include "afxcmn.h"
#include "libsenc.h"

// SencPT_Dlg �Ի���

class SencPT_Dlg : public CDialogEx
{
/*	DECLARE_DYNAMIC(SencPT_Dlg)*/

public:
	SencPT_Dlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~SencPT_Dlg();


// �Ի�������
	enum { IDD = IDD_SencPT_Dlg };

	void PostLog(const CString & _log);
	void PostErr(const CString & _log);
	void PostFin(const CString & _log);
	void PostStart(const CString & _log);
	void PostFFFF();
	void CountUpdate();


protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	CFont *sn, *fn, *tn;

	int SuccussTimes,FailedTimes,TotalTimes;

protected:
	HICON m_hIcon;
	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	virtual LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam);
	CEdit SNumCtr;
	CEdit FNumCtr;
	CEdit TNumCtr;
	CEdit LogCtr;
	CButton StartBtnCtr;
	CProgressCtrl mPrgsCtr;

	TCHAR szFilePath[MAX_PATH + 1];
	CString iniUrl;
	unsigned int productCount;

	int tardev;
	SENCryptCardList gDevList;

	afx_msg void OnBnClickedButtonProduction();
	afx_msg void OnBnClickedButtonFlashErase();
	afx_msg void OnBnClickedButtonGetList();
	afx_msg void OnBnClickedButtonNoneRand();
};

