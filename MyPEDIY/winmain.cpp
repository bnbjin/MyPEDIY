/*******************************************************
/*����������ܡ�����������ʵ��
/*��16�� ��Ǳ�д����
/*Microsoft Visual C++ 6.0
/*Code by Hying 2001.1
/*Modified by kanxue  2005.3
/*Thanks ljtt
/*Hyingԭ���������������asm��kanxue��VC��д����д���̣��ο���ljtt�����Դ��
/*(c)  ��ѩ�����ȫ��վ www.pediy.com 2000-2008
********************************************************/
/********************************************************************************/
/*  VC 6.0����ֱ���ں���MASM32������ķ���							        */
/* 1����shell.asm��ӵ�VC���̵�Source files�У�					                */
/* 2����Source files�е�shell.objɾ����							                */
/* 3����Source files�е�shell.asm�ϣ��Ҽ�->Setting->ѡ��Custom Buildҳ	        */
/*   ��Commands�����룺													        */
/*    �����DEBUGģʽ�������룺											        */
/*    c:\masm32\bin\ml /c /coff /Zi /Fo$(IntDir)\$(InputName).obj $(InputPath)  */
/*																		        */
/*    �����RELEASEģʽ�������룺 							                    */
/*    c:\masm32\bin\ml /c /coff  /Fo$(IntDir)\$(InputName).obj $(InputPath)     */
/*																		        */
/*    ��Outputs�����룺													      	*/
/* $(IntDir)\$(InputName).obj                                                   */
/*    ���û�а�masm��װ��c�̣���Ҫ����Ӧ���޸ġ�                               */
/********************************************************************************/

#include <windows.h> 
#include <commctrl.h>
#include <process.h> 
#include "resource.h"
#include "winmain.h"
#include "config.h"
#include "utilities.h"
#include "error.h"
#include "pediy.h"
#include "globalvalue.h"

#pragma comment(lib, "comctl32.lib")


/*
	Description:	�����Ӵ��ڻص�����
*/
INT_PTR CALLBACK SubCTLDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	HANDLE					hThread;
	DWORD					ProtFileThreadID;
	static TCHAR			szFilePath[MAX_PATH];

	switch (uMsg)
	{
	case WM_INITDIALOG:
		// ������Ϣ�򻺳�
		g_pMessageBuffer = new TCHAR[0x10000];
		ZeroMemory(g_pMessageBuffer, 0x10000);

		// ��ȡ���������
		g_hProgress = GetDlgItem(hDlg, IDC_PROGRESS);
		
		// ʹ�ܹ��ļ��϶�
		//DragAcceptFiles(hDlg, TRUE);
		
		// ���üӿǴ�����
		EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);

#ifdef __PARADOX_DEBUG__
		WinExec("C:\\Users\\Administrator\\Desktop\\deltest.bat", SW_HIDE);

		lstrcpy(szFilePath, TEXT("C:\\Users\\Administrator\\Desktop\\test.exe"));
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProtTheFile, (LPVOID)szFilePath, NORMAL_PRIORITY_CLASS, &ProtFileThreadID);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		WinExec("C:\\Users\\Administrator\\Desktop\\test.exe", SW_NORMAL);

		SendMessage(GetParent(GetParent(hDlg)), WM_CLOSE, 0, 0);
#endif 

		break;
	/*
	case WM_DROPFILES://֧���ļ��Ϸ�

		if (FALSE == ISWORKING) {

			ZeroMemory(g_pMessageBuffer, 0x10000); //����Ϣ��������������
			ZeroMemory(szFilePath, MAX_PATH);//����ļ�������
			DragQueryFile((HDROP)wParam, 0, szFilePath, sizeof(szFilePath));
			DragFinish((HDROP)wParam);

			SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, WM_SETTEXT, 0, 0);//�����Ϣ���е���ʾ
			SendDlgItemMessage(hDlg, IDC_FILEPATH_EDIT, WM_SETTEXT, MAX_PATH, (LPARAM)szFilePath);
			AddLine(hDlg, szFilePath);
			if (!IsPEFile(szFilePath, hDlg))
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);
			else
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), TRUE);
			SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
		}
		break;
	*/
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		//����			
		case IDC_PROT_BUTTON:
			EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_OPEN_BUTTON), FALSE);

			// ����һ���߳�����������
			hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ProtTheFile, (LPVOID)szFilePath, NORMAL_PRIORITY_CLASS, &ProtFileThreadID);
			CloseHandle(hThread);

			break;

		//��Ԥ����
		case IDC_OPEN_BUTTON:
			if (!OpenFileDlg(szFilePath, hDlg))
			{
				break;
			}
			
			SendDlgItemMessage(hDlg, IDC_MESSAGEBOX_EDIT, WM_SETTEXT, 0, 0);//�����Ϣ���е���ʾ

			SendDlgItemMessage(hDlg, IDC_FILEPATH_EDIT, WM_SETTEXT, MAX_PATH, (LPARAM)szFilePath);
			AddLine(hDlg, szFilePath);
			
			if (ERR_SUCCESS == IsPEFile(szFilePath))
			{
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), TRUE);
			}
			else
			{
				EnableWindow(GetDlgItem(hDlg, IDC_PROT_BUTTON), FALSE);
			}
			
			SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
			
			break;

		default:
			
			// MessageBox(hDlg, TEXT("�����Ӵ���δ����WM_COMMAND"), 0, 0);
			
			return FALSE;

			break;
		}

		return TRUE;
		
		break;
	}
	return FALSE;
}

/*
	Description:	���Կ����Ӵ��ڹ���
*/
INT_PTR CALLBACK SubSWTDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{

	switch (uMsg)
	{
	case WM_INITDIALOG:
		//���öԻ����ʼ��
		//properinitDlgProc(hDlg);
		break;
	}
	return FALSE;
}

/*
	Description:	���ڳ��򴰿�
*/
INT_PTR CALLBACK AboutPGMDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	switch (uMsg)
	{
	case  WM_LBUTTONDOWN:
		PostMessage(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, 0);
		return TRUE;
		break;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	}
	return FALSE;
}

/*
	Description:	�������ߴ���
*/
INT_PTR CALLBACK AboutAuthorDlgProc(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	switch (uMsg)
	{
	case  WM_LBUTTONDOWN:
		PostMessage(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, 0);
		return TRUE;

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	}

	return FALSE;
}


/*
Description:	���Ի�����Ϣ�ص�����
*/
INT_PTR CALLBACK MainDlg(
	_In_ HWND hDlg,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	static int     i;
	static HWND    hwndTab;           //TAB�ؼ����
	static HWND    SubCTLWnd;        //3���ӶԻ�����
	static HWND    SubSWTWnd;
	static HWND    Child3hWnd;
	TC_ITEM ItemStruct;


	switch (uMsg)
	{
	case WM_CLOSE:
		if (false == ISWORKING) {
			// �ͷ��ڿ����Ӵ���������ڴ�
			delete g_pMessageBuffer;

			DestroyWindow(hDlg);
		}
		else
		{
			MessageBox(NULL, TEXT("����ѹ���������˳���"), TEXT("����"), MB_OK);
		}

		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDM_ABOUT_PGM:
			DialogBox(g_hInst, MAKEINTRESOURCE(IDD_ABOUT_PGM), hDlg, AboutPGMDlgProc);
			break;

		case IDM_ABOUT_AUTHOR:
			DialogBox(g_hInst, MAKEINTRESOURCE(IDD_ABOUT_AUTHOR), hDlg, AboutAuthorDlgProc);
			break;

		case IDM_FILE_OPEN:
			SendMessage(SubCTLWnd, WM_COMMAND, (WPARAM)IDC_OPEN_BUTTON, 0);
			break;

		case IDM_FILE_EXIT:
			SendMessage(hDlg, WM_CLOSE, 0, 0);
			break;

		default:
			MessageBox(hDlg, TEXT("������δ����WM_COMMAND"), 0, 0);
			break;
		}

		break;

	case WM_INITDIALOG:

		// ����������ͼ��
		SendMessage(hDlg, WM_SETICON, ICON_BIG, LPARAM(LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_ICON1))));

		InitCommonControls();

		hwndTab = GetDlgItem(hDlg, IDC_TAB1);
		ItemStruct.mask = TCIF_TEXT;
		ItemStruct.iImage = 0;
		ItemStruct.lParam = 0;
		ItemStruct.pszText = TEXT("����");
		ItemStruct.cchTextMax = 4;
		SendMessage(hwndTab, TCM_INSERTITEM, 0, (LPARAM)&ItemStruct);

		ItemStruct.pszText = TEXT("ѡ��");
		ItemStruct.cchTextMax = 4;
		SendMessage(hwndTab, TCM_INSERTITEM, 1, (LPARAM)&ItemStruct);

		SubCTLWnd = CreateDialogParam(g_hInst, MAKEINTRESOURCE(IDD_SUB_CONTROL), hwndTab, SubCTLDlgProc, 0);
		SubSWTWnd = CreateDialogParam(g_hInst, MAKEINTRESOURCE(IDD_SUB_SWITCH), hwndTab, SubSWTDlgProc, 0);

		ShowWindow(SubCTLWnd, SW_SHOWDEFAULT);

		break;

	case WM_NOTIFY:
		//2���ӶԻ������л�
		if (*(LPDWORD)((LPBYTE)lParam + 8) == TCN_SELCHANGE)
		{
			//�����������ӶԻ���
			ShowWindow(SubCTLWnd, SW_HIDE);
			ShowWindow(SubSWTWnd, SW_HIDE);

			i = SendMessage(hwndTab, TCM_GETCURSEL, 0, 0);
			if (i == 0)
			{
				//GetOption(SubSWTWnd);//ȡ�����ò����浽�����ļ�
				ShowWindow(SubCTLWnd, SW_SHOWDEFAULT);
			}
			else if (i == 1)
			{
				ShowWindow(SubSWTWnd, SW_SHOWDEFAULT);
			}

		}
		break;

	default:
		break;
	}

	return 0;
}


/*
	Description:	������ڵ�
					1.�������Ի���
*/
int CALLBACK WinMain(
	_In_ HINSTANCE hInstance, 
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine, 
	_In_ int nCmdShow)
{
	// ����ʵ������Թ������ط�ʹ��
	g_hInst = hInstance;

	DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_MAINDLG), NULL, MainDlg, NULL);

	return 0;
}