#include "stdafx.h"
#include "plugin.h"
#include <tlhelp32.h>
#include <stdlib.h>
#include "Signature.h"

HANDLE g_hInstance; // DLL 인스턴스
HWND g_hWndOlly; // 올리디버거 윈도우 핸들

void ScanCodeViaAddr(PBYTE pbBaseAddr, PBYTE pbMemBuffer, DWORD dwTableAddr)
{
	// 버퍼가 아닌 실제 메모리로 하면 crash 발생.
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pbMemBuffer;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_Addtolist(0, 0, "NO DOS Signature");
		goto EXIT_ERROR;
	}
	
	PIMAGE_NT_HEADERS pNtHeader;
	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDos + pDos->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		_Addtolist(0, 0, "NO NT Signature");
		goto EXIT_ERROR;
	}

	DWORD dwBaseOfCode = pNtHeader->OptionalHeader.BaseOfCode;
	DWORD dwSizeOfCode = pNtHeader->OptionalHeader.SizeOfCode;

	int nOffset = 0;
	int nRetnByte = 0; // 어셈블 하고 리턴된 바이트

	t_disasm da;
	unsigned char cmd[MAXCMDSIZE] = { 0, }; // 한줄 읽기

	DWORD dwCodeAddr = (DWORD)pbBaseAddr + dwBaseOfCode;
	
	// 코드 섹션 만큼 뺑뺑이
	while (dwCodeAddr + dwSizeOfCode > dwCodeAddr + nOffset)
	{
		_Readmemory(cmd, dwCodeAddr + nOffset, MAXCMDSIZE, MM_RESTORE | MM_SILENT);
		nRetnByte = _Disasm(cmd, MAXCMDSIZE, dwCodeAddr + nOffset, NULL, &da, DISASM_CODE, 0);
		
		if (da.adrconst == dwTableAddr)
		{
			_Addtolist(0, 0, "Code Addr : 0x%08x %s", dwCodeAddr + nOffset, da.result);
		}
		nOffset += nRetnByte;
	}

EXIT_ERROR:
	return;
	
}

size_t Search(IN BYTE* pbBuffer, IN size_t BufSize, IN size_t Offset, IN BYTE* pbCode, IN size_t SigSize)
{
	size_t ret = (size_t)-1;
	size_t i = 0;
	for (i = Offset; i <= BufSize - SigSize; i++)
	{
		size_t j = 0;
		for (j = 0; j < SigSize; j++)
		{
			if ((pbBuffer[i + j] != pbCode[j]) && (0x91 != pbCode[j]))
			{
				// 일치하지 않으면 j의 증가를 멈춤
				break;
			}

		}
		if (j == SigSize)
		{
			ret = i;
			break;
		}
	}

	return ret;
}


void ScanTable(PBYTE pbBaseAddr, DWORD dwModSize, char* szExePath)
{	
	PBYTE pbMemBuffer = NULL;
	pbMemBuffer = (PBYTE)malloc(dwModSize);
	_Readmemory(pbMemBuffer, (DWORD)pbBaseAddr, dwModSize, MM_RESTORE | MM_SILENT);
	

	// 시그내처 갯수
	int nSigCount = sizeof(stSignature) / sizeof(stSignature[0]);

	for (int i = 0; i < nSigCount; i++)
	{
		DWORD dwOffset = 0;
		do
		{
			int nOffset = Search(pbMemBuffer, dwModSize, dwOffset, stSignature[i].pbCode, stSignature[i].dwSize);
			// 찾을 수 없다면
			if (nOffset == -1)
			{
				break;
			}
			_Addtolist(0, 1, "[Found] 0x%08x %s ", pbBaseAddr, szExePath);
			_Addtolist(0, 1, "[%s] 0x%08x ", stSignature[i].pszName, (DWORD)pbBaseAddr + nOffset);
			if (stSignature[i].code == 0)
			{
				ScanCodeViaAddr(pbBaseAddr, pbMemBuffer, (DWORD)pbBaseAddr + nOffset);
			}
			else
			{				
				// 코드인경우 disasm 해서 보여준다.
				unsigned char cmd[MAXCMDSIZE] = { 0, }; // 한줄 읽기
				t_disasm da;
				_Readmemory(cmd, (DWORD)pbBaseAddr + nOffset, MAXCMDSIZE, MM_RESTORE | MM_SILENT);
				_Disasm(cmd, MAXCMDSIZE, (DWORD)pbBaseAddr + nOffset, NULL, &da, DISASM_CODE, 0);
				_Addtolist(0, 0, "Code Addr : 0x%08x %s", (DWORD)pbBaseAddr + nOffset, da.result);
			}
			
			dwOffset = nOffset + 1;
		} while (dwOffset < dwModSize);
	}

	// Free!
	ZeroMemory(pbMemBuffer, dwModSize);
	free(pbMemBuffer);

}

void Scan()
{
	// 타겟 프로세스 ID 구하기
	DWORD dwPid = _Plugingetvalue(VAL_PROCESSID);
	
	MODULEENTRY32 me32 = { 0, };
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		goto EXIT_ERROR;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	BOOL bSuccess = Module32First(hModuleSnap, &me32);
	if (FALSE == bSuccess)
	{
		goto EXIT_ERROR;
	}
	do
	{		
		//_Addtolist(0, 0, "0x%08x %08x %s", me32.modBaseAddr, me32.modBaseSize, me32.szExePath);
		ScanTable(me32.modBaseAddr, me32.modBaseSize, me32.szExePath);

	} while (Module32Next(hModuleSnap, &me32));


EXIT_ERROR:
	return;
}
extc int _export cdecl ODBG_Plugininit(int OllyVersion, HWND hWnd, ulong *features)
{
	// ollydbg v1.10 이상에서는 미지원
	if (PLUGIN_VERSION < OllyVersion)
	{
		return -1;
	}
	g_hWndOlly = hWnd;


	_Addtolist(0, 1, "Scan Base64 Function v1.5");
	_Addtolist(0, 0, "written By Codetronik / http://codetronik.tistory.com");
	
	return 0;

}

extc int _export cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item)
{

	switch (origin)
	{
	case PM_MAIN:
		strcpy_s(data, 4096, 
			"0 Scan|"
			"1 About"
			);
		return 1;
	default:
		break;

	}
	return 0;
}


extc void _export cdecl ODBG_Pluginaction(int origin, int action, void* item)
{
	switch (origin)
	{
	case PM_MAIN:
	case PM_DISASM:
		switch (action)
		{
		case 0: // Scan
			Scan();
			return;
		case 1: // About
			MessageBox(g_hWndOlly, "Scan Base64 Function v1.0\nCodetronik", "About", MB_OK);
			return;
		}
	}
}


extc int _export cdecl ODBG_Plugindata(char szMenuName[32])
{
	strcpy_s(szMenuName, 32, "Scan Base64 Function");
	return PLUGIN_VERSION;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hInstance = hModule;
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

