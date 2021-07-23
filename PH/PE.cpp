#include <windows.h>
#include "internals.h"
#include "PE.h"

DWORD FindRemotePEB(HANDLE hProcess)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");		/*	We'll load the ntdll library in order to
								load the next function we'll be using.	*/
	if (!hNTDLL)
		return 0;

	FARPROC fpNtQueryInformationProcess = GetProcAddress	// Used to get the function we require from ntdll.
	(
		hNTDLL,
		"NtQueryInformationProcess"		// The function we need to retrieve information on svchost.exe
	);

	if (!fpNtQueryInformationProcess)
		return 0;

	_NtQueryInformationProcess ntQueryInformationProcess =
		(_NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION* pBasicInfo =
		new PROCESS_BASIC_INFORMATION();

	DWORD dwReturnLength = 0;

	ntQueryInformationProcess	//	The actual setting of all of the above in order to get the process address.
	(
		hProcess,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);

	return pBasicInfo->PebBaseAddress;
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
	DWORD dwPEBAddress = FindRemotePEB(hProcess);	/*	The "FindRemotePEB" function will contain the code
								for using- NtQueryInformationProcess.	*/
	PEB* pPEB = new PEB();

	BOOL bSuccess = ReadProcessMemory		// As the name implies :)
	(
		hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(PEB),
		0
	);

	if (!bSuccess)
		return 0;

	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
	BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0
	);

	if (!bSuccess)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	PLOADED_IMAGE pImage = new LOADED_IMAGE();

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew +
			sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}
