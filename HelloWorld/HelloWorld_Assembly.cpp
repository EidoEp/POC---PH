#include <iostream>
#include <windows.h>
#include <winbase.h>


int main()
{
	const char* wMsg = "Hello World!";
	const char* wCaption = "Hello World Process";
	__asm {
		mov eax, 0
		mov ebx, wCaption
		mov ecx, wMsg
		mov edx, 0
		push eax
		push ebx
		push ecx
		push edx
		call MessageBoxA
		pop edx
		pop ecx
		pop ebx
		pop eax
		mov ebx, 0
		mov ecx, 0
	}
}