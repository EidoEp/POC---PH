// HelloWorld.cpp : Defines the entry point for the console application.

#include <iostream>
#include <windows.h>
#pragma comment (lib, "user32.lib")


INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nCmdShow)
{
    MessageBoxA(0, "Hello World", "Hello World", 0);
    return 0;
}