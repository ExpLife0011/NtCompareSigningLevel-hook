#pragma once
#include	<iostream>
#include	<Windows.h>
#include	<TlHelp32.h>
#include	<string>


using namespace std;


typedef     DWORD64(NTAPI* pFnNtCompareSigningLevels)(DWORD64 a, DWORD64 b);
pFnNtCompareSigningLevels   NtCompareSigningLevels = 0;



/*	in case there needs to be more input than 16 bytes		*/

struct BYTE_BUFFER
{
	BYTE	data[50];
};

struct  Buffer
{
	BYTE_BUFFER*	buf;
};



namespace	globals
{
	Buffer	InBuffer;
	Buffer	OutBuffer;
}


namespace	offset
{
	DWORD	localplayer = 0x10f4f4;
	DWORD	health = 0xF8;
}