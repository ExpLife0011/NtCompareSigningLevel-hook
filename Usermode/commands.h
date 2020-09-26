#pragma once
#include	"utils.h"


enum	DRIVER_COMMAND : BYTE
{
	START_CONNECTION = 144,
	GET_BASE = 145,
	RESOLVE_RELATIVE_ADDR = 146,
	READ_MEMORY = 147,
	WRITE_MEMORY = 148,
	FIND_OUTBUFFER = 149,
	SIG_SCAN = 150,
	CLEAR_TRACES = 151,
	TEST = 152,
};


struct SigScanInput
{
	char	section[10];
	UCHAR	pattern[20];
	PVOID	moduleBase;
};


namespace Driver
{

	/*	get address of Output buffer (for read operations)		*/
	void	findOutBuffer()
	{
		BYTE		arg1[8];
		DWORD64		dArg1;

		arg1[0] = FIND_OUTBUFFER;

		memcpy(&dArg1, arg1, 8);

		NtCompareSigningLevels(dArg1, (DWORD64)globals::OutBuffer.buf);

		return;
	}


	DWORD64	getModuleBase(const wchar_t* moduleName, int procId)
	{
		wcscpy((wchar_t*)globals::InBuffer.buf, moduleName);

		NtCompareSigningLevels(GET_BASE, procId);


	
		return *(DWORD64*)globals::OutBuffer.buf;
	
	}

	template <typename T>
	T	Read(int	procId, int length, DWORD64 address)
	{
		BYTE	buffer1[8];


		buffer1[0] = READ_MEMORY;							/*	byte 1 for command ID	*/
		memcpy((PVOID)(buffer1 + 1), &procId, 4);			/*	byte 2-6 for process ID		*/
		memcpy((PVOID)(buffer1 + 5), &length, 3);			/*	byte 5-8 for length		*/
		

		DWORD64	arg1;

		memcpy(&arg1, buffer1, 8);

		NtCompareSigningLevels(arg1, address);
		
		return *(T*)globals::OutBuffer.buf;
	}

	template <typename T>
	T	Write(int	procId, int length, DWORD64 address, T* buffer)
	{
		BYTE	buffer1[8];


		buffer1[0] = WRITE_MEMORY;							/*	byte 1 for command ID	*/
		memcpy((PVOID)(buffer1 + 1), &procId, 4);			/*	byte 2-6 for process ID		*/
		memcpy((PVOID)(buffer1 + 5), &length, 3);			/*	byte 5-8 for length		*/


		DWORD64	arg1;

		memcpy(&arg1, buffer1, 8);
		memcpy(globals::InBuffer.buf, buffer, length);


		NtCompareSigningLevels(arg1, address);

		return *(T*)globals::OutBuffer.buf;
	}


	/*	starts connection with the  input buffer in usermode	*/

	int	startConnection()
	{
		BYTE		arg1[8];

		arg1[0] = START_CONNECTION;

		int currentPID = GetCurrentProcessId();

		memcpy((arg1 + 1), &currentPID, 4);


		DWORD64		dwordArg;
		memcpy(&dwordArg, arg1, 8);

		NtCompareSigningLevels(dwordArg, (DWORD64)globals::InBuffer.buf);

		Driver::findOutBuffer();

		return 0;
	}


	PVOID64	sigScan(const char* section, UCHAR* pattern, UCHAR wildcard, int length, PVOID moduleBase, int processId)
	{
		BYTE	arg1[8];

		arg1[0] = SIG_SCAN;
		arg1[1] = wildcard;

		memcpy((arg1 + 2), &length, 4);

		DWORD64	 dArg1;

		memcpy(&dArg1, arg1, 8);


		SigScanInput  input;


		strcpy(input.section, section);
		memcpy(input.pattern, pattern, length);
		input.moduleBase = moduleBase;


		memcpy(globals::InBuffer.buf, &input, sizeof(SigScanInput));

		NtCompareSigningLevels(dArg1, processId);

		return *(PVOID64*)(globals::OutBuffer.buf);
	}


	//ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
	PVOID		resolveRelativeAddress(PVOID instruction, int OffsetOffset, int InstructionSize)
	{
		BYTE	arg1[8];

		arg1[0] = RESOLVE_RELATIVE_ADDR;

		memcpy((arg1 + 1), &OffsetOffset, 3);
		memcpy((arg1 + 4), &InstructionSize, 4);


		DWORD64		dArg1;

		memcpy(&dArg1, arg1, 8);

		NtCompareSigningLevels(dArg1, (DWORD64)instruction);

		return *(PVOID*)(globals::OutBuffer.buf);
	}

	void	clearTraces()
	{
		NtCompareSigningLevels(CLEAR_TRACES, 0);
	}


	DWORD64	test()
	{
		cout << NtCompareSigningLevels(TEST, 0) << endl;

		return 0;
	}
}