#pragma once
#include    "KdmapperTraces.h"




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




PVOID   handler(DWORD64    a, DWORD64   b)
{
    int length;
    memcpy(&length, ((char*)&a + 5), 3);


    int processId;
    memcpy(&processId, ((char*)&a + 1), 4);


    PEPROCESS   process;
    PsLookupProcessByProcessId((HANDLE)processId, &process);



    KFLOATING_SAVE     saveData;


    BYTE* arg1 = (BYTE*)&a;

    switch (arg1[0])
    {
        case START_CONNECTION:
        {
            PsLookupProcessByProcessId((HANDLE)processId, &Globals::userClient);

            Globals::inBufAddress = (BYTE_BUFFER*)(PVOID)b;

            DbgPrint("start  connection command, %p \n", Globals::inBufAddress);

            break;
        }

        case GET_BASE:
        {
            PVOID   baseAddr = Utils::getUserModuleBase(b);

            DbgPrint("baseAddr is %p \n", baseAddr);

            Utils::WriteMemory((ULONG64)Globals::outBufAddress, &baseAddr, sizeof(PVOID), Globals::userClient);

            break;

        }

        case READ_MEMORY:
        {
            DbgPrint("[+] read memory command address  %p ", b);
            DbgPrint("   length %i   ", length);
            DbgPrint("   process ID %i   \n", processId);

            KeSaveFloatingPointState(&saveData);

            BYTE_BUFFER buffer;


            Utils::ReadMemory(b, length, buffer.data, process);

            Utils::WriteMemory((ULONG64)Globals::outBufAddress, buffer.data, length, Globals::userClient);


            KeRestoreFloatingPointState(&saveData);

            return 0;
         
        }

        case WRITE_MEMORY:
        {
            DbgPrint("[+] write memory command address  %p ", b);
            DbgPrint("   length %i   ", length);
            DbgPrint("   process ID %i   \n", processId);


            BYTE_BUFFER    buffer;

            KeSaveFloatingPointState(&saveData);

            Utils::ReadMemory((ULONG64)Globals::inBufAddress, length, buffer.data, Globals::userClient);

            Utils::WriteMemory((ULONG64)b, (PVOID)buffer.data, length, process);

            KeRestoreFloatingPointState(&saveData);

            
            return 0;
        }

        case FIND_OUTBUFFER:
        {

            Globals::outBufAddress = (BYTE_BUFFER*)(PVOID)b;

            break;

        }

        case RESOLVE_RELATIVE_ADDR:
        {
            int     offsetOffset;
            int     instructionLen;




            memcpy(&offsetOffset, (arg1 + 1), 3);
            memcpy(&instructionLen, (arg1 + 4), 4);


            PVOID   address = Utils::ResolveRelativeAddress((PVOID)b, offsetOffset, instructionLen);

            Utils::WriteMemory((DWORD64)Globals::outBufAddress, &address, 8, Globals::userClient);

            break;
        }


        case CLEAR_TRACES:
        {
            cleanUnloadedDriverString();
            ClearPiddbCacheTable();

            break;
        }

        case SIG_SCAN:
        {

            UCHAR   wildcard = arg1[1];

            int     processId = b;

            int     patternLength = *(int*)(arg1 + 2);

            PVOID   foundAt;



            SigScanInput  input;


            Utils::ReadMemory((ULONG64)Globals::inBufAddress, sizeof(SigScanInput), &input, Globals::userClient);
            

            PEPROCESS   targetProcess;
            PsLookupProcessByProcessId((HANDLE)processId, &targetProcess);

            
            KAPC_STATE  apc;
            KeStackAttachProcess(targetProcess, &apc);


            Utils::BBScan(input.section, input.pattern, wildcard, patternLength, &foundAt, input.moduleBase);


            KeUnstackDetachProcess(&apc);



            Utils::WriteMemory((ULONG64)Globals::outBufAddress, &foundAt, sizeof(PVOID64), Globals::userClient);

            return 0;
        }

        case TEST:
        {
            return (PVOID)TEST;
        }

        default:
        {
            Globals::oldFuncPtrAddr(a, b);
        }
    }



    return 0;
}


NTSTATUS    Entry(_In_ _DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS         status = STATUS_SUCCESS;
    ULONG            moduleSize;

    DWORD64          ntosBase = (DWORD64)Utils::getDriverBaseAddress(&moduleSize, "ntoskrnl.exe");




    /*  4c 8b 05 ? ? ? ? 33 c0 4d 85 c0 74 `*/
    Utils::BBScan(".PAGE", (PCUCHAR)"\x4C\x8B\x05\x00\x00\x00\x00\x33\xC0\x4D\x85\xC0\x74", '\x00', 13, 
        (PVOID*)&Globals::funcPtrAddress, (PVOID)ntosBase);


    if (Globals::funcPtrAddress != NULL)
    {
        Globals::funcPtrAddress = (NtCompareSigningLevelPtr)Utils::ResolveRelativeAddress(Globals::funcPtrAddress, 3, 7);

        DbgPrint("[1] NtCompareSigningLevels ptr location: %p \n", Globals::funcPtrAddress);

    }
    else
    {
        /*  48 8B 05 ? ? ? ? 48 85 c0 0F 84 ? ? ? ? 8a  */
        Utils::BBScan(".PAGE", (PCUCHAR)"\x4C\x8B\x05\x00\x00\x00\x00\x33\xC0\x4D\x85\xC0\x74", '\x00', 13, 
            (PVOID*)&Globals::funcPtrAddress, (PVOID)ntosBase);


        if (Globals::funcPtrAddress != NULL)
        {
            Globals::funcPtrAddress = (NtCompareSigningLevelPtr)Utils::ResolveRelativeAddress(Globals::funcPtrAddress, 3, 7);

            DbgPrint("[2] NtCompareSigningLevels ptr location: %p \n", Globals::funcPtrAddress);

        }
        else    /*      if step 3 fails, then there will be BSOD       */
        {

            UNICODE_STRING      ntCompareSigningLevel;
            RtlInitUnicodeString(&ntCompareSigningLevel, L"NtCompareSigningLevels");


            Globals::funcPtrAddress = (NtCompareSigningLevelPtr)MmGetSystemRoutineAddress(&ntCompareSigningLevel);

            DWORD64  instruction = (DWORD64)Globals::funcPtrAddress + 4;

            instruction = (DWORD64)Utils::ResolveRelativeAddress((PVOID)instruction, 3, 7);


            DbgPrint("[3] NtCompareSigningLevels ptr location: %p \n", Globals::funcPtrAddress);
        }
    }

    KIRQL   irql = Utils::disableWP();


    /*  save old address    */
    Globals::oldFuncPtrAddr = *(NtCompareSigningLevelPtr*)Globals::funcPtrAddress;

    *(NtCompareSigningLevelPtr*)Globals::funcPtrAddress = (NtCompareSigningLevelPtr)handler;

    Utils::enableWP(irql);


    return     status;
}






NTSTATUS mapperEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registry_path)
{
    DbgPrint("driver start \n");

    Entry(NULL, NULL);

    return STATUS_SUCCESS;
}