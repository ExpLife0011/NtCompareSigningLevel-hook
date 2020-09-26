#pragma once
#include	 "undocumented.h"


struct BYTE_BUFFER
{
    BYTE	data[50];
};



typedef __int64(__fastcall* NtCompareSigningLevelPtr)(DWORD64, DWORD64);



namespace   Globals
{
    NtCompareSigningLevelPtr    funcPtrAddress;
    NtCompareSigningLevelPtr    oldFuncPtrAddr;
    BYTE_BUFFER*                inBufAddress;
    BYTE_BUFFER*                outBufAddress;
    PEPROCESS                   userClient;
}


namespace Utils
{
    PVOID getDriverBaseAddress(OUT PULONG pSize, const char* driverName)
    {
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG Bytes = 0;
        PRTL_PROCESS_MODULES arrayOfModules;


        PVOID			DriverBase = 0;
        ULONG64			DriverSize = 0;


        //get size of system module information
        Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
        if (Bytes == 0)
        {
            DbgPrint("%s: Invalid SystemModuleInformation size\n");
            return NULL;
        }


        arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x45454545); //array of loaded kernel modules
        RtlZeroMemory(arrayOfModules, Bytes); //clean memory


        Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);

        if (NT_SUCCESS(Status))
        {
            PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
            for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
            {
                //list the module names:

                DbgPrint("Image name: %s\n", pMod[i].FullPathName + pMod[i].OffsetToFileName);
                // path name plus some amount of characters will lead to the name itself
                const char* DriverName = (const char*)pMod[i].FullPathName + pMod[i].OffsetToFileName;

                if (strcmp(DriverName, driverName) == 0)
                {
                    DbgPrint("found driver\n");


                    DriverBase = pMod[i].ImageBase;
                    DriverSize = pMod[i].ImageSize;

                    DbgPrint("kernel module Size : %i\n", DriverSize);
                    DbgPrint("kernel module Base : %p\n", DriverBase);


                    if (arrayOfModules)
                        ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'


                    if (pSize != NULL)
                    {
                        *pSize = DriverSize;
                    }

                    return DriverBase;
                }
            }
        }
        if (arrayOfModules)
            ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'


        if (pSize != NULL)
        {
            *pSize = DriverSize;
        }
        return (PVOID)DriverBase;
    }



    PVOID64     findPattern(BYTE* pattern, int patternSize, BYTE    wildCard, ULONG64 startAddress, ULONG64   endAddress)
    {
        bool found = false;

        if (!MmIsAddressValid((PVOID)startAddress))
        {
            return 0;
        }

        for (BYTE* i = (BYTE*)startAddress; i < (BYTE*)(endAddress - patternSize); ++i)
        {
            found = true;

            for (int j = 0; j < patternSize; ++j)
            {
                if ((pattern[j] != i[j]) && (pattern[j] != wildCard))
                {
                    found = false;
                    break;
                }
            }
            if (found == true)
            {
                return (PVOID64)i;
            }
        }

        return 0;
    }


    PVOID GetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
    {
        ASSERT(pProcess != NULL);
        if (pProcess == NULL)
            return NULL;


            LARGE_INTEGER time = { 0 };
            time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

            // Wow64 process
            if (isWow64)
            {
                PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
                if (pPeb32 == NULL)
                {
                    return NULL;
                }

                // Wait for loader a bit
                for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
                {
                    KeDelayExecutionThread(KernelMode, TRUE, &time);
                }

                // Still no loader
                if (!pPeb32->Ldr)
                {
                    return NULL;
                }

                // Search in InLoadOrderModuleList
                for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
                    pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
                    pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
                {
                    UNICODE_STRING ustr;
                    PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

                    RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

                    if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
                        return (PVOID)pEntry->DllBase;
                }
            }
            // Native process
            else
            {
                PPEB pPeb = PsGetProcessPeb(pProcess);
                if (!pPeb)
                {
                    return NULL;
                }

                // Wait for loader a bit
                for (INT i = 0; !pPeb->Ldr && i < 10; i++)
                {
                    KeDelayExecutionThread(KernelMode, TRUE, &time);
                }

                // Still no loader
                if (!pPeb->Ldr)
                {
                    return NULL;
                }

                // Search in InLoadOrderModuleList
                for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
                    pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
                    pListEntry = pListEntry->Flink)
                {
                    PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
                        return pEntry->DllBase;
                }
            }
        


        return NULL;
    }

    KIRQL disableWP()
    {
        KIRQL	tempirql = KeRaiseIrqlToDpcLevel();

        ULONG64  cr0 = __readcr0();

        cr0 &= 0xfffffffffffeffff;

        __writecr0(cr0);

        _disable();

        return tempirql;

    }


    void enableWP(KIRQL		tempirql)
    {
        ULONG64	cr0 = __readcr0();

        cr0 |= 0x10000;

        _enable();

        __writecr0(cr0);

        KeLowerIrql(tempirql);
    }


    VOID	WriteMemory(ULONG64 address, PVOID buffer, SIZE_T size, PEPROCESS process)
    {

        KAPC_STATE  apc_state;
        KeStackAttachProcess(process, &apc_state);
        if (MmIsAddressValid((PVOID)address) && MmIsAddressValid((PVOID)(address + size)))
        {
            KIRQL   tempirql = disableWP();

            RtlCopyMemory((PVOID64)address, buffer, size);

            enableWP(tempirql);
        }
        KeUnstackDetachProcess(&apc_state);

    }
    VOID	ReadMemory(ULONG64 address, SIZE_T size, PVOID outBuffer, PEPROCESS process)
    {
        KAPC_STATE  apc_state;

        KeStackAttachProcess(process, &apc_state);


        if (MmIsAddressValid((PVOID64)address) && MmIsAddressValid((PVOID64)(address + size)))
        {
            RtlCopyMemory(outBuffer, (PVOID64)address, size);
        }

        KeUnstackDetachProcess(&apc_state);

        return;
    }

    NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
    {
        ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
        if (ppFound == NULL || pattern == NULL || base == NULL)
            return STATUS_INVALID_PARAMETER;

        for (ULONG_PTR i = 0; i < size - len; i++)
        {
            BOOLEAN found = TRUE;
            for (ULONG_PTR j = 0; j < len; j++)
            {
                if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
                {
                    found = FALSE;
                    break;
                }
            }

            if (found != FALSE)
            {
                *ppFound = (PUCHAR)base + i;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }



    NTSTATUS BBScan(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
    {

        //ASSERT(ppFound != NULL);
        if (ppFound == NULL)
            return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

        if (nullptr == base)
            base = Utils::getDriverBaseAddress(NULL, "ntoskrnl.exe");
        if (base == nullptr)
            return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

        PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
        if (!pHdr)
            return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

        //PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
        PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

        PVOID ptr = NULL;

        for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
        {

            ANSI_STRING s1, s2;
            RtlInitAnsiString(&s1, section);
            RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
            if (((RtlCompareString(&s1, &s2, TRUE) == 0) || (pSection->Characteristics & IMAGE_SCN_CNT_CODE) || (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)))
            {
                NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
                if (NT_SUCCESS(status)) {
                    *(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
                    DbgPrint("found\r\n");
                    return status;
                }
                //we continue scanning because there can be multiple sections with the same name.
            }
        }

        return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
    }


    PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
    {
        ULONG_PTR Instr = (ULONG_PTR)Instruction;
        LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
        PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

        return ResolvedAddr;
    }



    PVOID		getUserModuleBase(int processId)
    {
        wchar_t			moduleName[24];
        UNICODE_STRING	uModuleNmae;


        KAPC_STATE	apc;
        KeStackAttachProcess(Globals::userClient, &apc);

        wcscpy(moduleName, (wchar_t*)Globals::inBufAddress);

        KeUnstackDetachProcess(&apc);




        RtlInitUnicodeString(&uModuleNmae, moduleName);

        PEPROCESS	process;
        PsLookupProcessByProcessId((HANDLE)processId, &process);


        BOOLEAN		isWow64 = (PsGetProcessWow64Process(process) != NULL) ? TRUE : FALSE;

        KeStackAttachProcess(process, &apc);

        PVOID	moduleBase = Utils::GetUserModule(process, &uModuleNmae, isWow64);

        KeUnstackDetachProcess(&apc);



        return moduleBase;
    }

    
}