#include    "commands.h"




int main()
{
    HMODULE  hModule = LoadLibrary(L"ntdll.dll");

    NtCompareSigningLevels = (pFnNtCompareSigningLevels)GetProcAddress(hModule, "NtCompareSigningLevels");


    globals::InBuffer.buf = new BYTE_BUFFER;
    globals::OutBuffer.buf = new BYTE_BUFFER;



    Driver::startConnection();
    Driver::clearTraces();


    int        processID = utils::FindProcessId(L"ac_client.exe");
    DWORD64    baseAddress = Driver::getModuleBase(L"ac_client.exe", processID);


    cout << "base address is: " << std::hex << baseAddress << endl;


    DWORD64    localPlayer = Driver::Read<int>(processID, 4, (baseAddress + offset::localplayer));
    DWORD64    health = Driver::Read<int>(processID, 4, (localPlayer + offset::health));


    cout << "current health is: " << std::dec << health << endl;



    int newHealth = 19991;
    Driver::Write<int>(processID, 4, (localPlayer + offset::health), &newHealth);


    Driver::test();

    cin.get();

    return 0;
}