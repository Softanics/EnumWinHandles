#include <ntstatus.h>
#include <windows.h>
#include <iostream>
#include <vector>

struct UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
};

struct OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
};

struct SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
};

int main()
{
    typedef DWORD SYSTEM_INFORMATION_CLASS;

    const DWORD SystemHandleInformation = 0x10;

    typedef NTSTATUS (__stdcall *P_NtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    P_NtQuerySystemInformation ntQuerySystemInformation =
        (P_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    typedef DWORD OBJECT_INFORMATION_CLASS;

    typedef NTSTATUS (__stdcall* P_NtQueryObject)(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength);

    P_NtQueryObject ntQueryObject =
        (P_NtQueryObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");

    std::vector<char> systemHandleInformationBuffer(0x10000);

    while (true)
    {
        ULONG returnLength;

        auto const status = ntQuerySystemInformation(
            SystemHandleInformation,
            &systemHandleInformationBuffer[0],
            (ULONG)systemHandleInformationBuffer.size(),
            &returnLength);

        if (STATUS_INFO_LENGTH_MISMATCH == status)
        {
            systemHandleInformationBuffer.resize(systemHandleInformationBuffer.size() + 0x10000);
            continue;
        }
        else if (STATUS_SUCCESS == status)
        {
            break;
        }
        else
        {
            std::cerr << "ntQuerySystemInformation() failed, status = " << std::hex << status << std::endl;
            return status;
        }
    };

    auto const handleTable = (SYSTEM_HANDLE_INFORMATION*)&systemHandleInformationBuffer[0];
    auto handleInfo = &handleTable->Handles[0];

    DWORD handleCount = 0;
    for (DWORD i = 0; i < handleTable->NumberOfHandles; i++, handleInfo++)
    {
        if (GetCurrentProcessId() == handleInfo->ProcessId)
        {
            handleCount++;

            char buffer[0x1000]{};
            OBJECT_TYPE_INFORMATION* objectTypeInformation = (OBJECT_TYPE_INFORMATION*)&buffer[0];
            ULONG returnLength;

            if (STATUS_SUCCESS == ntQueryObject(
                (HANDLE)handleInfo->Handle,
                2, // ObjectTypeInformation
                objectTypeInformation,
                (ULONG)sizeof(buffer),
                &returnLength))
            {
                std::wcout << L"Handle (" << objectTypeInformation->TypeName.Buffer << L"): " << std::hex << handleInfo->Handle << std::endl;
            }
        }
    }

    std::cout << "Total: " << std::dec << handleCount << std::endl;
}
