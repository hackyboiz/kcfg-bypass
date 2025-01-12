#pragma once

#include <Windows.h>
#include <stdint.h>


#define ObjectThreadType 0x08

/////////////// SystemModuleInformation ///////////////

typedef struct _SYSTEM_MODULE {
    ULONG Reserved1;
    ULONG Reserved2;
    ULONG REserved3;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG flags;
    WORD Id;
    WORD Rank;
    WORD LoadCound;
    WORD NameOffset;
    CHAR Name[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYTEM_MODULE_INFORMATION {
    ULONG   ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


/////////////// SystemHandleInformation, SystemExtendedHandleInformation ///////////////

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;


typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;


////////////// NtQuerySystemInformation ///////////////


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 0xb,
    SystemExtendedProcessInformation = 0x39,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 0x40,
    SystemBigPoolInformation = 0x42,
    SystemNonPagedPoolInformation = 0x0f
} SYSTEM_INFORMATION_CLASS, * PSYSETM_INFORMATION_CLASS;


typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformaton,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );



///////////////// NtFsControlFile ///////////////

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef NTSTATUS(WINAPI* _NtFsControlFile)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            FsControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
    );




/////// NtRead/Write Virtual Memory

typedef struct _MY_IRP
{
    uint64_t Type;
    PVOID CurrentProcId;
    uint64_t Flags;
    HANDLE hEvent;
    uint64_t val20;
    uint64_t val24;
    uint64_t val28;
    uint64_t val30;
    uint64_t val38;
    uint64_t val40;
    uint64_t val48;
    uint64_t val50;
    uint64_t val58;
    uint64_t val60;
    uint64_t val68;
    uint64_t val70;
    uint64_t val78;
    uint64_t val80;
    uint64_t val88;
    uint64_t val90;
    uint64_t val98;
    uint64_t valA0;
    uint64_t valA8;
    uint64_t valB0;
} MY_IRP;


typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToWrite,
    _Out_opt_ PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(WINAPI* _NtReadVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToRead,
    _Out_opt_ PULONG NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* _NtDeviceIoControlFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
    );