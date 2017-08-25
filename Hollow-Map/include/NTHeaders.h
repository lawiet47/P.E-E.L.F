#include <Windows.h>
//Structures that are defined in ntdef.h
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//for unmapping the original section
typedef NTSTATUS(__stdcall* __T_NtUnmapViewOfSection)(
	_In_ HANDLE,
	_In_opt_ PVOID
);

//for mapping a section to a remote process
typedef NTSTATUS(__stdcall* __T_NtMapViewOfSection)(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        DWORD			InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);

//for creating a new section
typedef NTSTATUS(__stdcall* __T_NtCreateSection)(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);
//for closing section handles
typedef NTSTATUS(__stdcall* __T_NtClose)(
	_In_ HANDLE Handle
);

//Custom Structure needed for holding the contents of the process to be injected
typedef struct _payload {
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER secHeader;
	CONTEXT ctx;
	LPVOID pImageBase;
} PAYLOAD, *PPAYLOAD;
