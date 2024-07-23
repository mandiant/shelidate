// Copyright 2024 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <winternl.h>
#include <WinSock2.h>

#pragma comment (lib, "Ws2_32.lib")

// Dependency Loading
typedef PVOID(WINAPI* FnGetProcAddress)(HMODULE mod, char* apiName);
typedef HMODULE(WINAPI* FnLoadLibraryA)(char* moduleName);
typedef HMODULE(WINAPI* FnGetModuleHandleA)(LPCSTR lpModuleName);
typedef void(WINAPI* FnSleep)(DWORD dwMilliseconds);
typedef void(WINAPI* FnExitProcess)(UINT uExitCode);
// sockets
typedef int(WINAPI* FnWSAStartup)(WORD wVersionRequired, LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* FnWSASocketA)(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags);
typedef int(WSAAPI* FnConnect)(SOCKET s, const SOCKADDR* name, int namelen);
typedef int(WSAAPI* FnSend)(SOCKET s, const char* buf, int len, int flags);
typedef int(WSAAPI* FnCloseSocket)(SOCKET s);

DWORD entry(int port, unsigned long host, int nonce);
PPEB GetPEB();
PVOID GetKernel32DLL(PPEB ppeb);
HMODULE MemGetProcAddress(PVOID pModule, PCSTR funcName);

DWORD entry(int port, unsigned long host, int nonce) {
    PVOID kernel32 = NULL;
    FnLoadLibraryA myLoadLibrary = NULL;
    FnGetProcAddress myGetProcAddress = NULL;
    FnSleep mySleep = NULL;
    FnExitProcess myExitProcess = NULL;

    FnWSAStartup myWSAStartup = NULL;
    FnWSASocketA myWSASocketA = NULL;
    FnConnect myConnect = NULL;
    FnSend mySend = NULL;
    FnCloseSocket myClose = NULL;

    WSADATA wsaData;
    SOCKET soc;
    struct sockaddr_in remote;

    char kernel32Str[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
    char loadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    char getProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    char sleep[] = { 'S', 'l', 'e', 'e', 'p', 0 };
    char exitProcess[] = { 'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };

    char ws2_32dll[] = { 'W', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };
    char wsaStartup[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', 0 };
    char wsaSocketA[] = { 'W', 'S', 'A', 'S', 'o', 'c', 'k', 'e', 't', 'A', 0 };
    char connect[] = { 'c', 'o', 'n', 'n', 'e', 'c', 't', 0 };
    char send[] = { 's', 'e', 'n', 'd', 0 };
    char close[] = { 'c', 'l', 'o', 's', 'e', 's', 'o', 'c', 'k', 'e', 't', 0 };

    kernel32 =  GetKernel32DLL(GetPEB());

    myGetProcAddress = (FnGetProcAddress)MemGetProcAddress(kernel32, getProcAddress);
    myLoadLibrary = (FnLoadLibraryA)myGetProcAddress(kernel32, loadLibrary);

    if (myLoadLibrary == NULL || myGetProcAddress == NULL) {
        return 0;
    }

    mySleep = (FnSleep)myGetProcAddress(kernel32, sleep);
    myExitProcess = (FnExitProcess)myGetProcAddress(kernel32, exitProcess);

    HMODULE winsock = myLoadLibrary(ws2_32dll);
    if (!winsock) {
        myExitProcess(2);
    }

    myWSAStartup = (FnWSAStartup)myGetProcAddress(winsock, wsaStartup);
    myWSASocketA = (FnWSASocketA)myGetProcAddress(winsock, wsaSocketA);
    myConnect = (FnConnect)myGetProcAddress(winsock, connect);
    mySend = (FnSend)myGetProcAddress(winsock, send);
    myClose = (FnCloseSocket)myGetProcAddress(winsock, close);

    if (myWSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        myExitProcess(3);
    }

    soc = myWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (soc == INVALID_SOCKET) {
        myExitProcess(4);
    }

    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = host;
    remote.sin_port = port;

    if (myConnect(soc, (SOCKADDR*)&remote, sizeof(remote))) {
        myExitProcess(5);
    }

    if (mySend(soc, (char*)&nonce, sizeof(int), 0) == SOCKET_ERROR) {
        myExitProcess(6);
    }

    // sleep for 100 milliseconds, so we know the send is going to complete
    mySleep(100);

    myClose(soc);

    myExitProcess(0);
	
    return 0;
}

PPEB GetPEB() {
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#else 
    return (PPEB)__readfsdword(0x30);
#endif
}

wchar_t* mywcsistr(wchar_t* string, wchar_t* substring)
{
    wchar_t* a;
    wchar_t* b;

    if (*substring == 0)
    {
        return string;
    }

    while (*string != 0)
    {
        b = substring;

        if (*string != *b && *string != (*b ^ 0x20))
        {
            *string++;
            continue;
        }
        a = string;

        while (*b != 0)
        {
            if (*a != *b && *a != (*b ^ 0x20))
            {
                break;
            }

            *a++;
            *b++;

            if (*b == 0)
            {
                return string;
            }
        }

        *string++;
    }
    return NULL;
}

int mystrcmp(const char* string1, const char* string2)
{

    while(*string1 != 0 && (*string1 == *string2)) {
        string1++;
        string2++;
    }

    return *string1 - *string2;
}

PVOID GetKernel32DLL(PPEB ppeb) {
    wchar_t kernel32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', 0 };
    PPEB_LDR_DATA pLdr = ppeb->Ldr;

    PLIST_ENTRY pNextModule = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurEntry = pNextModule->Flink;
    PLDR_DATA_TABLE_ENTRY pDataTableEntry = CONTAINING_RECORD(pCurEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    do {
        if (mywcsistr(pDataTableEntry->FullDllName.Buffer, kernel32) != NULL) {
            return pDataTableEntry->DllBase;
        }
        pNextModule = &(pDataTableEntry->InMemoryOrderLinks);
        pCurEntry = pNextModule->Flink;
        pDataTableEntry = CONTAINING_RECORD(pCurEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    } while (pDataTableEntry->DllBase != NULL);
    return NULL;
}

HMODULE MemGetProcAddress(PVOID pModule, PCSTR funcName) {
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
    DWORD dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (dwExportDirRVA != 0) {
        PIMAGE_EXPORT_DIRECTORY pExportsDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)pModule) + dwExportDirRVA);
        PDWORD pdwNameBase = (PDWORD)((ULONG_PTR)pModule + pExportsDir->AddressOfNames);
        PWORD pdwOrdinalBase = (PWORD)((ULONG_PTR)pModule + pExportsDir->AddressOfNameOrdinals);
        PDWORD pdwFunctionBase = (PDWORD)((ULONG_PTR)pModule + pExportsDir->AddressOfFunctions);
        for (int i = 0; i < pExportsDir->NumberOfFunctions; i++) {
            PCSTR pFunctionName = (PCSTR)(*pdwNameBase + (ULONG_PTR)pModule);
            if (!mystrcmp(funcName, pFunctionName)) {
                return (HMODULE)((ULONG_PTR)pModule + *((PDWORD)(pdwFunctionBase + *pdwOrdinalBase)));
            }
            pdwOrdinalBase++;
            pdwNameBase++;
        }
    }
    return NULL;
}

