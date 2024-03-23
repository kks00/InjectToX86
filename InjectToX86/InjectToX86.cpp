#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <string>
#include <vector>
#include <iterator>
using namespace std;

DWORD GetProcessID(LPCTSTR ProcessName) {
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

DWORD GetParentProcessID(LPCTSTR ProcessName) {
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ParentProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

void InjectDll(PINT64 pLoadLibraryA, HANDLE hProcess, const char* DllPath) {
	PVOID pPathDll = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pPathDll) {
		WriteProcessMemory(hProcess, pPathDll, DllPath, strlen(DllPath) + 1, NULL);

		DWORD ThreadId;
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pPathDll, 0, &ThreadId);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		VirtualFreeEx(hProcess, pPathDll, 0, MEM_RELEASE);
	}
}

class exportFunction {
public:
	string FunctionName;
	PVOID FunctionAddr;
};

BOOL ListDLLFunctions(void* libraryRaw, vector<exportFunction>& slListOfDllFunctions) {
	BOOL bResult = FALSE;

	slListOfDllFunctions.clear();

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)libraryRaw;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)libraryRaw + pDosHeader->e_lfanew);

	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(libraryRaw, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);
	if (ImageExportDirectory != NULL) {
		DWORD* dNameRVAs(0);
		dNameRVAs = (DWORD*)ImageRvaToVa(pNtHeaders, libraryRaw, ImageExportDirectory->AddressOfNames, NULL);

		DWORD* dAddressRVAs(0);
		dAddressRVAs = (DWORD*)ImageRvaToVa(pNtHeaders, libraryRaw, ImageExportDirectory->AddressOfFunctions, NULL);

		WORD* ord_table(0);
		ord_table = (WORD*)ImageRvaToVa(pNtHeaders, libraryRaw, ImageExportDirectory->AddressOfNameOrdinals, NULL);

		for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++) {
			exportFunction* newObject = new exportFunction();
			newObject->FunctionAddr = (PVOID)dAddressRVAs[ord_table[i]];
			newObject->FunctionName = (char*)ImageRvaToVa(pNtHeaders, libraryRaw, dNameRVAs[i], NULL);
			slListOfDllFunctions.push_back(*newObject);
		}

		bResult = TRUE;
	}

	return bResult;
}

DWORD GetModuleBase(HANDLE hProcess, string sModuleName) {
	DWORD cbNeeded = 0;
	EnumProcessModulesEx(hProcess, NULL, 0, &cbNeeded, LIST_MODULES_32BIT);
	std::vector<HMODULE> hModules(cbNeeded);
	DWORD dwResult = 0;
	if (EnumProcessModulesEx(hProcess, (HMODULE*)&hModules[0], hModules.size() * sizeof(HMODULE), &cbNeeded, LIST_MODULES_32BIT)) {
		hModules.resize(cbNeeded / sizeof(HMODULE));
		for (std::vector<HMODULE>::iterator iter = hModules.begin(); iter != hModules.end(); ++iter) {
			CHAR moduleName[0x128];
			if (GetModuleBaseNameA(hProcess, *iter, moduleName, sizeof(moduleName))) {
				for (int i = 0; i < strlen(moduleName); i++)
					moduleName[i] = tolower(moduleName[i]);
				if (sModuleName.compare(moduleName) == 0) {
					dwResult = (DWORD)*iter;
					break;
				}
			}
		}
	}
	return dwResult;
}

#define KERNEL32PATH "C:\\Windows\\SysWOW64\\kernel32.dll"

int main() {
	PINT64 pLoadLibraryA = NULL;

	HANDLE hFile = CreateFileA(KERNEL32PATH, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	int fileSize = GetFileSize(hFile, NULL);
	void* fileBuf = malloc(fileSize);
	DWORD bytesRead;
	if (ReadFile(hFile, fileBuf, fileSize, &bytesRead, NULL)) {
		vector<exportFunction> exportFunctions;
		if (ListDLLFunctions(fileBuf, exportFunctions)) {
			for (vector<exportFunction>::iterator iter = exportFunctions.begin(); iter != exportFunctions.end(); iter++) {
				if (!strcmp(iter->FunctionName.c_str(), "LoadLibraryA")) {
					pLoadLibraryA = (PINT64)iter->FunctionAddr;
				}
			}
		}
	}
	free(fileBuf);
	CloseHandle(hFile);

	DWORD dwPID = GetProcessID(L"Project1.exe");
	if (dwPID) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

		DWORD hKernel32 = GetModuleBase(hProcess, "kernel32.dll");

		pLoadLibraryA = (PINT64)((INT64)hKernel32 + (INT64)pLoadLibraryA);
		printf("0x%08X\n", pLoadLibraryA);

		//InjectDll(pLoadLibraryA, hProcess, "C:\\Module.dll");

		CloseHandle(hProcess);
	}

	system("pause");
	return 0;
}