# InjectToX86

- ### x64 프로세스에서 x86 프로세스에 DLL을 주입하고자 할 때 x86 KERNEL32.dll.LoadLibraryA의 주소를 GetProcAddress로 가져올 수 없음.

- ### 이를 해결하기 위하여 x86 KERNEL32.dll의 Export Table을 읽어 LoadLibraryA의 RVA를 얻은 다음, 프로세스에 주입된 kernel32.dll의 베이스 주소를 더하는 식으로 LoadLibraryA의 주소를 구함.

    ![image](https://github.com/kks00/InjectToX86/assets/68108664/f01cafbd-9c37-4db0-b81d-2bbe07534bd2)

<br>

- ### 메인함수 일부
    ```c++
    PINT64 pLoadLibraryA = NULL;

	HANDLE hFile = CreateFileA(KERNEL32PATH, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	int fileSize = GetFileSize(hFile, NULL);
	void* fileBuf = malloc(fileSize);
	DWORD bytesRead;
	if (ReadFile(hFile, fileBuf, fileSize, &bytesRead, NULL)) {
		vector<exportFunction> exportFunctions;
		if (ListDLLFunctions(fileBuf, exportFunctions)) {
			for (vector<exportFunction>::iterator iter = exportFunctions.begin(); iter != exportFunctions.end(); iter++) {
				if (!strcmp(iter->FunctionName.c_str(), "LoadLibraryA")) { // Export Name이 LoadLibraryA와 일치할 시
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

		DWORD hKernel32 = GetModuleBase(hProcess, "kernel32.dll"); // x86 프로세스의 kernel32.dll Module의 Base주소 구하기

		pLoadLibraryA = (PINT64)((INT64)hKernel32 + (INT64)pLoadLibraryA); // 더하여 x86 kernel32.LoadLibraryA의 주소를 구함
		printf("0x%08X\n", pLoadLibraryA);

		CloseHandle(hProcess);
	}
    ```