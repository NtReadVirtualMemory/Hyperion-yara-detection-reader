#include <Windows.h>
#include <TlHelp32.h>

HANDLE pHandle;
DWORD pid;

template <typename T>
T Read(uintptr_t address) {
	T buffer{};
	SIZE_T bytesRead;

	if (ReadProcessMemory(pHandle, (LPCVOID)address, &buffer, sizeof(T), &bytesRead) && bytesRead == sizeof(T)) {
		return buffer;
	}

	return T();
}

DWORD GetPID(const char* processName) {
	HWND hwnd = FindWindowA(NULL, processName);
	if (hwnd) {
		DWORD pid;
		GetWindowThreadProcessId(hwnd, &pid);
		return pid;
	}

	return 0;
}

uintptr_t GetModuleBaseAddress(const char* moduleName) {
	uintptr_t baseAddress = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(snapshot, &moduleEntry)) {
		do {
			if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
				return (uintptr_t)(moduleEntry.modBaseAddr);
			}
		} while (Module32Next(snapshot, &moduleEntry));
	}

	CloseHandle(snapshot);
	return 0;
}