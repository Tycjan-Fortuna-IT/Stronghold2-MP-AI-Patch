#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <print>
#include <source_location>
#include <vector>
#include <windows.h>

#include <tlhelp32.h>

void Verify(bool condition, std::string_view message, const std::source_location& location = std::source_location::current())
{
	if (!condition)
	{
		std::println(std::cerr,
		             "[ASSERTION FAILED]\n"
		             "  Condition   : false\n"
		             "  Message     : {}\n"
		             "  File        : {}\n"
		             "  Function    : {}\n"
		             "  Line        : {}\n",
		             message, location.file_name(), location.function_name(), location.line());

		std::cout << "Press any key to exit...";
		std::cin.get();

		std::exit(EXIT_FAILURE);
	}
}

bool EnableDebugPriv()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	Verify(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken), "Failed to open process token");

	LUID luid;
	Verify(LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid), "Failed to lookup SE_DEBUG_NAME");

	tkp.PrivilegeCount           = 1;
	tkp.Privileges[0].Luid       = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	Verify(AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr), "Failed to adjust token privileges");

	DWORD err = GetLastError();
	CloseHandle(hToken);

	if (err == ERROR_NOT_ALL_ASSIGNED)
	{
		std::println(std::cerr, "SeDebugPrivilege not granted. Run as administrator.");
		return false;
	}

	return true;
}

bool TryGetProcessIdByName(std::string_view processName, DWORD& processId)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Verify(hSnapshot != INVALID_HANDLE_VALUE, "Failed to create snapshot of processes");

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32))
	{
		CloseHandle(hSnapshot);
		return false;
	}

	do
	{
		if (processName == pe32.szExeFile)
		{
			processId = pe32.th32ProcessID;

			CloseHandle(hSnapshot);

			return true;
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);

	return false;
}

using MemoryAddress                            = DWORD;
constexpr MemoryAddress INVALID_MEMORY_ADDRESS = -1;

MemoryAddress FindBytePatternInHandleMemory(HANDLE hProc, const char* bMask, const char* szMask)
{
	const SIZE_T bufferSize = 4096; // 4KB chunks
	std::vector<BYTE> buffer(bufferSize);
	SIZE_T dwMaskLen = strlen(szMask);

	if (dwMaskLen == 0)
		return INVALID_MEMORY_ADDRESS;

	MODULEENTRY32 lpme = {sizeof(MODULEENTRY32)};
	HANDLE hSnap       = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProc));
	if (hSnap == INVALID_HANDLE_VALUE)
		return INVALID_MEMORY_ADDRESS;

	if (!Module32First(hSnap, &lpme))
	{
		CloseHandle(hSnap);
		return -1;
	}
	DWORD dwMainModStart = reinterpret_cast<DWORD>(lpme.modBaseAddr);
	DWORD dwMainModLen   = lpme.modBaseSize;
	CloseHandle(hSnap);

	MEMORY_BASIC_INFORMATION mbi;
	DWORD dwCurAddress = dwMainModStart;

	while (dwCurAddress < dwMainModStart + dwMainModLen && VirtualQueryEx(hProc, (LPCVOID)dwCurAddress, &mbi, sizeof(mbi)))
	{
		// Skip non-readable or non-committed regions
		if (mbi.State != MEM_COMMIT || mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
		{
			dwCurAddress += mbi.RegionSize;
			continue;
		}

		SIZE_T regionEnd = min(dwCurAddress + mbi.RegionSize, dwMainModStart + dwMainModLen);
		while (dwCurAddress < regionEnd)
		{
			SIZE_T bytesToRead = min(bufferSize, regionEnd - dwCurAddress);
			SIZE_T bytesRead;

			if (!ReadProcessMemory(hProc, (LPCVOID)dwCurAddress, buffer.data(), bytesToRead, &bytesRead))
			{
				dwCurAddress += (DWORD)bytesToRead;
				continue;
			}

			for (SIZE_T i = 0; i <= bytesRead - dwMaskLen; ++i)
			{
				bool found = true;
				for (SIZE_T j = 0; j < dwMaskLen; ++j)
				{
					if (szMask[j] != '?' && buffer[i + j] != (BYTE)bMask[j])
					{
						found = false;
						break;
					}
				}
				if (found)
				{
					return dwCurAddress + i;
				}
			}
			dwCurAddress += bytesRead;
		}
	}

	return INVALID_MEMORY_ADDRESS;
}

const char* g_ProcessName           = "Stronghold2.exe";
const char* g_AIDisableSignature_MP = "\xC6\x86\x28\x0D\x00\x00\x00"; // Byte pattern for MP AI Disable function
const char* g_AIDisableMask_MP      = "xxxx???";                      // Corresponding mask for the signature

int main()
{
	Verify(EnableDebugPriv(), "Could not enable debug privileges");

	DWORD processId;
	Verify(TryGetProcessIdByName(g_ProcessName, processId), "Failed to find process ID for Stronghold2.exe");

	std::println("Found process ID: {}", processId);

	const HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

	const MemoryAddress patternAddress = FindBytePatternInHandleMemory(hProc, g_AIDisableSignature_MP, g_AIDisableMask_MP);

	if (patternAddress == INVALID_MEMORY_ADDRESS)
	{
		CloseHandle(hProc);

		Verify(false, "Failed to find byte pattern in process memory");

		return 1;
	}

	std::println("Found byte pattern at address: 0x{:X}", patternAddress);

	std::println("Patching the process memory...");

	const std::array<BYTE, 7> patch = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}; // NOP instructions, 7 bytes

	Verify(WriteProcessMemory(hProc, (LPVOID)patternAddress, patch.data(), patch.size(), nullptr), "Failed to write process memory");

	std::cout << "Press any key to exit...";
	std::cin.get();

	return 0;
}
