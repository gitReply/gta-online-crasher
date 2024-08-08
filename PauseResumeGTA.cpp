#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <locale> 

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Ошибка при создании снимка процессов." << std::endl;
        return 0;
    }

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processName == processEntry.szExeFile) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    std::wcerr << L"Процесс " << processName << L" не найден." << std::endl;
    return 0;
}

void SuspendProcess(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
    if (process == NULL) {
        std::wcerr << L"Не удалось открыть процесс." << std::endl;
        return;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Ошибка при создании снимка потоков." << std::endl;
        CloseHandle(process);
        return;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                if (thread != NULL) {
                    SuspendThread(thread);
                    CloseHandle(thread);
                }
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
    CloseHandle(process);
    std::wcout << L"Процесс приостановлен." << std::endl;
}

void ResumeProcess(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
    if (process == NULL) {
        std::wcerr << L"Не удалось открыть процесс." << std::endl;
        return;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Ошибка при создании снимка потоков." << std::endl;
        CloseHandle(process);
        return;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                if (thread != NULL) {
                    ResumeThread(thread);
                    CloseHandle(thread);
                }
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
    CloseHandle(process);
    std::wcout << L"Процесс возобновлен." << std::endl;
}

int main() {
    std::locale::global(std::locale(""));

    std::wstring processName = L"GTA5.exe";

    DWORD processId = FindProcessId(processName);
    if (processId == 0) {
        std::wcerr << L"Не удалось найти процесс " << processName << std::endl;
        return 1;
    }

    std::wcout << L"Найден процесс " << processName << L" с PID: " << processId << std::endl;

    SuspendProcess(processId);
    Sleep(12000);
    ResumeProcess(processId);

    return 0;
}
