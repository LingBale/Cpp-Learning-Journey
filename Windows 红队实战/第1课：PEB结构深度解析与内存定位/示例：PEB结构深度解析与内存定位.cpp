#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

// 手动定义 UNICODE_STRING
typedef struct _UNICODE_STRING {
    USHORT Length;          // 字符串长度（字节数）
    USHORT MaximumLength;   // 缓冲区大小
    PWSTR  Buffer;          // 宽字符串指针
} UNICODE_STRING;

// 自定义 LDR_DATA_TABLE_ENTRY，只保留课程需要的字段
// 注意：偏移量基于 Windows 10/11 x64（其他系统需调整）
struct MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;          // 0x00
    LIST_ENTRY InMemoryOrderLinks;        // 0x10  ← 我们遍历的链表节点
    LIST_ENTRY InInitializationOrderLinks;// 0x20
    PVOID DllBase;                        // 0x30  模块基址
    PVOID EntryPoint;                     // 0x38
    ULONG SizeOfImage;                    // 0x40
    UNICODE_STRING FullDllName;           // 0x48  完整路径
    UNICODE_STRING BaseDllName;           // 0x58  文件名（不含路径）
    // 后续字段省略（不影响本示例）
};

int main() {
    // 1. 获取 PEB 地址（x64 使用 gs 段寄存器）
    uintptr_t pPeb = __readgsqword(0x60);

    // 2. 获取 Ldr 结构指针（PEB 偏移 0x18）
    uintptr_t pLdr = *(uintptr_t*)(pPeb + 0x18);

    // 3. 获取 InMemoryOrderModuleList 链表头（Ldr 偏移 0x20）
    LIST_ENTRY* pListHead = (LIST_ENTRY*)(pLdr + 0x20);
    LIST_ENTRY* pEntry = pListHead->Flink;   // 第一个节点

    // 4. 遍历链表
    while (pEntry != pListHead) {
        // 5. 使用 CONTAINING_RECORD 宏反推结构体首地址
        //    该宏由 windows.h 提供，计算方式：address - offsetof(field)
        MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(
            pEntry,
            MY_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        // 6. 读取模块基址和文件名
        uintptr_t dllBase = (uintptr_t)pModule->DllBase;
        if (dllBase == 0) {
            pEntry = pEntry->Flink;
            continue;
        }

        UNICODE_STRING* pName = &pModule->BaseDllName;
        if (pName->Buffer && pName->Length > 0) {
            std::wstring dllName(pName->Buffer, pName->Length / 2);
            // 不区分大小写比较，找到 kernel32 和 ntdll
            if (_wcsicmp(dllName.c_str(), L"kernel32.dll") == 0) {
                std::cout << "[+] kernel32.dll 基址: 0x"
                          << std::hex << dllBase << std::dec << std::endl;
            } else if (_wcsicmp(dllName.c_str(), L"ntdll.dll") == 0) {
                std::cout << "[+] ntdll.dll 基址: 0x"
                          << std::hex << dllBase << std::dec << std::endl;
            }
        }

        // 移到下一个节点
        pEntry = pEntry->Flink;
    }

    return 0;
}
