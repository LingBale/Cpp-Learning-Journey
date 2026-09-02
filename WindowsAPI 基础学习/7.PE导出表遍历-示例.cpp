#include <windows.h>
#include <iostream>
#include <iomanip>

int main() {
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\kernel32.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "打开文件失败" << std::endl;
        return 1;
    }
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 1;
    }
    char* pBase = (char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }
    // ① DOS 头
    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
    // ② NT 头
    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
    // ③ 从 NT 头的可选头里，取第 0 号目录项（即“导出表”）
    IMAGE_DATA_DIRECTORY exportDir = pNt->OptionalHeader.DataDirectory[0];
    // ④ 把“藏宝图”里的偏移量加上基址，跳到真正的导出表
    IMAGE_EXPORT_DIRECTORY* pExport = (IMAGE_EXPORT_DIRECTORY*)(pBase + exportDir.VirtualAddress);

    // 纸条 1：函数名列表的起始偏移（指向一堆字符串）
    DWORD* nameArrayRVA = (DWORD*)(pBase + pExport->AddressOfNames);
    // 纸条 2：函数地址列表的起始偏移（指向一堆 4 字节数字）
    DWORD* funcArrayRVA = (DWORD*)(pBase + pExport->AddressOfFunctions);
    // 纸条 3：序号列表的起始偏移（指向一堆 2 字节数字）
    WORD* ordinalArray = (WORD*)(pBase + pExport->AddressOfNameOrdinals);
    // 总共导出了多少个名字（循环用这个数）
    DWORD nameCount = pExport->NumberOfNames;

    std::cout << "总导出函数名数量: " << nameCount << std::endl;
    std::cout << "前 10 个导出函数名:" << std::endl;

    // 遍历公告栏上的名字列表（只打印前 10 个，避免刷屏）
    for (DWORD i = 0; i < 10 && i < nameCount; i++) {
        // ① 取第 i 个名字的 RVA（它是数字，指向真正的字符串）
        DWORD nameRVA = nameArrayRVA[i];
        // ② 用基址 + RVA，定位到字符串所在的 ImHex 地址，然后把它当成 char* 打印
        char* funcName = (char*)(pBase + nameRVA);
        // ③ 取第 i 个函数地址（通过序号数组找到对应的函数 RVA）
        WORD ordinal = ordinalArray[i];
        DWORD funcRVA = funcArrayRVA[ordinal];
        // 打印结果
        std::cout << "[" << i << "] 名称: " << funcName 
                  << " | RVA: 0x" << std::hex << funcRVA << std::dec << std::endl;
    }

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    system("pause");
    return 0;
}