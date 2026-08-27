#include <windows.h>
#include <iostream>
#include <iomanip>

int main(){
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\notepad.exe", 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        std::cerr << "打开文件失败，错误码：" << GetLastError() << std::endl;
        return 1;
    }
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if(!hMapping){
        std::cerr << "创建映射失败，错误码：" << GetLastError() << std::endl;
        CloseHandle(hFile);
        return 1; 
    }
    char* pBase = (char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if(!pBase){
        std::cout << "映射识图失败，错误码：" << GetLastError() << std::endl;
        CloseHandle(hMapping);
        CloseHandle(hFile);
    }

    std::cout << std::hex << std::setfill('0');

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pBase;
    std::cout << "[1] DOS签名：0x" << std::setw(4) << pDos-> e_magic << std::endl;
    std::cout << "[2] NT头偏移：0x" << std::setw(8) << pDos -> e_lfanew << std::endl;

    IMAGE_NT_HEADERS64* pNt = (IMAGE_NT_HEADERS64*)pBase;
    std::cout << "[3] PE签名：0x" << std::setw(8) << pNt -> Signature << std::endl;
    std::cout << "[4] 入口点RAV：0x" << std::setw(8) << pNt -> OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "[5] 镜像基址：0x" << std::setw(16) << pNt -> OptionalHeader.ImageBase << std::endl;

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    system("pause");
}
