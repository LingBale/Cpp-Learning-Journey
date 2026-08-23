#include <windows.h>
#include <cstring>

int main(){
    SIZE_T ShellCodeSize = 4096;
    char* p = (char*)VirtualAlloc(NULL, ShellCodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    unsigned char ShellCode[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,
        0xC3
    };
    memcpy(p, ShellCode, sizeof(ShellCode));
    DWORD oldIts{};
    VirtualProtect(
        p,
        ShellCodeSize,
        PAGE_EXECUTE_READ,
        &oldIts
    );
    void (*fuk)() = (void(*)())p;
    fuk();
    VirtualFree(p, 0 , MEM_RELEASE);
}