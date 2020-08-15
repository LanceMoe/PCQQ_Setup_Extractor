#include "utils.h"

using namespace std;

// 参考 https://blog.csdn.net/HeroNeverDie/article/details/78990616

// 根据内存偏移地址RVA得到文件偏移地址
DWORD RvaToOffset(PIMAGE_NT_HEADERS pNtHeader, DWORD rva)
{
    // PE节
    IMAGE_SECTION_HEADER* p_Section_Header;
    // 获得Pe节数目
    DWORD sectionSum = pNtHeader->FileHeader.NumberOfSections;
    // 第一个节表项
    p_Section_Header = (IMAGE_SECTION_HEADER*)((DWORD)pNtHeader + (DWORD)sizeof(IMAGE_NT_HEADERS));
    for (size_t i = 0; i < sectionSum; i++)
    {
        // printf_s("%s\n", p_Section_Header->Name);
        // virtualAddress节区的RVA地址
        // sizeofrawdata节区对齐后的尺寸
        // PointerToRawData节区起始数据在文件中的偏移
        if (p_Section_Header->VirtualAddress <= rva && rva < p_Section_Header->VirtualAddress + p_Section_Header->SizeOfRawData)
        {
            return rva - p_Section_Header->VirtualAddress + p_Section_Header->PointerToRawData;
        }
        p_Section_Header++;
    }
    return 0x00000;
}

std::wstring AnsiToUnicode(const std::string& orgstr)
{
    const int size = MultiByteToWideChar(CP_ACP, 0, orgstr.c_str(), -1, nullptr, 0);
    vector<wchar_t> buf(size, 0);
    MultiByteToWideChar(CP_ACP, 0, orgstr.c_str(), -1, buf.data(), size);
    return buf.data();
}

// 根据ID得到图标资源
PIMAGE_RESOURCE_DATA_ENTRY ExtractIcoByID(PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryRoot, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS pImageNtHeader, int ID)
{
    // 遍历资源表根目录
    for (int i = 0; i < pImageResourceDirectoryRoot->NumberOfIdEntries + pImageResourceDirectoryRoot->NumberOfNamedEntries; i++)
    {
        // depth == 2
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntrySec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryRoot + sizeof(IMAGE_RESOURCE_DIRECTORY)) + i;
        // 图标资源
        if (pImageResourceDirectoryEntrySec->Id == 3)
        {
            PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectorySec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntrySec->OffsetToDirectory);
            for (int r = 0; r < pImageResourceDirectorySec->NumberOfIdEntries + pImageResourceDirectorySec->NumberOfNamedEntries; r++)
            {
                // depth == 3
                PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryTir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectorySec + sizeof(IMAGE_RESOURCE_DIRECTORY)) + r;
                // 根据图标ID获得图标数据
                if (pImageResourceDirectoryEntryTir->Id == ID)
                {
                    PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryTir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryTir->OffsetToDirectory);
                    for (int t = 0; t < pImageResourceDirectoryTir->NumberOfIdEntries + pImageResourceDirectoryTir->NumberOfNamedEntries; t++)
                    {
                        // depth == 4
                        PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryFour = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryTir + sizeof(IMAGE_RESOURCE_DIRECTORY)) + t;
                        PIMAGE_RESOURCE_DATA_ENTRY pImageResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryFour->OffsetToData);
                        return pImageResourceDataEntry;
                    }
                }
            }
        }
    }
    return NULL;
}

// 图标提取方法
void ExtractIco(PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryRoot, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS pImageNtHeader)
{
    // 遍历资源表根目录
    for (int i = 0; i < pImageResourceDirectoryRoot->NumberOfIdEntries + pImageResourceDirectoryRoot->NumberOfNamedEntries; i++)
    {
        // depth == 2
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntrySec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryRoot + sizeof(IMAGE_RESOURCE_DIRECTORY)) + i;
        // 图标资源
        if (pImageResourceDirectoryEntrySec->Id == 3)
        {
            PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectorySec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntrySec->OffsetToDirectory);
        }
        // 图标组
        if (pImageResourceDirectoryEntrySec->Id == 14)
        {
            PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectorySec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntrySec->OffsetToDirectory);
            for (int r = 0; r < pImageResourceDirectorySec->NumberOfIdEntries + pImageResourceDirectorySec->NumberOfNamedEntries; r++)
            {
                // depth == 3
                PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryTir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectorySec + sizeof(IMAGE_RESOURCE_DIRECTORY)) + r;
                PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryTir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryTir->OffsetToDirectory);
                for (int t = 0; t < pImageResourceDirectoryTir->NumberOfIdEntries + pImageResourceDirectoryTir->NumberOfNamedEntries; t++)
                {
                    // depth == 4
                    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryFour = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryTir + sizeof(IMAGE_RESOURCE_DIRECTORY)) + t;
                    PIMAGE_RESOURCE_DATA_ENTRY pImageResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryFour->OffsetToData);
                    DWORD pIcoGroupData = (DWORD)pImageDosHeader + RvaToOffset(pImageNtHeader, pImageResourceDataEntry->OffsetToData);
                    int sizeOfIcoGroup = pImageResourceDataEntry->Size;
                    // printf_s("%08x\n", *((WORD*)pIcoGroupData + 2));
                    // 得到图标组中图标数量
                    for (int n = 0; n < *((WORD*)pIcoGroupData + 2); n++)
                    {
                        // 只包含一个图标的图标头构造
                        uint8_t* currentIcoHeader = 6 + 14 * n + (uint8_t*)pIcoGroupData;
                        vector<uint8_t> myIcoHeader(22);
                        myIcoHeader[0] = 0x00;
                        myIcoHeader[1] = 0x00;
                        myIcoHeader[2] = 0x01;
                        myIcoHeader[3] = 0x00;
                        myIcoHeader[4] = 0x02;
                        myIcoHeader[5] = 0x00;
                        for (int m = 6; m < 14; m++)
                        {
                            myIcoHeader[m] = currentIcoHeader[m - 6];
                        }
                        int ID = (DWORD) * (currentIcoHeader + 12);
                        PIMAGE_RESOURCE_DATA_ENTRY pImageResourceDataEntryOfIco = ExtractIcoByID(pImageResourceDirectoryRoot, pImageDosHeader, pImageNtHeader, ID);
                        myIcoHeader[14] = (uint8_t)pImageResourceDataEntryOfIco->Size;
                        myIcoHeader[15] = (uint8_t)(pImageResourceDataEntryOfIco->Size >> 8);
                        myIcoHeader[16] = (uint8_t)(pImageResourceDataEntryOfIco->Size >> 16);
                        myIcoHeader[17] = (uint8_t)(pImageResourceDataEntryOfIco->Size >> 24);
                        myIcoHeader[18] = 0x16;
                        myIcoHeader[19] = 0x00;
                        myIcoHeader[20] = 0x00;
                        myIcoHeader[21] = 0x00;
                        DWORD pIcoData = (DWORD)pImageDosHeader + RvaToOffset(pImageNtHeader, pImageResourceDataEntryOfIco->OffsetToData);
                        const char* nameHeader = "D:\\test\\qq\\";
                        const char* nameTail = ".ico";
                        char fileName[256];
                        sprintf_s(fileName, "%s%d", nameHeader, ID);
                        sprintf_s(fileName, "%s%s", fileName, nameTail);
                        HANDLE hFile = CreateFile(AnsiToUnicode(fileName).c_str(), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
                        // 写入文件
                        WriteFile(hFile, (LPVOID)myIcoHeader.data(), 22, NULL, NULL);
                        WriteFile(hFile, (LPVOID)pIcoData, pImageResourceDataEntryOfIco->Size, NULL, NULL);
                        CloseHandle(hFile);
                    }
                }
            }
        }
    }
}

void PEControl()
{
    LPCWSTR fileName = TEXT("D:\\test\\qq\\PCQQ2020.exe");
    HANDLE fileHandle = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
    DWORD high_size;
    DWORD size = GetFileSize(fileHandle, &high_size);
    HANDLE hMapFile = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapFile == NULL)
    {
        cout << "内存映射文件失败" << endl;
        system("PAUSE");
    }
    LPDWORD lpMemory = (LPDWORD)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    // 得到PE文件DOS头所在位置
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpMemory;
    // 得到PE头所在位置 PE start = DOS MZ 基地址 + IMAGE_DOS_HEADER.e_lfanew
    PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageDosHeader->e_lfanew + (DWORD)pImageDosHeader);
    // PE文件的图标数据储存在资源表中 得到资源表头所在位置 资源表RVA储存在PE扩展头(pImageNTHeader->OptionalHeader)的数据目录的第三个
    IMAGE_RESOURCE_DIRECTORY* pImageResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageDosHeader + RvaToOffset(pImageNTHeader, pImageNTHeader->OptionalHeader.DataDirectory[2].VirtualAddress));
    // 调用PE文件ICO提取方法
    ExtractIco(pImageResourceDirectory, pImageDosHeader, pImageNTHeader);
}
