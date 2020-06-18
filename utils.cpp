#include "utils.h"

using namespace std;


// �ο� https://blog.csdn.net/HeroNeverDie/article/details/78990616

//�����ڴ�ƫ�Ƶ�ַRVA�õ��ļ�ƫ�Ƶ�ַ
DWORD RvaToOffset(PIMAGE_NT_HEADERS pNtHeader, DWORD rva)
{
    //PE��
    IMAGE_SECTION_HEADER* p_Section_Header;
    //���Pe����Ŀ
    DWORD sectionSum = pNtHeader->FileHeader.NumberOfSections;
    //��һ���ڱ���
    p_Section_Header = (IMAGE_SECTION_HEADER*)((DWORD)pNtHeader + (DWORD)sizeof(IMAGE_NT_HEADERS));
    for (size_t i = 0; i < sectionSum; i++)
    {
        //printf_s("%s\n", p_Section_Header->Name);
        //virtualAddress������RVA��ַ
        //sizeofrawdata���������ĳߴ�
        //PointerToRawData������ʼ�������ļ��е�ƫ��
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

//����ID�õ�ͼ����Դ
PIMAGE_RESOURCE_DATA_ENTRY ExtractIcoByID(PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryRoot, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS pImageNtHeader, int ID)
{
    //������Դ���Ŀ¼
    for (int i = 0; i < pImageResourceDirectoryRoot->NumberOfIdEntries + pImageResourceDirectoryRoot->NumberOfNamedEntries; i++)
    {
        //depth == 2
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntrySec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryRoot + sizeof(IMAGE_RESOURCE_DIRECTORY)) + i;
        //ͼ����Դ
        if (pImageResourceDirectoryEntrySec->Id == 3)
        {
            PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectorySec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntrySec->OffsetToDirectory);
            for (int r = 0; r < pImageResourceDirectorySec->NumberOfIdEntries + pImageResourceDirectorySec->NumberOfNamedEntries; r++)
            {
                //depth == 3
                PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryTir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectorySec + sizeof(IMAGE_RESOURCE_DIRECTORY)) + r;
                //����ͼ��ID���ͼ������
                if (pImageResourceDirectoryEntryTir->Id == ID)
                {
                    PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryTir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryTir->OffsetToDirectory);
                    for (int t = 0; t < pImageResourceDirectoryTir->NumberOfIdEntries + pImageResourceDirectoryTir->NumberOfNamedEntries; t++)
                    {
                        //depth == 4
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

//ͼ����ȡ����
void ExtractIco(PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryRoot, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS pImageNtHeader)
{
    int sizeOfIcoGroup;
    DWORD pIcoData;
    DWORD pIcoGroupData;
    //������Դ���Ŀ¼
    for (int i = 0; i < pImageResourceDirectoryRoot->NumberOfIdEntries + pImageResourceDirectoryRoot->NumberOfNamedEntries; i++)
    {
        //depth == 2
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntrySec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryRoot + sizeof(IMAGE_RESOURCE_DIRECTORY)) + i;
        //ͼ����Դ
        if (pImageResourceDirectoryEntrySec->Id == 3)
        {
            PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectorySec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntrySec->OffsetToDirectory);
        }
        //ͼ����
        if (pImageResourceDirectoryEntrySec->Id == 14)
        {
            PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectorySec = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntrySec->OffsetToDirectory);
            for (int r = 0; r < pImageResourceDirectorySec->NumberOfIdEntries + pImageResourceDirectorySec->NumberOfNamedEntries; r++)
            {
                //depth == 3
                PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryTir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectorySec + sizeof(IMAGE_RESOURCE_DIRECTORY)) + r;
                PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryTir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryTir->OffsetToDirectory);
                for (int t = 0; t < pImageResourceDirectoryTir->NumberOfIdEntries + pImageResourceDirectoryTir->NumberOfNamedEntries; t++)
                {
                    //depth == 4
                    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntryFour = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pImageResourceDirectoryTir + sizeof(IMAGE_RESOURCE_DIRECTORY)) + t;
                    PIMAGE_RESOURCE_DATA_ENTRY pImageResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pImageResourceDirectoryRoot + pImageResourceDirectoryEntryFour->OffsetToData);
                    pIcoGroupData = (DWORD)pImageDosHeader + RvaToOffset(pImageNtHeader, pImageResourceDataEntry->OffsetToData);
                    sizeOfIcoGroup = pImageResourceDataEntry->Size;
                    //printf_s("%08x\n", *((WORD*)pIcoGroupData + 2));
                    //�õ�ͼ������ͼ������
                    for (int n = 0; n < *((WORD*)pIcoGroupData + 2); n++)
                    {
                        //ֻ����һ��ͼ���ͼ��ͷ����
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
                        pIcoData = (DWORD)pImageDosHeader + RvaToOffset(pImageNtHeader, pImageResourceDataEntryOfIco->OffsetToData);
                        const char* nameHeader = "D:\\test\\qq\\";
                        const char* nameTail = ".ico";
                        char fileName[256];
                        sprintf_s(fileName, "%s%d", nameHeader, ID);
                        sprintf_s(fileName, "%s%s", fileName, nameTail);
                        HANDLE hFile = CreateFile(AnsiToUnicode(fileName).c_str(), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
                        //д���ļ�
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
        cout << "�ڴ�ӳ���ļ�ʧ��" << endl;
        system("PAUSE");
    }
    LPDWORD lpMemory = (LPDWORD)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    //�õ�PE�ļ�DOSͷ����λ��
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpMemory;
    //�õ�PEͷ����λ�� PE start = DOS MZ ����ַ + IMAGE_DOS_HEADER.e_lfanew
    PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageDosHeader->e_lfanew + (DWORD)pImageDosHeader);
    //PE�ļ���ͼ�����ݴ�������Դ���� �õ���Դ��ͷ����λ�� ��Դ��RVA������PE��չͷ(pImageNTHeader->OptionalHeader)������Ŀ¼�ĵ�����
    IMAGE_RESOURCE_DIRECTORY* pImageResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pImageDosHeader + RvaToOffset(pImageNTHeader, pImageNTHeader->OptionalHeader.DataDirectory[2].VirtualAddress));
    //����PE�ļ�ICO��ȡ����
    ExtractIco(pImageResourceDirectory, pImageDosHeader, pImageNTHeader);
}
