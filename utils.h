#pragma once

#include <Windows.h>

#include <iostream>
#include <string>
#include <vector>

#include <cstdint>

DWORD RvaToOffset(PIMAGE_NT_HEADERS pNtHeader, DWORD rva);
std::wstring AnsiToUnicode(const std::string& orgstr);
PIMAGE_RESOURCE_DATA_ENTRY ExtractIcoByID(PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryRoot, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS pImageNtHeader, int ID);
void ExtractIco(PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectoryRoot, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS pImageNtHeader);
void PEControl();