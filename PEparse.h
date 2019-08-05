#pragma once
#pragma once
#ifndef PEparse_H
#define PEparse_H
#include <Winsock2.h>  
#include<WinDef.h>
#include<winnt.h>

class PEparse {
private:
	PBYTE p_file_buffer;  // 文件的内存映像

	PIMAGE_DOS_HEADER p_dos_header;
	PIMAGE_NT_HEADERS p_nt_header;
	PIMAGE_SECTION_HEADER p_section_header;



public:
	PEparse(BYTE* p_fileimage_buff);
	~PEparse();
public:
	void initDosHeader();
	void initNtHeader();
	void initSectionHeader();

	void showSectionInfo();
	void showDataDirectory();
	void showExportTable();
	void showRelocationtTable();
	void showImportTable();

	DWORD rva2foa(DWORD rva);
};


#endif // !PEparse_H

