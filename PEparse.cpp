#include <stdio.h>
#include<string.h>

#include "PEparse.h"



PEparse::PEparse(BYTE* p_fileimage_buff) {
	this->p_file_buffer = p_fileimage_buff;

	this->initDosHeader();
	this->initNtHeader();
	this->initSectionHeader();
	printf("PEparse  init ok\n");
}


void PEparse::initDosHeader() {
	// dos header 0x40 bytes
	this->p_dos_header = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	if (this->p_dos_header == NULL) {
		printf("PEparse initDosHeader failed, malloc p_dos_header failed!\n");
		return;
	}
	memcpy(this->p_dos_header, this->p_file_buffer, sizeof(IMAGE_DOS_HEADER));
	printf("PEparse  initDosHeader ok\n");

}


void PEparse::initNtHeader() {
	this->p_nt_header = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
	if (this->p_nt_header == NULL) {
		printf("PEparse initNtHeader failed, malloc p_nt_header failed!\n");
		return;
	}
	memcpy(this->p_nt_header, this->p_file_buffer + this->p_dos_header->e_lfanew, sizeof(IMAGE_NT_HEADERS));
	printf("PEparse  initNtHeader ok\n");
}


void PEparse::initSectionHeader() {
	int numberOfSections = this->p_nt_header->FileHeader.NumberOfSections;
	this->p_section_header = (PIMAGE_SECTION_HEADER)malloc(numberOfSections * sizeof(IMAGE_SECTION_HEADER));
	if (this->p_section_header == NULL) {
		printf("PEparse initSectionHeader failed, malloc p_section_header failed!\n");
		return;
	}
	memcpy(this->p_section_header, this->p_file_buffer + this->p_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS), numberOfSections * sizeof(IMAGE_SECTION_HEADER));
	printf("PEparse  initSectionHeader ok\n");
}



void PEparse::showSectionInfo() {
	int numberOfSections = this->p_nt_header->FileHeader.NumberOfSections;
	char sectionName[10] = { 0 };
	printf("%-6s    %-8s   %-10s  %-20s  %-20s  %-20s  %-20s\n",
		"number",
		"Name",
		"Misc",
		"VirtualAddress",
		"SizeOfRawData",
		"PointerToRawData",
		"Characteristics"
	);
	for (int i = 0; i < numberOfSections; i++) {
		memset(sectionName, 0, sizeof(sectionName));
		memcpy(sectionName, (char*)& this->p_section_header[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		printf("%-6d    %-8s   %-10X  %-20X  %-20X  %-20X  %-40X\n",
			i,
			sectionName,
			this->p_section_header[i].Misc.VirtualSize,
			this->p_section_header[i].VirtualAddress,
			this->p_section_header[i].SizeOfRawData,
			this->p_section_header[i].PointerToRawData,
			this->p_section_header[i].Characteristics
		);
	}
	printf("\n");
}


void PEparse::showDataDirectory() {
	int number = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	printf("%-3s  %-08s   %-08s\n", "No.", "VAddress", "Size");
	for (int i = 0; i < number; i++) {
		printf("%-3d  %-08x    %-08x\n",
			i,
			this->p_nt_header->OptionalHeader.DataDirectory[i].VirtualAddress,
			this->p_nt_header->OptionalHeader.DataDirectory[i].Size);
	}
	printf("\n");
}

void PEparse::showExportTable() {
	// 导出表
	IMAGE_EXPORT_DIRECTORY exportTable;

	DWORD exportTableFoa = this->rva2foa(this->p_nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);
	memcpy(&exportTable, this->p_file_buffer + exportTableFoa, sizeof(IMAGE_EXPORT_DIRECTORY));

	if (exportTable.NumberOfFunctions == 0) {
		printf("%-5s  %-3s  %-08s   %s\n", "Base", "Odr", "VAddress", "Name");
		return;
	}

	DWORD addressOfNameTabelFoa = this->rva2foa(exportTable.AddressOfNames);

	PDWORD addressOfNames = (PDWORD)(this->p_file_buffer + this->rva2foa(exportTable.AddressOfNames));
	for (int i = 0; i < exportTable.NumberOfNames; i++) {
		DWORD functionNameAddr = *(addressOfNames + i);
		char* functionName = (char*)(this->p_file_buffer + this->rva2foa(functionNameAddr));
		printf("name: %s\n", functionName);
	}

	// 函数地址表
	PDWORD addressOfFunctionTable = (PDWORD)(this->p_file_buffer + this->rva2foa(exportTable.AddressOfFunctions));
	for (int i = 0; i < exportTable.NumberOfFunctions; i++) {
		printf("addr: %X\n", *(addressOfFunctionTable + i));
	}


	// 序号表
	PWORD addressOfNameOrdinalsTable = (PWORD)(this->p_file_buffer + this->rva2foa(exportTable.AddressOfNameOrdinals));
	for (int i = 0; i < exportTable.NumberOfNames; i++) {
		printf("odr: %d\n", *(addressOfNameOrdinalsTable + i));
	}


	// 遍历
	printf("%-5s  %-3s  %-08s   %s\n", "Base", "Odr", "VAddress", "Name");
	for (int i = 0; i < exportTable.NumberOfFunctions; i++) {
		DWORD addOfFunc = *(addressOfFunctionTable + i);

		if (addOfFunc == 0x0) {
			// 0地址的函数跳过，导出序号间隔不是为1
			continue;
		}

		// 导出序号表里面寻找序号
		int odrOfFuncIndex = -1;
		for (int j = 0; j < exportTable.NumberOfNames; j++) {
			WORD odrOfFunc = *(addressOfNameOrdinalsTable + j);
			if (odrOfFunc == i) {
				// 有导出函数名
				odrOfFuncIndex = j;
				break;
			}
		}

		if (odrOfFuncIndex >= 0) {
			// 有导出函数名
			DWORD functionNameAddr = *(addressOfNames + odrOfFuncIndex);
			char* functionName = (char*)(this->p_file_buffer + this->rva2foa(functionNameAddr));
			printf("%-5d  %-3d  %-08X  %s\n",
				exportTable.Base,
				i,
				addOfFunc,
				functionName
			);
		}
		else {
			// 没有导出函数名
			printf("%-5d  %-3d  %-08X   %s\n",
				exportTable.Base,
				i,
				addOfFunc,
				"-"
			);
		}
	}


}

// rva2foa  DWORD rva2foa(DWORD rva)
DWORD PEparse::rva2foa(DWORD rva) {
	// 在pe头
	if (rva <= this->p_nt_header->OptionalHeader.SizeOfHeaders) {
		return rva;
	}

	// rva 落在哪个节里面
	int section_number = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	// 节在内存中的对齐
	DWORD sectionAlignment = this->p_nt_header->OptionalHeader.SectionAlignment;
	for (int i = 0; i < section_number; i++) {
		DWORD virtualSize = this->p_section_header[i].Misc.VirtualSize;
		DWORD start = this->p_section_header[i].VirtualAddress;
		DWORD end;
		if (virtualSize % sectionAlignment == 0) {
			end = start + virtualSize;
		}
		else {
			end = start + (virtualSize / sectionAlignment + 1) * sectionAlignment;
		}

		if (rva >= start && rva < end) {
			// 落在此节中
			return (rva - start) + this->p_section_header[i].PointerToRawData;
		}

	}
	return -1;
}




void PEparse::showRelocationtTable() {
	// 重定位表
	IMAGE_BASE_RELOCATION relocationBlock;

	int numberOfBlock = 1;

	// 第一个重定位块
	DWORD relocationBlockFoa = this->rva2foa(this->p_nt_header->OptionalHeader.DataDirectory[5].VirtualAddress);
	memcpy(&relocationBlock, this->p_file_buffer + relocationBlockFoa, sizeof(IMAGE_BASE_RELOCATION));
	printf("%-5s %-8s %-15s %-8s %-8s %-8s %s\n", "No.", "VAddress", "SizeOfBlock", "Item", "ItemNo.", "ItemRVA", "ItemFOA");
	while (relocationBlock.VirtualAddress != 0 && relocationBlock.SizeOfBlock != 0) {
		printf("%-5X %-08X %-015X %X\n", numberOfBlock, relocationBlock.VirtualAddress, relocationBlock.SizeOfBlock, (relocationBlock.SizeOfBlock - 8) / 2);

		int itemNo = 1;
		while (itemNo <= (relocationBlock.SizeOfBlock - 8) / 2) {
			WORD itemOffset = *(WORD*)(this->p_file_buffer + relocationBlockFoa + 8 + (itemNo - 1) * 2);
			if (itemOffset >> 12 == 0x3) {
				// 高4位为3，需要修正的的重定位地址
				DWORD itemRVA = relocationBlock.VirtualAddress + (itemOffset & 0x0FFF);
				DWORD itemFOA = this->rva2foa(itemRVA);

				printf("%39s %-8X %-8X %X\n", "", itemNo, itemRVA, itemFOA);
			}


			itemNo++;
		}


		// 下一个块
		numberOfBlock++;
		relocationBlockFoa += relocationBlock.SizeOfBlock;
		memcpy(&relocationBlock, this->p_file_buffer + relocationBlockFoa, sizeof(IMAGE_BASE_RELOCATION));
	}

}


void PEparse::showImportTable() {
	// 导入表
	IMAGE_IMPORT_DESCRIPTOR importTable;
	// 第一个导入模块
	DWORD importTableFoa = this->rva2foa(this->p_nt_header->OptionalHeader.DataDirectory[1].VirtualAddress);
	memcpy(&importTable, this->p_file_buffer + importTableFoa, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	printf("%-5s %s  %-15s %s\n", "No.", "dllName", "funcOdr", "funcName");
	int numberOfImport = 1;
	while (importTable.FirstThunk != 0 && importTable.OriginalFirstThunk != 0) {
		DWORD dllNameFOA = this->rva2foa(importTable.Name);
		printf("%-5d %s\n", numberOfImport, this->p_file_buffer + dllNameFOA);

		// 遍历INT表
		DWORD dllINTFOA = this->rva2foa(importTable.OriginalFirstThunk);
		int intNumber = 1;
		DWORD intValue = *(DWORD*)(this->p_file_buffer + dllINTFOA);
		while (intValue != 0) {
			// 最高位为1则为序号导入，否则是名字导入
			if (intValue >> 31 == 0x1) {
				printf("%-15s %X\n", "", intValue);
			}
			else {
				char* funName = (char*)this->p_file_buffer + this->rva2foa(intValue) + 2;
				printf("%-25s %s\n", "", funName);
			}

			// 下一个intvalue
			intValue = *(DWORD*)(this->p_file_buffer + dllINTFOA + intNumber * 4);
			intNumber++;
		}





		// 下一个导入dll
		memcpy(&importTable, this->p_file_buffer + importTableFoa + numberOfImport * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
		numberOfImport++;


	}


}


PEparse::~PEparse() {
	if (this->p_file_buffer) {
		free(this->p_file_buffer);
	}
	if (this->p_dos_header) {
		free(this->p_dos_header);
	}
	if (this->p_nt_header) {
		free(this->p_nt_header);
	}
	if (this->p_section_header) {
		free(this->p_section_header);
	}
}