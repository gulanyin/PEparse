#include<stdio.h>
#include<string.h>
#include<fstream>
#include<iostream>
#include "PEparse.h"

int main(int argc, char** argv) {

	// 命令行参数
	// PEparse.exe  filepath  command
	if (argc != 3) {
		printf("length of arg not correct");
		return -1;
	}

	char command[50] = { 0 };

	memcpy(command, argv[2], strlen(argv[2]));

	if (!strcmp(command, "help")) {
		printf("export: print export table\n");
		printf("import: print import table\n");
		printf("reloc: print reloc table\n");
		return -1;
	}


	if (strcmp(command, "export")
		&& strcmp(command, "import")
		&& strcmp(command, "reloc")) {
		printf("no support command\n");
		return -1;
	}



	const char* file_path = argv[1];

	std::fstream fileReader;
	fileReader.open(file_path, std::ios::in | std::ios::binary);
	if (!fileReader)
	{
		printf("file %s does'nt exiest", file_path);
		fileReader.close();
		return -1;
	}
	// 文件存在， 不是pe文件

	WORD e_magic;
	fileReader.read((char*)&e_magic, 2);
	if (e_magic != 0x5a4d) {
		printf("file %s does'nt a pe file\n", file_path);
		fileReader.close();
		return -1;
	}
	DWORD e_lfanew;
	fileReader.seekg(0x3cL, std::ios::beg);
	fileReader.read((char*)& e_lfanew, 4);
	DWORD signature;
	fileReader.seekg(e_lfanew, std::ios::beg);
	fileReader.read((char*)& signature, 4);
	if (signature != 0x4550) {
		printf("file %s does'nt a pe file\n", file_path);
		fileReader.close();
		return -1;
	}
	// 是pe文件申请内存拷贝文件映像
	// 移动到文件尾，获取大小
	fileReader.seekg(0L, std::ios::end);
	long fileSize = fileReader.tellg();

	// 移动到文件首，读取文件到缓冲区
	PBYTE p_fileimage_buff = (BYTE*)malloc(fileSize);
	if (p_fileimage_buff == NULL) {
		printf("malloc p_fileimage_buff failed");
		fileReader.close();
		return -1;
	}
	fileReader.seekg(0L, std::ios::beg);
	fileReader.read((char*)p_fileimage_buff, fileSize);
	fileReader.close();

	// 文件存在
	PEparse parse(p_fileimage_buff);

	//parse.showSectionInfo();
	//parse.showDataDirectory();
	//printf("%x\n", parse.rva2foa(0x1f0ff));
	//parse.showExportTable();
	//parse.showRelocationtTable();
	//parse.showImportTable();

	
	if (!strcmp(command, "export")) {
		parse.showExportTable();
	}
	else if (!strcmp(command, "import")) {
		parse.showImportTable();
	}
	else if (!strcmp(command, "reloc")) {
		parse.showRelocationtTable();
	}

}