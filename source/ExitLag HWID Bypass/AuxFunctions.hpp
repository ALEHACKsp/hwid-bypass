#pragma once
// Get the process id of the process, knowing the process name
// const char* name -> the name of the process
// return DWORD -> return the process identificator. returns 0 if not found
DWORD GetPIdByProcessName(const char* name)
{
	PROCESSENTRY32 PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	do {
		if (!strcmp(PE32.szExeFile, name)) {
			CloseHandle(hSnap);
			return PE32.th32ProcessID;
		}
	} while (Process32Next(hSnap, &PE32));
	CloseHandle(hSnap);
	return 0;
}



// Get the address of the module in the memory.
// DWORD Pid -> the process id of the target.
// const char* ModuleName -> the name of the target module.
// return DWORD -> the module start address
DWORD GetModuleAddressByName(DWORD Pid, const char* ModuleName) {
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid);
	Module32First(snapshot, &me32);
	do {
		if (!strcmp(me32.szModule, ModuleName)) {
			CloseHandle(snapshot);
			return (uintptr_t)me32.modBaseAddr;
		}
	} while (Module32Next(snapshot, &me32));
	CloseHandle(snapshot);
	return 0;
}


// this function I got from the internet. This could be much bettern, but anyway.
// function to split strings. This is used by PatternStringToBytePatternAndMask to  
// get the bytes (or unknow byte) separated by spaces
// const string& s -> the string to be splitted.
// char delimiter -> the delimiter that splittes the string
// return vector<string> -> return a string array with the splitted strings
vector<string> split(const string& s, char delimiter)
{
	vector<string> tokens;
	string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

// transform string hex to byte
// example: string "AA" to byte 0xAA
// string hex_byte_str -> a string with the bytes as hex. 
// BYTE StrHexToInt -> return the byte version of the string input
BYTE StrHexToInt(string hex_byte_str) { // len 2

	return (BYTE)strtoul(hex_byte_str.c_str(), nullptr, 16);
}

// this function get an pattern like "AA BB CC ?? AA BB" and transform
// to a byte array [0xAA 0xBB 0xCC 0x00 AA BB] and a mask. xxx?xx
// string in_pattern -> the string version of the pattern (input)
// vector<byte>* out_pattern -> a pointer to a byte array, the pattern byte version. (output)
// string* out_mask -> a pointer to a string, the pattern mask version. (output)
void PatternStringToBytePatternAndMask(string in_pattern, vector<byte>* out_pattern, string* out_mask) {

	/* gera a mascara e transforma o pattern em int array */

	vector<string> res = split(in_pattern, ' ');
	string mask;
	vector<byte> pattern_return;

	for (unsigned int x = 0; x < res.size(); x++) {
		if (strcmp("??", res[x].c_str())) {
			mask += "x";
			pattern_return.push_back((byte)StrHexToInt(res[x]));
		}
		else {
			pattern_return.push_back(0);
			mask += "?";
		}
	}
	/* escrevendo nos parametros */
	*out_pattern = pattern_return;
	*out_mask = mask;
}

// this function scan throw all the memory of another process by the pattern that you choice.
// HANDLE hprocess -> a HANDLE to the target process
// DWORD start_address -> the start address that we will look for the pattern
// DWORD section_size -> the size of the memory that we will look for the pattern
// vector<byte> pattern -> this is actually the pattern, a byte array with the bytes that we will look for in the memory
// string mask -> This say the bytes that we want to include or not in the pattern.
// return uintptr_t -> the address first address found. Return 0 if not found.
DWORD ExPatternScanByStartAddress(HANDLE hprocess, DWORD start_address, DWORD section_size, vector<byte> pattern, string mask) {
	CONST DWORD buf_sz = 4096;
	DWORD old_protection;
	byte buffer[buf_sz];
	for (DWORD current_section = start_address; current_section < start_address + section_size; current_section += buf_sz) { // get a piece of memory and read

		if (!VirtualProtectEx(hprocess, (LPVOID)current_section, buf_sz, PAGE_EXECUTE_READWRITE, &old_protection)) { cout << "Error VirtualProtectEx memory section: " << hex << current_section << endl;  exit(1); };
		if (!ReadProcessMemory(hprocess, (LPVOID*)current_section, &buffer, buf_sz, 0)) { cout << "Error ReadProcessMemory" << endl;  exit(2); }
		if (!VirtualProtectEx(hprocess, (LPVOID)current_section, buf_sz, old_protection, &old_protection)) { cout << "Error VirtualProtectEx 2 " << endl;  exit(4); };

		for (DWORD current_address = 0; current_address < buf_sz; ++current_address) { // get this piece and scan for the pattern
			for (DWORD correct_count = 0; correct_count < pattern.size(); ++correct_count) {
				if (correct_count == pattern.size() - 1) {
					return current_section + current_address;
				}

				if (mask[correct_count] == '?') {
					continue;
				}
				else if (buffer[current_address + correct_count] == pattern[correct_count]) {
					continue;
				}
				else {
					correct_count = 0;
					break;
				}
			}
		}
	}


	return 0;
}
