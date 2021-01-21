#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <sstream>  
#include <string.h>
#include <Windows.h>



using std::cout;
using std::endl;
using std::cin;
using std::hex;
using std::string;
using std::vector;



// Get the process id of the process, knowing the process name
// const char* name -> the name of the process
// return DWORD -> return the process identificator. returns 0 if not found
DWORD GetPIdByProcessName(const char* name)
{
	PROCESSENTRY32 PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // dá um print nos processos
	BOOL status = Process32First(hSnap, &PE32); // BLZ, INICIOU
	while (status) {
		if (!strcmp(PE32.szExeFile, name)) {
			CloseHandle(hSnap);
			return PE32.th32ProcessID;
		}
		status = Process32Next(hSnap, &PE32);
	}
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
	bool isntEnd = true;
	while (isntEnd) {
		if (!strcmp(me32.szModule, ModuleName)) {
			CloseHandle(snapshot);
			return (uintptr_t)me32.modBaseAddr;
		}
		isntEnd = Module32Next(snapshot, &me32);
	}
	CloseHandle(snapshot);
	return 0;
}

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
// uintptr_t start_address -> the start address that we will look for the pattern
// uintptr_tsection_size -> the size of the memory that we will look for the pattern
// vector<byte> pattern -> this is actually the pattern, a byte array with the bytes that we will look for in the memory
// string mask -> This say the bytes that we want to include or not in the pattern.
// return uintptr_t -> the address first address found. Return 0 if not found.
uintptr_t ExPatternScanByStartAddress(HANDLE hprocess, uintptr_t start_address, uintptr_t section_size, vector<byte> pattern, string mask) {
	CONST DWORD buf_sz = 4096;
	DWORD old_protection = 0;
	byte buffer[buf_sz];
	for (uintptr_t current_section = start_address; current_section < start_address + section_size; current_section += buf_sz) { // get a piece of memory and read

		if (!VirtualProtectEx(hprocess, (LPVOID)current_section, buf_sz, PAGE_EXECUTE_READWRITE, &old_protection)) { cout << "Error VirtualProtectEx memory section: " << hex << current_section  << endl;  exit(1); };
		if (!ReadProcessMemory(hprocess, (LPVOID*)current_section, &buffer, buf_sz, 0)) { cout << "Error ReadProcessMemory" << endl;  exit(2); }
		if (!VirtualProtectEx(hprocess, (LPVOID)current_section, buf_sz, old_protection, &old_protection)) { cout << "Error VirtualProtectEx 2 " << endl;  exit(4); };

		for (uintptr_t current_address = 0; current_address < buf_sz; current_address++) { // get this piece and scan for the pattern
			for (uintptr_t correct_count = 0; correct_count < pattern.size(); correct_count++) {
				if (correct_count == pattern.size() - 1) {
					return current_section + current_address;
				}

				if (mask[correct_count] == '?') {
					continue;
				}
				if (buffer[current_address + correct_count] == pattern[correct_count]) {
					int foo = 1;
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

// Where the magic happens
int main()
{
	/* Get the process identificator of the target and check if it were found*/
	DWORD PID = GetPIdByProcessName((char*)"ExitLag.exe");
	if (!PID) {
		system("cls");
		cout << "Waiting for process \"ExitLag.exe\"..." << endl;
		Sleep(100);
		main();
	}

	/* Open a handle to the target process, with full access, then check if it worked. */
	HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	if (hprocess == INVALID_HANDLE_VALUE) {
		system("cls");
		cout << "Error in Handle..." << endl;
		Sleep(3000);
		main();
	}

	/* Give time to the program load everything. */
	Sleep(1000); 

	/* The pattern that we want to find in the memory (string version)*/
	string pattern_str = "46 3B 73 08 72 89 8B 75 08 8D 8D 58 FF FF FF 56";
	/* An array where the pattern bytes will be writen */
	vector<byte> pattern_byte; // 
	/* An array where the mask will be write */
	string mask; 

	/* We call the function that will write pattern_byte and mask values.*/
	PatternStringToBytePatternAndMask(pattern_str, &pattern_byte, &mask);

	/* Get the module start address. This is where the function will start to look for the pattern. Then check if it worked*/
	auto main_module_address = GetModuleAddressByName(PID, "ExitLag.exe");
	if (!main_module_address) {
		system("cls");
		cout << "Error in GetModuleAddress..." << endl;
		Sleep(3000);
		main();
	}

	/* The size of the memory that we will look for the pattern */
	auto size_to_scan = 4096 * 100;
	

	/* Now we call the function that will search for the pattern*/
	DWORD* address = (DWORD*)ExPatternScanByStartAddress(hprocess, main_module_address, size_to_scan, pattern_byte, mask);
	if (!address) {
		cout << "Error. Address for hook wasn't found. Trying again..." << endl;
		Sleep(3000);
		system("cls");
		main();
	}
	
	/* As the pattern that I scanned is -6 that the address that I want to modify, i am increasing 6  to this */
	address = (DWORD*)((DWORD)address + 6); 
	cout << "The Address was found. It is: 0x" << hex << address << endl;
	
	/* Now we need to know where the return address should be. Because we will hook the address with a jump */
	/* The return address is address + 8. This is where the jmp and nops are finisheds */
	DWORD* return_hook_address = (DWORD*)((DWORD)address + 8);

	/* Now we alloc memory to the target process. We will need this to hook. VirtualAllocEx  will return the address were it was allocated	*/
	DWORD* alloc_address = (DWORD*) VirtualAllocEx(hprocess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!alloc_address) {
		system("cls");
		cout << "Error while allocating memory..." << endl;
		Sleep(3000);
		main();
	}

	cout << "The memory has been allocated. The address is: 0x" << hex << alloc_address << endl;

	/* This is the solution that I found to read the addresses the way a need*/
	/* I am just saying that alloc_address_bytes should be interpreted as an byte array. The same to the other.*/
	BYTE* alloc_address_bytes = (BYTE*)&alloc_address;
	BYTE* return_hook_address_bytes = (BYTE*)&return_hook_address;
	
	/* OK. It is an important thing. It is the assembly opcodes that will be writen in the allocated memory. Each bytes means a thing in the assembly.*/
	/* You can check what this mean in the end of this sourcecode. I let the assembly opcodes in there */
	BYTE assembly_opcodes[] = { 0x50, 0x53, 0x56, 0x51, 0x57, 0x52, 0x8B, 0x44, 0x24, 0x54, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x14, 0x08, 0x80, 0xFA, 0x00, 0x74, 0x2B,
		0x83, 0xF9, 0x39, 0x41, 0x72, 0xF2, 0x8B, 0xF8, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x51, 0xBB, 0x50, 0xC6, 0x10, 0x76, 0xFF, 0xD3, 0x59, 0x3C, 0x41, 0x72, 0xF3, 0x3C,
		0x5A, 0x77, 0xEF, 0x88, 0x07, 0x47, 0x41, 0x83, 0xF9, 0x39, 0x72, 0xE6, 0x5A, 0x5F, 0x59, 0x5E, 0x5B, 0x58, 0x8B, 0x75, 0x08, 0x8D, 0x8D, 0x58, 0xFF, 0xFF, 0xFF,
		0x50, 0XB8, return_hook_address_bytes[0], return_hook_address_bytes[1], return_hook_address_bytes[2], return_hook_address_bytes[3], 0xFF, 0xE0 };

	/* This is the assembly opcodes where the hook will be done. */
	BYTE hook_change_bytes[9] = { 0XBE, alloc_address_bytes[0], alloc_address_bytes[1], alloc_address_bytes[2], alloc_address_bytes[3], 0xFF, 0xE6, 0x90, 0x58};

	/* Writting all the opcodes to the allocated memory*/
	WriteProcessMemory(hprocess, (LPVOID)(alloc_address), assembly_opcodes, sizeof(assembly_opcodes), 0);	
	/* Doing the same, but this time to the address (place where the hook will be done) */
	WriteProcessMemory(hprocess, (LPVOID)(address), hook_change_bytes, sizeof(hook_change_bytes), 0);
	
	system("pause");

	exit(0);
}



/*
// this address (that we found with pattern scan) is before the hook
ExitLag.exe+5D497 - 8B 75 08              - mov esi,[ebp+08]
ExitLag.exe+5D49A - 8D 8D 58FFFFFF        - lea ecx,[ebp-000000A8]

*/

/*
// this is how the hook looks like after the pattern scan
ExitLag.exe+5D497 - BE 00004501           - mov esi, allocated_memory
ExitLag.exe+5D49C - FF E6                 - jmp esi
ExitLag.exe+5D49E - 90                    - nop
ExitLag.exe+5D49F - 58                    - pop eax
*/


/*
// and this is how the  memory that we allocated and wrote is.
allocated_memory + 00 - 50                    - push eax
allocated_memory + 01 - 53                    - push ebx
allocated_memory + 02 - 56                    - push esi
allocated_memory + 03 - 51                    - push ecx
allocated_memory + 04 - 57                    - push edi
allocated_memory + 05 - 52                    - push edx
allocated_memory + 06 - 8B 44 24 54           - mov eax,[esp+54]
allocated_memory + 0A - B9 00000000           - mov ecx,00000000 
allocated_memory + 0F - 8A 14 08              - mov dl,[eax+ecx]
allocated_memory + 12 - 80 FA 00              - cmp dl,00 
allocated_memory + 15 - 74 2B                 - je allocated_memory + 42
allocated_memory + 17 - 83 F9 39              - cmp ecx,39 
allocated_memory + 1A - 41                    - inc ecx
allocated_memory + 1B - 72 F2                 - jb allocated_memory + 0F
allocated_memory + 1D - 8B F8                 - mov edi,eax
allocated_memory + 1F - B9 00000000           - mov ecx,00000000 
allocated_memory + 24 - 51                    - push ecx
allocated_memory + 25 - BB 50C61076           - mov ebx,msvcrt.rand 
allocated_memory + 2A - FF D3                 - call ebx
allocated_memory + 2C - 59                    - pop ecx
allocated_memory + 2D - 3C 41                 - cmp al,41 
allocated_memory + 2F - 72 F3                 - jb allocated_memory + 24
allocated_memory + 31 - 3C 5A                 - cmp al,5A 
allocated_memory + 33 - 77 EF                 - ja allocated_memory + 24
allocated_memory + 35 - 88 07                 - mov [edi],al
allocated_memory + 37 - 47                    - inc edi
allocated_memory + 38 - 41                    - inc ecx
allocated_memory + 39 - 83 F9 39              - cmp ecx,39 
allocated_memory + 3C - 72 E6                 - jb allocated_memory + 24
allocated_memory + 3E - 5A                    - pop edx
allocated_memory + 3F - 5F                    - pop edi
allocated_memory + 40 - 59                    - pop ecx
allocated_memory + 41 - 5E                    - pop esi
allocated_memory + 42 - 5B                    - pop ebx
allocated_memory + 43 - 58                    - pop eax
allocated_memory + 44 - 8B 75 08              - mov esi,[ebp+08]
allocated_memory + 47 - 8D 8D 58FFFFFF        - lea ecx,[ebp-A8]
allocated_memory + 4D - 50                    - push eax
allocated_memory + 4E - B8 9FD44A00           - mov eax, return_address //
allocated_memory + 53 - FF E0                 - jmp eax

*/


/*
Some questions that you may ask:
- How did you know what pattern use?
	I analised and reverse engineered the exitlag with cheat engine debugger.

- Did you wrote the assembly code?
	Yes, I did.

*/