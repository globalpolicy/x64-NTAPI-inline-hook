#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

//x64 inline API hooking example(NtOpenProcess)
//Author : globalpolicy
//17th May, 2018 - 11:42 PM

/*
NOTE: Disable incremental linking!
With incremental linking, address of operator(&) for functions give the addresses of indirection jumps, not the actual location of the functions
NOTE: Compile as x64 executable. getRemoteProcAddress() depends on it.
*/

/*
Relevant sites for this project:
https://docs.microsoft.com/en-us/cpp/build/parameter-passing
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntddk/nf-ntddk-ntopenprocess
https://msdn.microsoft.com/en-us/library/gg750647.aspx
https://msdn.microsoft.com/en-us/library/cc704588.aspx
https://www.codeproject.com/Articles/4610/Three-Ways-to-Inject-Your-Code-into-Another-Proces (this could never be irrelevant)
http://c0dew0rth.blogspot.com/2016/01/openprocess-api-hook-in-msvcc.html (myself, ~ 2.5 years ago)
*/

LPVOID getRemoteProcAddress(char* dllName, char* procName, int targetPid);
void injectCode(int hookPid, int protectPid, char* dllName, char* procName);
LPVOID injectTrampoline(HANDLE hProcess, int protectPid);
BOOL writeNOPs(HANDLE hProcess, LPVOID lpAddress, int numBytes);


void main() {

	injectCode(5348, 6324, "ntdll.dll", "NtOpenProcess");
	getchar();

}

LPVOID getRemoteProcAddress(char* dllName, char* procName, int targetPid) {
	LPVOID retval = NULL;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
	if (hProcess) {
		DWORD reqSizeOfBuffer = 0;
		if (EnumProcessModulesEx(hProcess, 0, 0, &reqSizeOfBuffer, LIST_MODULES_64BIT)) {
			HMODULE* modulesBuffer = (HMODULE*)malloc(reqSizeOfBuffer);
			if (EnumProcessModulesEx(hProcess, modulesBuffer, reqSizeOfBuffer, &reqSizeOfBuffer, LIST_MODULES_64BIT)) {
				int seizeOfHMODULE = sizeof(HMODULE);
				int numberOfModules = reqSizeOfBuffer / seizeOfHMODULE;
				for (int i = 0; i < numberOfModules; i++) {
					HMODULE hModule = modulesBuffer[i];
					char* moduleName = (char*)calloc(256, sizeof(char));
					if (GetModuleBaseName(hProcess, hModule, moduleName, 256) <= 256) {
						if (_stricmp(moduleName, dllName) == 0) {
							HMODULE localModuleAddress = GetModuleHandle(dllName);
							FARPROC localProcAddress = GetProcAddress(localModuleAddress, procName);
							DWORD offset = (DWORD)localProcAddress - (DWORD)localModuleAddress;
							retval = (LPVOID)((DWORD)hModule + offset);
							break;
						}
					}
				}
			}
		}
		CloseHandle(hProcess);
	}

	return retval;
}

void injectCode(int hookPid, int protectPid, char* dllName, char* procName) {

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hookPid);
	if (hProcess) {
		LPVOID hookAtAddress = getRemoteProcAddress(dllName, procName, hookPid);

		if (hookAtAddress) {
			LPVOID trampolineAddress = injectTrampoline(hProcess, protectPid);
			if (trampolineAddress) {

				char jumpBytes[] = { 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0 };
				/*
				The fact that Visual Studio 2017's C compiler still doesn't support inline x64 asm sucks!
				Disassembly of the above opcodes:(x64dbg)

				00000000777C9B00 | B8 EF BE AD DE           | mov eax,DEADBEEF                               |
				00000000777C9B05 | FF E0                    | jmp rax                                        |
				*/

				memcpy(&jumpBytes[1], &trampolineAddress, 4);//patch DEADBEEF to trampolineAddress
				int sizeOfJumpBytes = sizeof(jumpBytes);


				if (writeNOPs(hProcess, hookAtAddress, 11)) //NOP out 11 bytes in remote process at hookAtAddress
				{
					SIZE_T numBytesWritten = 0;
					if (!WriteProcessMemory(hProcess, hookAtAddress, jumpBytes, sizeOfJumpBytes, &numBytesWritten) || numBytesWritten != sizeOfJumpBytes) { //Write jump bytes to remote process
						printf("WriteProcessMemory at %0x4 failed!\n", hookAtAddress);
					}
					else {
						printf("Inline hook set!\n");
					}
				}
				/*
				Say it is NtOpenProcess that we're hooking in the remote process. Before writing our jump bytes, the remote memory starting at hookAtAddress looks like: (x64dbg)

				...............
				00000000777C9B00 | 4C 8B D1                 | mov r10,rcx                                    | NtOpenProcess
				00000000777C9B03 | B8 23 00 00 00           | mov eax,23                                     | 23:'#'
				00000000777C9B08 | 0F 05                    | syscall                                        |
				00000000777C9B0A | C3                       | ret                                            |
				00000000777C9B0B | 0F 1F 44 00 00           | nop dword ptr ds:[rax+rax],eax                 |
				00000000777C9B10 | 4C 8B D1                 | mov r10,rcx                                    | NtSetInformationFile
				00000000777C9B13 | B8 24 00 00 00           | mov eax,24                                     | 24:'$'
				00000000777C9B18 | 0F 05                    | syscall                                        |
				00000000777C9B1A | C3                       | ret                                            |
				00000000777C9B1B | 0F 1F 44 00 00           | nop dword ptr ds:[rax+rax],eax                 |
				00000000777C9B20 | 4C 8B D1                 | mov r10,rcx                                    | ZwMapViewOfSection
				00000000777C9B23 | B8 25 00 00 00           | mov eax,25                                     | 25:'%'
				00000000777C9B28 | 0F 05                    | syscall                                        |
				00000000777C9B2A | C3                       | ret                                            |
				...............

				Upon close inspection, it is immediately clear that each ntdll function has 11 bytes starting from 4C and ending at C3 i.e. for our case, the following:

				00000000777C9B00 | 4C 8B D1                 | mov r10,rcx                                    | NtOpenProcess
				00000000777C9B03 | B8 23 00 00 00           | mov eax,23                                     | 23:'#'
				00000000777C9B08 | 0F 05                    | syscall                                        |
				00000000777C9B0A | C3                       | ret                                            |

				I don't know why or how the nop dword ptr ds:[rax+rax],eax comes into play, but GetProcAddress on any ntdll function points to a mov r10,rcx address
				The only difference between the otherwise completely different ntdll functions is the syscall id moved into eax at the 5th byte starting from 4C
				Anyway, we then NOP out the 11 familiar bytes to get, unremarkably, the following, eleven 0x90 bytes:

				00000000777C9B00 | 90                       | nop                                            | NtOpenProcess
				00000000777C9B01 | 90                       | nop                                            |
				00000000777C9B02 | 90                       | nop                                            |
				00000000777C9B03 | 90                       | nop                                            |
				00000000777C9B04 | 90                       | nop                                            |
				00000000777C9B05 | 90                       | nop                                            |
				00000000777C9B06 | 90                       | nop                                            |
				00000000777C9B07 | 90                       | nop                                            |
				00000000777C9B08 | 90                       | nop                                            |
				00000000777C9B09 | 90                       | nop                                            |
				00000000777C9B0A | 90                       | nop                                            |

				Upon successful NOPing, we bluntly write our redirection jump code:

				00000000777C9B00 | B8 EF BE AD DE           | mov eax,DEADBEEF                               |
				00000000777C9B05 | FF E0                    | jmp rax                                        |
				00000000777C9B07 | 90                       | nop                                            |
				00000000777C9B08 | 90                       | nop                                            |
				00000000777C9B09 | 90                       | nop                                            |
				00000000777C9B0A | 90                       | nop                                            |

				Whatever of the NOPs remain, we do not care. Our trampoline function subsumes the default functionality of the original 11 bytes - along with our filter logic of course
				*/
				/*
				NOTE: Since VirtualAllocEx() to allocate memory for trampoline seems to return 4-byte(32-bit) address even in x64 compilation, the | MOV EAX,DEADBEEF | JMP RAX | jump code works.
				If however VirtualAllocEx() gives back an address greater than FFFFFFFF, which can theoretically happen in x64 compilation, the JMP RAX bytes will be overwritten and things will go haywire.
				So, it will be safest to prepare for that and NOP out not 11 bytes at the hook address but 16 bytes since then we'll require a new bigger jump code.
				The remote memory should look like below after patching:
				00000000777C9B00 | 48 B8 32 54 76 98 78 56 34 12        | mov rax,1234567898765432                       | NtOpenProcess
				00000000777C9B0A | FF E0                                | jmp rax                                        |
				00000000777C9B0C | 90                                   | nop                                            |
				00000000777C9B0D | 90                                   | nop                                            |
				00000000777C9B0E | 90                                   | nop                                            |
				00000000777C9B0F | 90                                   | nop                                            |
				Notice that the jumpBytes[] array will need to be like {0x48,0xB8,0x32,0x54,0x76,0x98,0x78,0x56,0x34,0x12,0xFF,0xE0}, which is 12 bytes long; 
				also note the trampoline address will need to be patched at jumpBytes[2] and not at jumpBytes[1] 
				Contrast that with the current implementation's patch :
				00000000777C9B00 | B8 00 00 03 02                       | mov eax,2030000                                | NtOpenProcess
				00000000777C9B05 | FF E0                                | jmp rax                                        |
				00000000777C9B07 | 90                                   | nop                                            |
				00000000777C9B08 | 90                                   | nop                                            |
				00000000777C9B09 | 90                                   | nop                                            |
				00000000777C9B0A | 90                                   | nop                                            |
				00000000777C9B0B | 0F 1F 44 00 00                       | nop dword ptr ds:[rax+rax],eax                 |
				And with the original disassembly :
				00000000777C9B00 | 4C 8B D1                             | mov r10,rcx                                    | NtOpenProcess
				00000000777C9B03 | B8 23 00 00 00                       | mov eax,23                                     | 23:'#'
				00000000777C9B08 | 0F 05                                | syscall                                        |
				00000000777C9B0A | C3                                   | ret                                            |
				00000000777C9B0B | 0F 1F 44 00 00                       | nop dword ptr ds:[rax+rax],eax                 |

				*/

			}
			else {
				printf("Trampoline injection failed!\n");
			}
		}
		else {
			printf("Couldn't find %s!%s in remote process!\n", dllName, procName);
		}
		CloseHandle(hProcess);
		
	}
	else {
		printf("OpenProcess failed!\n");
	}
}

LPVOID injectTrampoline(HANDLE hProcess, int protectPid) {

	char trampolineOpcodes[] = { 0x41,0x8B,0x01,0x3D,0x84,0x10,0x00,0x00,0x75,0x06,0xB8,0x22,0x00,0x00,0xC0,0xC3,0x4C,0x8B,0xD1,0xB8,0x23,0x00,0x00,0x00,0x0F,0x05,0xC3 };
	/*
	The fact that Visual Studio 2017's C compiler still doesn't support inline x64 asm sucks!

	PSEUDO-ASM:
	1	mov eax, dword ptr [r9]  -->R9 register contains the pointer to CLIENT_ID structure whose first DWORD is ProcessId
	2	cmp eax,1084  -->compare with our desired ProcessId to protect
	3	jne 6  -->if not equal, goto third line from here
	4	mov eax,c0000022  -->EAX register, which contains the return value, is assigned 0xc0000022 i.e. STATUS_ACCESS_DENIED
	5	ret  -->return to kernel32.dll module with the STATUS_ACCESS_DENIED output
	6	mov r10,rcx  --------------------------------\
	7	mov eax,23   --(syscall id for NtOpenProcess)-\__[standard code in any Ntdll function]
	8	syscall      ---------------------------------/
	9	ret          --------------------------------/

	ACTUAL DISASSEMBLY (x64dbg):
	00000000001A0000 | 41 8B 01                 | mov eax,dword ptr ds:[r9]                      |
	00000000001A0003 | 3D 84 10 00 00           | cmp eax,1084                                   |
	00000000001A0008 | 75 06                    | jne 1A0010                                     |
	00000000001A000A | B8 22 00 00 C0           | mov eax,C0000022                               |
	00000000001A000F | C3                       | ret                                            |
	00000000001A0010 | 4C 8B D1                 | mov r10,rcx                                    |
	00000000001A0013 | B8 23 00 00 00           | mov eax,23                                     | 23:'#'
	00000000001A0018 | 0F 05                    | syscall                                        |
	00000000001A001A | C3                       | ret                                            |

	Note: I had first avoided the mov eax,C0000022 line but it resulted in an INVALID_HANDLE_EXCEPTION (or sth like that). I looked up the return value of NtOpenProcess
	and x64 calling conventions and it turns out : (msdn)
	"A scalar return value that can fit into 64 bits is returned through RAX..."
	Whew! At least there's one thing in common with x86
	So, I decided to give a STATUS_ACCESS_DENIED return value (0xC0000022); and that stopped the exception and as a bonus, the hooked application(Win7 x64 taskmanager in my case)
	gave me a warm "Access is denied" error message upon trying to end the protected process.
	*/

	memcpy(&trampolineOpcodes[4], &protectPid, 4);//patch the PID to protect
	long sizeOfTrampoline = sizeof(trampolineOpcodes);

	LPVOID lpAddressTrampoline = VirtualAllocEx(hProcess, 0, sizeOfTrampoline, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpAddressTrampoline) {
		SIZE_T bytesWritten = 0;
		if (WriteProcessMemory(hProcess, lpAddressTrampoline, trampolineOpcodes, sizeOfTrampoline, &bytesWritten) && bytesWritten == sizeOfTrampoline) {
			printf("Wrote trampoline to remote process successfully!\n");
		}
		else {
			printf("WriteProcessMemory failed!\n");
			if (VirtualFreeEx(hProcess, lpAddressTrampoline, 0, MEM_RELEASE)) {
			}
		}
	}
	else {
		printf("VirtualAllocEx failed!\n");
	}
	return lpAddressTrampoline;
}

BOOL writeNOPs(HANDLE hProcess, LPVOID lpAddress, int numBytes) {
	BOOL retval = FALSE;

	char* nopArray = (char*)calloc(numBytes, sizeof(char));
	char nop = 0x90;
	for (int i = 0; i < numBytes; i++) {
		memcpy(&nopArray[i], &nop, 1);//fill buffer with NOP bytes
	}

	if (hProcess) {
		SIZE_T numBytesWritten = 0;
		if (WriteProcessMemory(hProcess, lpAddress, nopArray, numBytes, &numBytesWritten)) {//write NOPs to remote process
			if (numBytesWritten == numBytes)
				retval = TRUE;
		}
	}

	return retval;
}
