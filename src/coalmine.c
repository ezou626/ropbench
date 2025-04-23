#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    system("/bin/sh");
}

void callme() {
    __asm__ volatile ("pop %%rdi\n\t"
        "ret"
        :
        :
        : "rdi");
  }

void vuln() {
    char name[64];
    char buffer[64];

    fgets(name, sizeof(name), stdin);
    printf(name);

    printf("\nSay something:\n");
    gets(buffer);
}

int main() {
    setbuf(stdout, NULL);
    alarm(15);
    vuln();
    return 0;
}