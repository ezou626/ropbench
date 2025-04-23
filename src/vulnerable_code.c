#include <stdio.h>
#include <stdlib.h>

int foo = 0;

void callme() {
    __asm__ volatile ("pop %%rdi\n\t"
        "ret"
        :
        :
        : "rdi");
  }

void vuln() {
    char buffer[64];
    puts("Overflow me");
    gets(buffer);
}

void marker(const char *msg) {
    puts(msg);
}

int main() {
    marker("hello from marker"); 
    if (foo == 0x55) {
        callme();
    }
    vuln();
    return 0;
}