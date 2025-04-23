#include <stdio.h>
#include <stdlib.h>

void vulnerable() {
    char buffer[64];

    // Intentionally insecure: reading 128 bytes into a 64-byte buffer
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);  // Unsafe use — may overflow 'buffer'
    
    printf("You entered: %s\n", buffer);
}

void secret() {
    printf("You've reached the secret function!\n");
    system("/bin/sh");  // Spawn a shell for exploit demonstration
}

int main() {
    vulnerable();
    printf("Done.\n");
    return 0;
}