#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win_function() {
    printf("Congratulations! You've successfully exploited the program!\n");
    system("/bin/cat flag.txt");
}

void vulnerable_function() {
    char buffer[64];
    printf("Enter your input: ");
    gets(buffer);
    printf("You entered: %s\n", buffer);
}

int main() {
    printf("Welcome to the ret2win challenge!\n");
    printf("Can you call the win_function?\n");
    
    vulnerable_function();
    
    printf("Goodbye!\n");
    return 0;
}