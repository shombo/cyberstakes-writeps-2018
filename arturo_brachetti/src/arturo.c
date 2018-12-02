#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "dump_stack.h"

void vuln(int win, char *str) {
    char buf[64];
    strcpy(buf, str);
    dump_stack((void **) buf, 23, (void **) &win);
    printf("win value (hex)  = %x\n", win);
    if (win == 1211332983) {
        execl("/bin/sh", "sh", NULL);
    } else {
        printf("Sorry, you lose.\n");
    }
    exit(0);
}

int main(int argc, char **argv) {

    char guess[100] = { 0 };
    int buffer_size = 1211332983;
    printf("You need to set win to %X\n", buffer_size);
    printf("Enter your string: ");
    fflush(stdout);
    fgets(guess,100,stdin);
    int len = strlen(guess);
    guess[len-1] = 0;

    uid_t euid = geteuid();
    setresuid(euid, euid, euid);
    vuln(0, guess);
    return 0;
}
