#include "stdio.h"

char xor_char(char input){
    return input ^= 0xa;
}

char* process(char input[]){

    for (unsigned i = 0; i < 4; ++i){
        input[i] = input[i] + 1;
        input[i] = xor_char(input[i]);
    }

    return input;
}

int main(int argc, char** argv){
    char input[] = "Hello!\n";
    process(input);
    printf("%s", input);
}
