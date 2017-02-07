#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include "pirate_mark_lava.h"

int testFunc(int test){
    int val = test;
    vm_lava_query_buffer(&val, sizeof(int), 0, 0, 0, 0);
    return val + 5;
}

int main(int argc, char **argv){
    
    // simple copy
    int taint = argc;
    int taintCopy;
    vm_lava_label_buffer(&taint, sizeof(int), 0, 0, 0, 0, 1, 0);
    taintCopy = taint;
    vm_lava_query_buffer(&taintCopy, sizeof(int), 0, 0, 0, 0);

    // string copy
    char *tainted_string = "This is a tainted string";
    char *tainted_strcpy = (char*)malloc(strlen(tainted_string));
    vm_lava_label_buffer(tainted_string, strlen(tainted_string),
        0, 0, 0, 0, 1, 0);
    strcpy(tainted_strcpy, tainted_string);
    vm_lava_query_buffer(tainted_strcpy, strlen(tainted_strcpy), 0, 0, 0, 0);

    // function parameter
    int tcn = testFunc(taint);

    // TCN arithmetic
    tcn = tcn + 5;
    vm_lava_query_buffer(&tcn, sizeof(int), 0, 0, 0, 0);

    // helper function (fdiv)
    float div = 2.0;
    vm_lava_label_buffer(&div, sizeof(float), 0, 0, 0, 0, 1, 0);
    float frac = 8.2 / div;
    vm_lava_query_buffer(&frac, sizeof(float), 0, 0, 0, 0);

    // helper function that does memory write (maybe cmpxchg)

    return 0;
}
