#include <stdio.h>
#include "utils.h"

int inject(char* hiddenfile, char* keyfile, struct fields* fields){
    puts("=========== inject() ==========");
    printf("Hidden Information: %s\n", hiddenfile);
    printf("Secret Key: %s\n", keyfile);
    printf(" Selector: %d[%d]\n", fields->selector.protocol, fields->selector.offset);
    printf("   Field1: %d[%d]\n", fields->field1.protocol, fields->field1.offset);
    printf("   Field2: %d[%d]\n", fields->field2.protocol, fields->field2.offset);
    puts("========== return errorcode ==========");
}

int select(char* infile, char* outfile, char* keyfile, struct fields* fields){
    puts("=========== select() ==========");
    printf("Input File: %s\n", infile);
    printf("Secret Key: %s\n", keyfile);
    printf(" Selector: %d[%d]\n", fields->selector.protocol, fields->selector.offset);
    printf("   Field1: %d[%d]\n", fields->field1.protocol, fields->field1.offset);
    printf("   Field2: %d[%d]\n", fields->field2.protocol, fields->field2.offset);
    printf("Display Hidden Information?\n");
    printf("Output File: %s\n", outfile);
    puts("========== return errorcode ==========");
}
