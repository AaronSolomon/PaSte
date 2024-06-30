#include <stdio.h>
#include <malloc.h>
#include "utils.h"

int read(char* infile, struct fields* fields){
    puts("=============== read() ===============");
    printf("Read from: %s\n", infile);
    printf(" Selector: %d[%d]\n", fields->selector.protocol, fields->selector.offset);
    printf("   Field1: %d[%d]\n", fields->field1.protocol, fields->field1.offset);
    printf("   Field2: %d[%d]\n", fields->field2.protocol, fields->field2.offset);
    puts("========== return errorcode ==========");
}

int write(char* infile, char* outfile, struct fields* fields){
    puts("=============== write() ==============");
    printf("Write to: %s\n", outfile);
    printf(" Selector(ignore)\n");
    printf("   Field1: %d[%d]\n", fields->field1.protocol, fields->field1.offset);
    printf("   Field2: %d[%d]\n", fields->field2.protocol, fields->field2.offset);
    puts("========== return errorcode ==========");
}
