#include <stdio.h>
#include <malloc.h>
#include "utils.h"
#include "readwrite.h"
#include "steganography.h"

int main(){
    struct fields fields;
    struct fields* fields_ptr = &fields;
    
    set_fields(fields_ptr, ENUM_IP, 2, ENUM_IP, 4, ENUM_TCP, 6);
    /* Get the bytestreams: selector, field1, field2 from the original file*/
    read("TEST1", fields_ptr);
    /* Copy  */

    /* Inject hidden information into bytestream field1 and field2 with selector. */
    inject("hidden", "key", fields_ptr);
    /* Write the new bytestream field1 and field2 into newfile. */
    write("TEST2", "TEST3", fields_ptr);

    /* Free the bytestreams. */
    clear_bytestream(fields_ptr);

}
