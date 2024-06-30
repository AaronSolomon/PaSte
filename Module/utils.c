#include <malloc.h>
#include "utils.h"

int set_fields(struct fields* fields, int p0, int o0, int p1, int o1, int p2, int o2){
    /* selector */
    fields->selector.protocol = p0;
    fields->selector.offset = o0;
    fields->selector.bytestream = NULL;
    fields->selector.length = 0;
    /* field1 */
    fields->field1.protocol = p1;
    fields->field1.offset = o1;
    fields->field1.bytestream = NULL;
    fields->field1.length = 0;
    /* field2 */
    fields->field2.protocol = p2;
    fields->field2.offset = o2;
    fields->field2.bytestream = NULL;
    fields->field2.length = 0;
}

int clear_bytestream(struct fields* fields){
    /* selector */
    if(fields->selector.bytestream != NULL)
        free(fields->selector.bytestream);
    fields->selector.bytestream = NULL;
    fields->selector.length = 0;
    /* field1 */
    if(fields->field1.bytestream != NULL)
        free(fields->field1.bytestream);
    fields->field1.bytestream = NULL;
    fields->field1.length = 0;
    /* field2 */
    if(fields->field2.bytestream != NULL)
        free(fields->field2.bytestream);
    fields->field2.bytestream = NULL;
    fields->field2.length = 0;
}
