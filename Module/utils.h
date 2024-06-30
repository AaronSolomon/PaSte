#ifndef _UTILS_H_
#define _UTILS_H_
struct fields{
    struct {
        int protocol;
        int offset;
        char* bytestream;
        int length;
    } selector, field1, field2;
};

enum{
    ENUM_IP,
    ENUM_UDP,
    ENUM_TCP
};

enum {
    ENUM_HELP = 0,
    ENUM_DEF,
    ENUM_GRAMMER,
    ENUM_SELECT,
    ENUM_INJECT
};

int set_fields(struct fields* fields, int p0, int o0, int p1, int o1, int p2, int o2);
int clear_bytestream(struct fields* fields);
#endif

