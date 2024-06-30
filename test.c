#include <stdio.h>
#include <malloc.h>
#include "Module/utils.h"
#include "grammer.h"

int main(){
//  inject_file("input.pcap", "output.pcap", "message.txt", "key.txt",
//              ENUM_IP, 3, ENUM_UDP, 4, ENUM_UDP, 5);
//  select_file("input.pcap", "output.txt", "key.txt", 
//              ENUM_IP, 3, ENUM_UDP, 4, ENUM_UDP, 5);
    help(ENUM_INJECT);
    help(ENUM_SELECT);
    help(ENUM_HELP);
}
