#include <stdio.h>
#include "Module/utils.h"
#include "Module/readwrite.h"
#include "Module/steganography.h"

void inject_file(char* infile, char* outfile, char* hiddenfile, char* keyfile,
                 int proto0, int offset0, int proto1, int offset1, int proto2, int offset2){

    struct fields fields;
    struct fields* fields_ptr = &fields;

    /* Config the information of selector, field1 and field2. */
    set_fields(fields_ptr, proto0, offset0, proto1, offset1, proto2, offset2);
    /* Get the bytestreams of selector, field1 and field2 from the infile. */
    read(infile, fields_ptr);

    /* Inject hidden message into bytestreams of field1 and field2 with selector. */
    inject(hiddenfile, keyfile, fields_ptr);
    /* Write the new bytestreams field1 and field2 into outfile. */
    write(infile, outfile, fields_ptr);

    /* Free the bytestreams. */
    clear_bytestream(fields_ptr);

}

void select_file(char* infile, char* outfile, char* keyfile,
                 int proto0, int offset0, int proto1, int offset1, int proto2, int offset2){

    struct fields fields;
    struct fields* fields_ptr = &fields;

    /* Config the information of selector, field1 and field2. */
    set_fields(fields_ptr, proto0, offset0, proto1, offset1, proto2, offset2);
    /* Get the bytestreams of selector, field1 and field2 from the infile. */
    read(infile, fields_ptr);

    /* Get the  hidden message from bytestreams of field1 and field2 with selector
     * and write into . */
    select(infile, outfile, keyfile, fields_ptr);

    /* Free the bytestreams. */
    clear_bytestream(fields_ptr);

}

void help(int type){
    if(!type){
        /* Title */
        puts("Compiler Term Project: Steganography");
    }
    if(!type || type == ENUM_DEF){
        /* Define Grammer */
        puts("DEFINITION");
        puts("\tSELECT");
        puts("\tINJECT");
    }
    if(!type || type == ENUM_SELECT || type == ENUM_INJECT || type == ENUM_GRAMMER ){
        /* Grammer */
        puts("GRAMMAR");
    }
    if(!type || type == ENUM_INJECT || type == ENUM_GRAMMER ){
        /* Steganography */
        puts("\tSteganography");
        printf("\t");
    }
    if(!type || type == ENUM_INJECT || type == ENUM_GRAMMER ){
        puts("  INJECT \e[4mmessage\e[0m INTO \e[4min.pcap\e[0m USEKEY \e[4mkey\e[0m "
             "IF \e[4mproto1[offset1]\e[0m DO \e[4mproto2[offset2]\e[0m ELSE \e[4mproto3[offset3]\e[0m "
             "OUT \e[4mout.pcap\e[0m;");
    }
    if(!type || type == ENUM_INJECT || type == ENUM_GRAMMER ){
        printf("\t");
    }
    if(!type || type == ENUM_INJECT || type == ENUM_GRAMMER ){
        puts("  INJECT \e[4mmessage\e[0m INTO \e[4min.pcap\e[0m USEKEY \e[4mkey\e[0m "
             "IF \e[4mproto1[offset1]\e[0m DO \e[4mproto2[offset2]\e[0m ELSE \e[4mproto3[offset3]\e[0m;");
    }
    if(!type || type == ENUM_SELECT || type == ENUM_GRAMMER ){
        /* Extract */
        puts("\tExtract");
        printf("\t");
    }
    if(!type || type == ENUM_SELECT || type == ENUM_GRAMMER ){
        puts("  SELECT FROM \e[4mcovert.pcap\e[0m INTO \e[4mextract\e[0m USEKEY \e[4mkey\e[0m "
             "IF \e[4mproto1[offset1]\e[0m DO \e[4mproto2[offset2]\e[0m ELSE \e[4mproto3[offset3]\e[0m;");
    }
    if(!type){
        puts("");
        /* Argument */
        puts("ARGUMENT");
        /* in.pcap */
        puts("\t\e[4min.pcap\e[0m");
        puts("\t\tThe input PCAP file is used for hiding data.");
        /* out.pcap */
        puts("\t\e[4mout.pcap\e[0m");
        puts("\t\tThe output PCAP file contains hidden data. The default filename is \e[3mcovert.pcap\e[0m.");
        /* covert.pcap */
        puts("\t\e[4mcovert.pcap\e[0m");
        puts("\t\tThe input PCAP file may contain hidden data.");
        /* message */
        puts("\t\e[4mmessage\e[0m");
        puts("\t\tThe file has the data you want to hide.");
        /* key */
        puts("\t\e[4mkey\e[0m");
        puts("\t\tThe file has the key used to do hidden data.");
        /* extract */
        puts("\t\e[4mextract\e[0m");
        puts("\t\tThe file has the extracted data from covert.pcap.");
        /* proto */
        puts("\t\e[4mproto\e[0m");
        puts("\t\tThe protocol name, including \e[3mIP, UDP, TCP\e[0m");
        /* offset */
        puts("\t\e[4moffset\e[0m");
        puts("\t\tThe offset of the \e[4mproto\e[0m header.");
        /* proto[offset] */
        puts("\t\e[4mproto1[offset1]\e[0m");
        puts("\t\tThe byte is used to select the byte which is used to hide data.");
        puts("\t\e[4mproto2[offset2]\e[0m");
        puts("\t\e[4mproto3[offset3]\e[0m");
        puts("\t\tThe byte is used to hide data.");
    }
        puts("");
}
