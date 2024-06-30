%{
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "Module/utils.h"
#include "grammer.h"


void yyerror(const char *s, ...);

extern int yylineno;

FILE *yyset_in(FILE *);

%}

%union {
    char *strval;
    int  intval;
}

%token <strval> STRING
%token <intval> NUMBER
%token <intval> ENUM_PROTO

%token <intval> SELECT
%token FROM
%token INTO

%token <intval> INJECT
%token USEKEY
%token PROTO
%token WITH
%token OUT
%token EOL
%token IF
%token DO
%token ELSE
%type <strval> outfile

%token HELP
%token <intval> DEF
%token <intval> GRAMMER
%type <intval> help_option


%start stmt

%%
stmt:
    | inject_stmt 
    | select_stmt 
    | help_stmt
    ;

 /* inject */
inject_stmt: 
       INJECT STRING
       INTO STRING
       USEKEY STRING
       IF ENUM_PROTO '[' NUMBER ']'
       DO ENUM_PROTO '[' NUMBER ']' 
       ELSE ENUM_PROTO '[' NUMBER ']'
       outfile ';'
 	{ inject_file( $4, $22, $2, $6, $8, $10, $13, $15, $18, $20); } 
       ;

 
 /* default outfile */
 outfile: OUT STRING { $$ = $2 ;}
    | { $$ = "covert.pcap" ;}

    ;

 /* else protocol[offset] */


/* select */
select_stmt:
       SELECT FROM STRING
       INTO STRING
       USEKEY STRING
       IF ENUM_PROTO '[' NUMBER ']'
       DO ENUM_PROTO '[' NUMBER ']' 
       ELSE ENUM_PROTO '[' NUMBER ']'
       ';'
       { select_file( $3, $5, $7, $9, $11, $14, $16, $19, $21); } 
       ;	

 /* help */
help_stmt:
      HELP help_option ';' { help($2); }
      ;
help_option: { $$ = 0; }
      | '*'  { $$ = 0; }
      | SELECT { $$ = $1; }
      | INJECT { $$ = $1; }
      | DEF    { $$ = $1; }
      | GRAMMER    { $$ = $1; }
      ;


%%

void yyerror(const char *s, ...){
    va_list ap;
    va_start(ap, s);

    fprintf(stderr, "%d: error: ", yylineno);
    vfprintf(stderr, s, ap);
    fprintf(stderr, "\n");

    va_end(ap);
}

int main(int argc, char** argv){
     
    extern FILE *yyin;
    if ( argc > 1 ){
    	if( !(yyin = fopen(argv[1], "r")) ) {
        	perror(argv[1]);
        	exit(1);
    	}
    } 
    /*
    char* buffer = NULL;
    while( ( buffer = readline("> ")) ){
	add_history(buffer);
	// strcat(buffer, "\n");
	// yyset_in(fmemopen(buffer, strlen(buffer), "r"));
	yyparse();
        free(buffer);
    }
    */
    yyparse();
  
   return 0;
}
