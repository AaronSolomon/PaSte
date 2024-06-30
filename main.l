%option noyywrap yylineno case-insensitive
%{
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "main.tab.h"
#include "Module/utils.h"

void yyerror(char *s, ...);
%}

%%

 /* keyword */
SELECT  { yylval.intval = ENUM_SELECT; return SELECT; }
FROM    { return FROM; }
INTO    { return INTO; }

INJECT  { yylval.intval = ENUM_INJECT; return INJECT; }
USEKEY  { return USEKEY; }
PROTO   { return PROTO; }
WITH    { return WITH; }
OUT     { return OUT; }
IF	    { return IF; }
DO	    { return DO; }
ELSE	{ return ELSE; }

HELP    { yylval.intval = ENUM_HELP; return HELP; }
DEF    { yylval.intval = ENUM_DEF; return DEF; }
GRAMMER    { yylval.intval = ENUM_GRAMMER; return GRAMMER; }

  /* protocol */
ip  { yylval.intval = ENUM_IP; return ENUM_PROTO; }
udp { yylval.intval = ENUM_UDP; return ENUM_PROTO; }
tcp { yylval.intval = ENUM_TCP; return ENUM_PROTO; }

  /* numbers */
[0-9]+  { yylval.intval = atoi(yytext); return NUMBER; }

  /* strings */
[_.A-Z]+ { yylval.strval = strdup(yytext); return STRING; }

  /* skip whitespace */
[ \t]   { }  
\n      { return EOF; } 
.       { return yytext[0]; } /* return any other character as itself */

%%
