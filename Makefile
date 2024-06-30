CC = gcc
LEX = flex
YACC = bison
MODULES = grammer.o Module/utils.o Module/readwrite.o Module/steganography.o

all: main.exe

test.exe: test.o $(MODULES)
	gcc -o $@ $^

%.o: %.c
	gcc -c $< -o $@

main.exe: lex.yy.c main.tab.c $(MODULES)
	$(CC) -o $@ $^ -lfl -lreadline

lex.yy.c: main.l main.tab.h main.tab.c
	$(LEX) main.l

main.tab.h main.tab.c: main.y
	$(YACC) -d main.y

clean:
	rm -f *.exe *.o lex.yy.c main.tab.c main.tab.h
	cd Module && make clean

