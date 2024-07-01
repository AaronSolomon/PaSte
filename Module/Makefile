all: readwrite.o steganography.o analysis.o

%.o: %.c %.h utils.h
	gcc -c $<

clean:
	rm -f *.o test.exe
