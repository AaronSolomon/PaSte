test.exe: test.o readwrite.o steganography.o utils.o
	gcc -o $@ $^

%.o: %.c %.h utils.h
	gcc -c $<

clean:
	rm -f *.o test.exe
