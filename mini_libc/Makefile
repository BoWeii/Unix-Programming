LIB64_S:=libmini64.asm
LIB64_O:=libmini64.o
LIB_C:=libmini.c
LIB_O:=libmini.o
LIB_SO:=libmini.so
START_O:=start.o

all: $(LIB_SO) $(START_O)
	

$(START_O):
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o

$(LIB_SO): $(START_O)
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC $(LIB64_S) -o $(LIB64_O)
	gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib $(LIB_C)
	ld -shared -o $(LIB_SO) $(LIB64_O) $(LIB_O)

write1: write1.c $(LIB_SO) 
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI write1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o write1 write1.o start.o -L. -L.. -lmini
	rm write1.o

alarm1: alarm1.c $(LIB_SO)
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini
	rm alarm1.o

alarm2: alarm2.c $(LIB_SO)
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini
	rm alarm2.o

alarm3: alarm3.c $(LIB_SO)
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm3.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini
	rm alarm3.o

jmp1: jmp1.c $(LIB_SO)
	gcc -o jmp1.o -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI jmp1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini
	rm jmp1.o

clean:
	rm -f *.o *.so write1 alarm1 alarm2 alarm3 jmp1