CFLAG = -Iinclude
CXX = g++
HW = hw1
SRC:=$(shell find src/ -name '*.c')

OBJS:= $(SRC_C:%.c=%.o)


all:$(HW).o

$(HW).o: $(HW:=.cpp) $(SRC)
	$(CXX) -o $@ $(CFLAG)  $^

test: all
	./$(HW:=.o)

su: all
	sudo ./$(HW:=.o)

clean:
	$(RM) $(HW:=.o) $(SRC)