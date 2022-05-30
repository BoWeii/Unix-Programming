CFLAG = -Wall -lcapstone
CXX = g++
HW = hw4
LIBNAME = capstone


all:$(HW)

$(HW): $(HW:=.cpp) sdb.cpp
	$(CXX) $^ $(CFLAG) -o $@

test: all
	./$(HW)

s1: all
	sudo ./$(HW) -s scripts/hello3.txt 2>&1 | grep -v '^\*\*'

s2: all
	sudo ./$(HW) -s scripts/guess.txt sample/guess.nopie 2>&1 | grep -v '^\*\*'

s: all
	sudo ./$(HW) sample/hello64
n: all
	sudo ./$(HW) -s scripts/a.txt sample/hello64

clean:
	$(RM) $(HW) $(SRC)