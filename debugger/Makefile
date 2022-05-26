CFLAG = -Iinclude -Wall
CXX = g++
HW = hw4



all:$(HW)

$(HW): $(HW:=.cpp) sdb.cpp
	$(CXX) -o $@ $(CFLAG)  $^

test: all
	./$(HW)

s1: all
	sudo ./$(HW) -s scripts/hello1.txt  2>&1 | grep -v '^\*\*'

s2: all
	sudo ./$(HW) -s scripts/guess.txt  2>&1 | grep -v '^\*\*'

clean:
	$(RM) $(HW) $(SRC)