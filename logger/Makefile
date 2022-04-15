CFLAG = -shared -fPIC -Wincompatible-pointer-types -Wall
C = gcc
CXX = g++
HW = hw2
LOGGER = logger

all:$(HW).so $(LOGGER)

$(HW).so: $(HW:=.c) 
	$(C) -o $@ $(CFLAG) $^ -ldl

$(LOGGER): $(LOGGER:=.cpp) 
	$(CXX) -o $@ $^ 

clean:
	$(RM) $(HW:=.so) $(LOGGER)