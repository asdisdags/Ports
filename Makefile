all: scanner puzzlesolver

scanner: udpport.cpp
	g++ --std=c++11 udpport.cpp -o scanner
puzzlesolver: puzzlesolver.cpp
	g++ --std=c++11 puzzlesolver.cpp -o puzzlesolver