# Ports
Project 2 - Ports!
This project includes two files that need to be compiled and executed.

puzzlesolver.cpp
udpport.cppp

To compile the files simply write "make all" in the directory where the files are located.

First one is udpport.cpp which includes a scanner that each and every port from a low port to a high port.

./scanner <ip> <low_port> <high_port>

The scanner will then display the ports that are currently open. 


puzzlesolver.cpp then uses these open ports to function. Puzzlesolver sends to the open ports the appropriate messages and the ports will then send back a response, which is then further worked with.

./puzzlesolver <ip> <port1> <port2> <port3> <port4>

The hidden ports and secret phrase are automatically worked with and the secret phrase is sent to the hidden ports. 

The parts we did correctly:

We believe that we should get full marks for the scanner as well as it works fully as it is intended to do.

We believe we should get full marks for checksum, oracle port and evil bit, as we spent a lot of time developing and carefully configuring all parts of the assignment. 

We did not attempt the bonus phase.

Time taken: 49 hours.