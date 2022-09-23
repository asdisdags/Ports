#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sstream>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>

using namespace std;

char buffer[4096];

void read_message(int socket) {
    read(socket, buffer, sizeof(buffer));
    printf("%s\n", buffer);
    buffer[0] = '\0';
};

void send_message(int socket, string message) {
    if (send(socket, message.c_str(), (sizeof(message) - 1), 0) < 0) {
        perror("Error sending message\n");
    }
};

int main (int argc, char *argv[])
{   
    // ./puzzlesolver <IP address>
    if (argc == 2) {
        
    }

    // ./puzzlesolver <IP address> <port1> <port2> <port3> <port4>
    else if (argc == 6) {

    }

    // invalid number of arguments 
    else {
        printf("usage: ./puzzlesolver <IP address> or ./puzzlesolver <IP address> <port1> <port2> <port3> <port4>\n"); 
        exit(1);
    }
}