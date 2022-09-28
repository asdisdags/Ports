#ifndef scanner
#define scanner 

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <set>

using namespace std;

class Scanner{
    public:
        int udp_socket;
        char buffer[1400];
        struct sockaddr_in server_address;
        int len;
        const char* ip;
        int port_from;
        int port_to;
        struct sockaddr_in destination;
        struct hostent *server;
        struct timeval tv;

        Scanner(const char* ip);
        
        int open_socket();
        set<int> scan(int low_port, int high_port);

    private:
        int udp_sock;
        set<int> ports;

};


#endif