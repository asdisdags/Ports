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

void scan(int low_port, int high_port, string host){
    char server_message[2048];
    char client_message[2048];
    for (int i = low_port; i <= high_port; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0){
            perror("Failed to create socket");
        }
        memset(server_message, '\0', sizeof(server_message));
        memset(client_message, '\0', sizeof(client_message));

        struct sockaddr_in server_address;
        int sock_addr_len = sizeof(server_address);
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(i);
        server_address.sin_addr.s_addr = inet_addr(host.c_str());

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
        if (sendto(sock, client_message, strlen(client_message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) < 0){
            perror("Failed to send message");
        }
        if (recvfrom(sock, server_message, sizeof(server_message), 0, (struct sockaddr*)&server_address, (socklen_t*)&sock_addr_len) >= 0){
            cout << "Port " << i << " is open" << endl;
            cout << server_message << endl;
        }
       
        close(sock);
    }
}

int main(int argc, char* argv[])
{   
    // check if the user entered the correct number of arguments
    if (argc < 4) { 
        printf("usage: scanner <IP address> <low port> <high port>\n"); 
        exit(1); 
    }

    string host = argv[1];
    int low_port = atoi(argv[2]);
    int high_port = atoi(argv[3]);
    scan(low_port, high_port, host);
    return 0;
}
    
