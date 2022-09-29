#ifndef SCANNER_123u488932u9
#define SCANNER_123u488932u9

#include <set>
#include <string>
#include "stdio.h"
#include "stdlib.h"

using namespace std;

set<int> scan (char* host, int low_port, int high_port) {
    char server_message[2048];
    char client_message[2048];
    set<int> open_ports;

    for (int i = low_port; i <= high_port; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        
        if (sock < 0){
            perror("Failed to create socket");
            exit(1);
        }

        memset(server_message, '\0', sizeof(server_message));
        memset(client_message, '\0', sizeof(client_message));

        // set up server address
        struct sockaddr_in server_address;
        int sock_addr_len = sizeof(server_address);
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(i);
        server_address.sin_addr.s_addr = inet_addr(host);
        
        // set timeout for recvfrom() - if no response before timeout, port is closed
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
        
        if (sendto(sock, client_message, strlen(client_message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) < 0){
            perror("Failed to send message");
        }
        if (recvfrom(sock, server_message, sizeof(server_message), 0, (struct sockaddr*)&server_address, (socklen_t*)&sock_addr_len) >= 0){
            cout << "Port " << i << " is open" << endl;
            open_ports.insert(i);
        }
       
        close(sock);
    }

    return open_ports;
};

#endif