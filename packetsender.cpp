#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sstream>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <string.h>

int main(){
    char server_message[2048];
    char client_message[2048];
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0){
        perror("Failed to create socket");
    }
    memset(server_message, '\0', sizeof(server_message));
    memset(client_message, '\0', sizeof(client_message));
    std::string host = "130.208.242.120";
    int port = 4011;
    struct sockaddr_in server_address;
    int sock_addr_len = sizeof(server_address);
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = inet_addr(host.c_str());

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    if (sendto(sock, client_message, strlen(client_message), 0, (struct sockaddr*)&server_address, sizeof(server_address)) < 0){
        perror("Failed to send message");
    }
    if (recvfrom(sock, server_message, sizeof(server_message), 0, (struct sockaddr*)&server_address, (socklen_t*)&sock_addr_len) < 0){
        std::cout << "Port " << port << " is closed" << std::endl;
    } else {
        std::cout << "Port " << port << " is open" << std::endl;
        std::cout << server_message << std::endl;
    }
    close(sock);
    return 0;
}