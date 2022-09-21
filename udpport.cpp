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
    for (int i = low_port; i <= high_port; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0){
            perror("Failed to create socket");
        }

        struct sockaddr_in server_address;
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(i);

        struct hostent *hp = gethostbyname(host.c_str());
        
        if (hp == 0){
            perror("Unknown host");
            exit(1);
        }

        bcopy((char *)hp->h_addr, (char *)&server_address.sin_addr, hp->h_length);
        
        if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0){
            cout << "Error connecting to port " << i << endl;
        }
        else {
            cout << "Port " << i << " is open" << endl;
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

    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Failed to create socket"); 
        exit(1); // eða return (-1)?
    }
    
    struct sockaddr_in server_addr;
    struct hostent *server;

    server = gethostbyname(argv[1]);

    if (server == NULL){
        perror("No such host");
        exit(0);
    }

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(low_port);
    scan(low_port, high_port, host);
    return 0;
}
    
