#include <arpa/inet.h>
#include <thread>
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
#include <fcntl.h>
#include <sys/time.h>

using namespace std;

char buffer[4096];

// void scan(int low_port, int high_port, string host){
//     for (int i = low_port; i <= high_port; i++) {
//         cout << "Scanning port " << i << endl;
//         int sock = socket(AF_INET, SOCK_STREAM, 0); 
//         if (sock < 0){
//             perror("Failed to create socket");
//             exit(0);
//         }

//         cout << "Socket created" << endl;
//         struct sockaddr_in server_address;
//         memset(&server_address, 0, sizeof(server_address));

//         cout << "Server address initialized" << endl;
//         server_address.sin_family = AF_INET;
//         server_address.sin_port = htons(i);

//         int set_address = inet_pton(AF_INET, host.c_str(), &server_address.sin_addr);
//         if (set_address <= 0){
//             perror("Failed to set socket address");
//             exit(0);
//         }

//         cout << "Socket address set" << endl;
        
//         if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0){
//             cout << "Could not connect to port" << endl;
//         }

//         else {
//             cout << "Port " << i << " is open" << endl;
//         }


//         close(sock);
//     }
// }

int main(int argc, char* argv[])
{   
    // check if the user entered the correct number of arguments
    if (argc < 4) { 
        printf("usage: scanner <IP address> <low port> <high port>\n"); 
        exit(1); 
    }

    char *host = argv[1];
    int low_port = atoi(argv[2]);
    int high_port = atoi(argv[3]);
    
    // scan all ports from low_port to high_port
    for (int i = low_port; i <= high_port; i++) {
        int sockfd;
        struct sockaddr_in server_address;


        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            perror("Failed to create socket"); 
            exit(1); // eða return (-1)?
        }

        memset(&server_address, 0, sizeof(server_address));
        server_address.sin_addr.s_addr = inet_addr(host);
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(i);

        if (inet_pton(AF_INET, host, &server_address.sin_addr) <= 0){
            perror("Failed to set socket address");
            exit(0);
        }

        sendto(sockfd, "hello", 5, 0, (struct sockaddr *)&server_address, sizeof(server_address));
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        socklen_t socket_len = sizeof(server_address);

        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&server_address, &socket_len) >= 0){
            cout << "Port " << i << " is open" << endl;
        }
        else {
            cout << "Port " << i << " is closed" << endl;
        }

        close(sockfd);
    }

    // struct hostent *server;

    // server = gethostbyname(argv[1]);

    // if (server == NULL){
    //     perror("No such host");
    //     exit(0);
    // }

    // scan(low_port, high_port, host);

    return 0;
}
    
