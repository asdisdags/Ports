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

void scan(int lowPort, int highPort, string host){
    for (int i = lowPort; i <= highPort; i++){
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0){
            cout << "Error creating socket" << endl;
            exit(1);
        }
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(i);
        struct hostent *hp = gethostbyname(host.c_str());
        
        if (hp == 0){
            cout << "Error: unknown host" << endl;
            exit(1);
        }
        bcopy((char *)hp->h_addr, (char *)&server.sin_addr, hp->h_length);
        int err = connect(sock, (struct sockaddr *)&server, sizeof(server));
        if (err < 0){
            cout << "Error connecting to port " << i << endl;
        }
        else{
            cout << "Port " << i << " is open" << endl;
        }
        close(sock);
    }
}

int main(int argc, char* argv[])
{   
    string host = argv[1];
    int lowPort = atoi(argv[2]);
    int highPort = atoi(argv[3]);
    struct sockaddr_in server_addr;
    struct hostent *server;
    cout << "what the woof"<< endl;
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cout << "socket failed" << endl;
        perror("socket failed");
        exit(1);
    }
    
    server = gethostbyname(argv[1]);

    if (server = NULL){
        cout << "Error, no such host" << endl;
        exit(0);
    }

    bzero((char *) &server_addr, sizeof(server_addr));
    cout << "we here" << endl;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[2]));
    scan(lowPort, highPort, host);
    return 0;
    }
    
