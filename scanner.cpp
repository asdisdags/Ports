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
#include <set>

#include "scanner.h"

using namespace std;

int main(int argc, char* argv[])
{   
    // check if the user entered the correct number of arguments
    if (argc < 4) { 
        printf("usage: scanner <IP address> <low port> <high port>\n"); 
        exit(1); 
    }

    char* host = argv[1];
    int low_port = atoi(argv[2]);
    int high_port = atoi(argv[3]);

    set<int> open_ports = scan(host, low_port, high_port);

    cout << "The following ports are open: " << endl;
    for (int port : open_ports) {
        cout << port << endl;
    }

    return 0;
}
    
