
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <set>
#include <queue>
#include "scanner.h"

using namespace std;

struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

int ports[4] = {0};
int oracle_port = 0;
int checksum_port = 1;
int evil_port = 2;
int simple_port = 3;

string CHECKSUM_STRING = "Hello, group_60!";
string ORACLE_STRING = "I am the oracle,";
string SECRET_STRING = "My boss told me ";
string EVILBIT_STRING = "The dark side of";


string receive_buffer_from_server(const char* ip, int port, int udp_socket, char* buffer, int buffer_len){
    string incoming;
    char receiving_buffer[1400];
    struct sockaddr_in destination;
    memset(&receiving_buffer, 0, sizeof(receiving_buffer));
    
    if (udp_socket > 0){
        fd_set readfds;
        FD_SET(udp_socket, &readfds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        destination.sin_family = AF_INET;
        destination.sin_port = htons(port);
        inet_aton(ip, &destination.sin_addr);

        if (sendto(udp_socket, buffer, buffer_len,0,(struct sockaddr *)&destination, sizeof(destination)) < 0){
            cout << "Error sending to port " << port << endl;
        }
        
        else {
            int t = select(udp_socket + 1, &readfds, NULL, NULL, &tv);
            if (t > 0){
                int dest_size = sizeof(destination);
                if (recvfrom(udp_socket, receiving_buffer, sizeof(receiving_buffer), 0, (struct sockaddr *)&destination, (socklen_t *)&dest_size) < 0){
                    cout << "Error receiving from port " << port << endl;
                }
                else {
                    incoming = receiving_buffer;
                    return incoming;
                }
            }   
        }

    }
    return incoming;
}


u_short calculate_checksum(unsigned short *udpheader, u_short len){
    long checksum;
    u_short odd_byte;
    short checksum_short;
    checksum = 0;
    while (len > 1){
        checksum += *udpheader++;
        len -= 2;
    }

    if (len == 1) {
        odd_byte = 0;
        *((u_char *) &odd_byte) =* (u_char *) udpheader;
        checksum += odd_byte;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = checksum + (checksum >> 16);
    checksum_short = (short)~checksum;

    return checksum_short;
}


string secret_phrase(u_short checksum, string source_address, int udp_sock){
    char udp_buffer[4096];
    memset(udp_buffer, 0, sizeof(udp_buffer));
    unsigned short data;
    struct ip *iphdr = (struct ip *)udp_buffer;
    struct udphdr *udphdr = (struct udphdr *)(udp_buffer + sizeof(struct ip));
    struct pseudo_header psh;

    char *message = (char *)(udp_buffer + sizeof(struct ip) + sizeof(struct udphdr));
    // ip header
    struct in_addr source;
    struct in_addr destination;
    inet_aton(source_address.c_str(), &source);
    iphdr->ip_src = source;
    inet_aton("130.208.242.120", &destination);
    iphdr->ip_dst = destination;
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + 2;
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_off = 0;
    iphdr->ip_id = htonl(54321);

    // udp header 
    udphdr->uh_dport = htons(ports[checksum_port]);
    udphdr->uh_sport = htons(58585);
    udphdr->uh_sum = htons(checksum);
    udphdr->uh_ulen = htons(sizeof(struct udphdr) + 2);
    // pseudo header
    psh.source_address = inet_addr(source_address.c_str());
    psh.dest_address = inet_addr("130.208.242.120");
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + 2);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + 2;
    char *pseudogram = (char *)malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udphdr, sizeof(struct udphdr));
    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct udphdr), message, 2);

    data = calculate_checksum((unsigned short *)pseudogram, psize);

    memcpy(message, &data, 2);
    iphdr->ip_sum = htons(calculate_checksum((unsigned short *)udp_buffer, iphdr->ip_len));
    int len = sizeof(struct ip) + sizeof(struct udphdr) + 2;

    string secret_phrase, messages = "", index_beginning = "Congratulations group_60!";
    messages = receive_buffer_from_server("130.208.242.120", ports[checksum_port], udp_sock, udp_buffer, len);
             //receive_buffer_from_server(const char* ip, int port, int udp_socket, char* buffer, int buffer_len){
    cout << messages.c_str() << endl;
    while(true){
        if(strstr(messages.c_str(), index_beginning.c_str())){
            cout << "we got in" << endl;
            secret_phrase = messages;
            break;
        }
        else{
            exit(0);
        }
    }
}


struct sockaddr_in local_address(){
    int the_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local;
    const char* ip = "130.208.242.120";
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(ip);
    local.sin_port = htons(evil_port);

    connect(the_socket, (const struct sockaddr *)&local, sizeof(local));

    struct sockaddr_in name;
    name.sin_port = htons(0);
    socklen_t namelen = sizeof(name);
    getsockname(the_socket, (struct sockaddr *)&name, &namelen);
    cout << "local ip: " << inet_ntoa(((struct sockaddr_in *)&name)->sin_addr) << endl;
    cout << "local port: " << ntohs(((struct sockaddr_in *)&name)->sin_port) << endl;
    cout << "local port: " << htons(((struct sockaddr_in *)&name)->sin_port) << endl;
    printf("port number %d\n", ntohs(name.sin_port));
    return name;

}


int evil_bit(const char* ip, struct sockaddr_in destination){
    int the_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local;
    unsigned int desired_port;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(ip);
    local.sin_port = htons(ports[evil_port]);

    if(connect(the_socket, (const struct sockaddr *)&local, sizeof(local)) < 0){
        cout << "connect error" << endl;
        exit(0);
    } 

    struct sockaddr_in name;
    int name_len = sizeof(name);
    bzero(&name, name_len);
    socklen_t namelen = sizeof(name);
    getsockname(the_socket, (struct sockaddr *)&name, &namelen);
    cout << "local ip: " << inet_ntoa(((struct sockaddr_in *)&name)->sin_addr) << endl;
    cout << "local port: " << ntohs(((struct sockaddr_in *)&name)->sin_port) << endl;
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(raw_sock < 0){
        cout << "raw socket error" << endl;
        exit(0);
    }
    int IPHDR_OPT = 1;
    if(setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &IPHDR_OPT, sizeof(IPHDR_OPT)) < 0){
        cout << "setsockopt error" << endl;
        exit(0);
    }

    char udp_buffer[4096];
    memset(udp_buffer, 0, 4096);
    char group_data[128];
    strcpy(group_data, "$group_60$");

    struct ip *iphdr = (struct ip *)udp_buffer;
    struct udphdr *udphdr = (struct udphdr *)(udp_buffer + sizeof(struct ip));
    char *message = (char *)(udp_buffer + sizeof(struct ip) + sizeof(struct udphdr));
    
    //ipheader 
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + 2;
    iphdr->ip_id = htons(0);
    iphdr->ip_off = htons(0x8000);
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_sum = 0;
    iphdr->ip_src = name.sin_addr;
    iphdr->ip_dst = destination.sin_addr;

    //udp header
    udphdr->uh_sport = name.sin_port;
    udphdr->uh_dport = htons(ports[evil_port]);
    udphdr->uh_ulen = htons(sizeof(struct udphdr) + strlen(group_data));
    udphdr->uh_sum = 0;
    strcpy(message, group_data);

    fd_set readfds;
    FD_SET(the_socket, &readfds);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 50000;
    int receive_buffer_len = 1400;
    char* receiving_buffer = new char[receive_buffer_len];

    string messages_from_server;
    char* secret_port_evil;

    sendto(raw_sock, &udp_buffer, (sizeof(struct ip) + sizeof(struct udphdr) + strlen(group_data)), 0, (struct sockaddr *)&destination, sizeof(destination)); 
    setsockopt(the_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int res = recvfrom(the_socket, receiving_buffer, receive_buffer_len, 0, (sockaddr *)&name, (socklen_t *)&name_len);
    if (res < 0){
        cout << "did not receive packet" << endl;
    }
    else{
        secret_port_evil = receiving_buffer + res - 4;
        cout << "Message : " << receiving_buffer << endl;
        cout << "Secret Port : " << secret_port_evil << endl;
        return stoi(secret_port_evil);
    }





return -1;
}

  



string string_manipulation(string message, string whole_message, char to_break) {
    string manipulation_string;
    int index = whole_message.find(message) + message.size();
    while(whole_message[index] != to_break){
        manipulation_string += whole_message[index];
        index++;
        }
        return manipulation_string;
    }
    
    




queue<string> oracle_information(set<int> oports, char *ip, int udp_socket, struct sockaddr_in destination){
    char buffer[1400];
    strcpy(buffer, "$group_60$");
    queue<string> oracle_info;
    set<int> invis_ports;
    string messages_from_server = receive_buffer_from_server(ip, ports[checksum_port], udp_socket, buffer, strlen(buffer));
    // if (strstr(messages_from_server.c_str(), CHECKSUM_STRING.c_str())){
    //     string source_addr_in_string = string_manipulation("source address being ", messages_from_server, '!');
    //     string checksum = string_manipulation("checksum of ", messages_from_server, ',');
    //     string binary_info = string_manipulation("network order)", messages_from_server , ' ');
    //     u_short short_checksum = (unsigned short) (stoul(checksum, 0, 16));
    //     string s_phrase = secret_phrase(short_checksum, source_addr_in_string, udp_socket);
    //     cout << "secret phrase is: " << s_phrase << endl;
    // }
    // messages_from_server = "";
    // messages_from_server = receive_buffer_from_server(ip, ports[simple_port], udp_socket, buffer, strlen(buffer));
    // if (strstr(messages_from_server.c_str(), SECRET_STRING.c_str())){
    //     string hidden_port = messages_from_server.substr((messages_from_server.size() -5 ));
    //     invis_ports.insert(stoi(hidden_port));
    // }
    messages_from_server = "";
    messages_from_server = receive_buffer_from_server(ip, ports[evil_port], udp_socket, buffer, strlen(buffer));
    cout << "before evil"<< endl;
    cout << messages_from_server << endl;
    if (strstr(messages_from_server.c_str(), EVILBIT_STRING.c_str())){
        cout << "we in the evil" << endl;
        evil_bit(ip, destination);
    }
}


void send_to_available_ports(set<int> udpports, char *ip, int udp_socket){
    char client_buf[1400];
    strcpy(client_buf, "$group_60$");

   
    for(int port : udpports){
        string messages_from_server = "";
        while (messages_from_server == ""){
            messages_from_server = receive_buffer_from_server(ip, port, udp_socket, client_buf, strlen(client_buf) + 1);
            }  
        if (strstr(messages_from_server.c_str(), CHECKSUM_STRING.c_str())){
            ports[checksum_port] = port;
        }
        if (strstr(messages_from_server.c_str(), EVILBIT_STRING.c_str())){
            ports[evil_port] = port;
        }
        if (strstr(messages_from_server.c_str(), ORACLE_STRING.c_str())){
            ports[oracle_port] = port;
        }
        if (strstr(messages_from_server.c_str(), SECRET_STRING.c_str())){
            ports[simple_port] = port;
        }
        }
        
    }


int main(int argc, char *argv[]){
    char client_buf[1400];
    strcpy(client_buf, "$group_60$");
    int len = strlen(client_buf) + 1; 
    struct sockaddr_in server_address;
    string message;
    server_address.sin_family = AF_INET;
    char* ip;
    int udp_socket;

    set<int> oports;

    
    

    //  ./puzzlesolver <ip>
    if (argc == 2) {
        ip = argv[1];
        int port1 = atoi(argv[2]);
        udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    // ./puzzlesolver <ip> <port1> <port2> <port3> <port4>
    else if (argc == 6) {
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        ip = argv[1];
        for (int i = 2; i < 6; i++) {
            oports.insert(atoi(argv[i]));
        }
    } else {
        cout << "usage: ./puzzlesolverv2 <ip>" << endl;
        cout << "or" << endl;
        cout << "usage: ./puzzlesolverv2 <ip> <port1> <port2> <port3> <port4>" << endl;
        exit(0);
    }
    inet_aton(ip, &server_address.sin_addr);
    

    send_to_available_ports(oports, ip, udp_socket);
    // while(ports[checksum_port] == 0 || ports[oracle_port] == 0 || ports[simple_port] == 0 || ports[evil_port] == 0){
    //     send_to_available_ports(oports, ip, udp_socket);
    // }

    //queue<string> oracle_info = oracle_information(oports, ip, udp_socket, server_address);
    cout << "server ip: " << inet_ntoa(((struct sockaddr_in *)&server_address)->sin_addr) << endl;
    evil_bit(ip, server_address);

}
 