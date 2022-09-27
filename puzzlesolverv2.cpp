
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
    short checksum_short = 0;

    while (len > 1){
        checksum += *udpheader++;
        len -= 2;
    }

    if (len == 1) {
        odd_byte = 0;
        *((u_char *) &odd_byte) = *(u_char *) udpheader;
        checksum += odd_byte;
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    checksum_short = (short)~checksum;

    return checksum_short;
}


string secret_phrase(u_short checksum, string source_address, int udp_sock){
    char udp_buffer[1400];
    memset(udp_buffer, 0, sizeof(udp_buffer));
    unsigned short data;

    struct ip *iphdr = (struct ip *)udp_buffer;
    struct udphdr *udphdr = (struct udphdr *)(udp_buffer + sizeof(struct ip));
    struct pseudo_header psh;

    char *message = (char *)(udp_buffer + sizeof(struct ip) + sizeof(struct udphdr));

    struct in_addr source;
    inet_aton(source_address.c_str(), &source);
    iphdr->ip_src = source;

    struct in_addr destination;
    inet_aton("130.208.242.120", &destination);
    iphdr->ip_dst = destination;

    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + 2;
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_off = 0;
    iphdr->ip_id = htons(54321);

    udphdr->uh_dport = htons(ports[checksum_port]);
    udphdr->uh_sport = htons(64436);
    udphdr->uh_sum = htons(checksum);
    udphdr->uh_ulen = htons(sizeof(struct udphdr) + 2);

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

    string secret_phrase, messages = "", index_beginning = "Hello group_60";
    messages = receive_buffer_from_server("130.208.242.120", ports[checksum_port], udp_sock, udp_buffer, len);
    cout << "before the while loop " << endl;
    while(true){
        cout << "we in the secret phrase while loop" << endl;
        if(strstr(messages.c_str(), index_beginning.c_str())){
            secret_phrase = messages;
            cout<< "secret phrase is: " << secret_phrase << endl;
            break;
        }
    }
}





string string_manipulation(string message, string whole_message) {
    string manipulation_string;
    int index = whole_message.find(message) + sizeof(message);
    cout << "message: " << message << endl;
    cout << "whole_message: " << whole_message << endl;
    while (true){
        //cout << "index is: " << index << endl;
        if (whole_message[index] != '!'){
            manipulation_string += whole_message[index];
            index += 1;
        }
    }
    return manipulation_string;
}



queue<string> oracle_information(set<int> oports, char *ip, int udp_socket, struct in_addr destination){
    char buffer[1400];
    strcpy(buffer, "$group_60$");
    queue<string> oracle_info;
    set<int> invis_ports;
    cout << "we in the oracle" << endl;
    string messages_from_server = receive_buffer_from_server(ip, ports[checksum_port], udp_socket, buffer, strlen(buffer));
    while(1){
        cout << "before if"<< endl;
        if (strstr(messages_from_server.c_str(), CHECKSUM_STRING.c_str())){
            cout << "bang" << endl;
            string source_addr_in_string = string_manipulation("source address being ", messages_from_server);
            string checksum = string_manipulation("checksum is ", messages_from_server);
            u_short short_checksum = (unsigned short) (stoul(checksum, 0, 16));
            string s_phrase = secret_phrase(short_checksum, source_addr_in_string, udp_socket);
            cout << "secret phrase is: " << s_phrase << endl;
            break;
        }
        messages_from_server = receive_buffer_from_server(ip, ports[checksum_port], udp_socket, buffer, strlen(buffer));
    }

}







void send_to_available_ports(set<int> udpports, char *ip, int udp_socket){
    char client_buf[1400];
    strcpy(client_buf, "$group_60$");
    cout << "we he in open ports function" << endl;
   
    for(int port : udpports){
        string messages_from_server = "";
        while (messages_from_server == ""){
            messages_from_server = receive_buffer_from_server(ip, port, udp_socket, client_buf, strlen(client_buf) + 1);
            }  
        if (strstr(messages_from_server.c_str(), CHECKSUM_STRING.c_str())){
            ports[checksum_port] = port;
            //cout << "Message from " << port << " is " << messages_from_server << endl;
            cout << "checksum" << endl;
        }
        if (strstr(messages_from_server.c_str(), EVILBIT_STRING.c_str())){
            ports[evil_port] = port;
            cout << "evil" << endl;
            //cout << "Message from " << port << " is " << messages_from_server << endl;
        }
        if (strstr(messages_from_server.c_str(), ORACLE_STRING.c_str())){
            ports[oracle_port] = port;
            cout << "oracle" << endl;
            //cout << "Message from " << port << " is " << messages_from_server << endl;
        }
        if (strstr(messages_from_server.c_str(), SECRET_STRING.c_str())){
            ports[simple_port] = port;
            cout << "secret" << endl;
            //cout << "Message from " << port << " is " << messages_from_server << endl;
        }
        }
        
    }


int main(int argc, char *argv[]){
    char client_buf[1400];
    int len; 
    struct sockaddr_in server_address;
    string message;

    char* ip;
    int udp_socket;

    set<int> oports;

    strcpy(client_buf, "$group_60$");
    len = strlen(client_buf) + 1; 

    if (argc == 2){
        ip = argv[1];
        int port1 = atoi(argv[2]);
        udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    else if (argc == 6){
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        ip = argv[1];
        for(int i = 2; i < 6; i++){
            oports.insert(atoi(argv[i]));
        }
    } else {
        cout << "usage: ./puzzlesolverv2 <ip>" << endl;
        cout << "or" << endl;
        cout << "usage: ./puzzlesolverv2 <ip> <port1> <port2> <port3> <port4>" << endl;
        exit(0);
    }

    

    send_to_available_ports(oports, ip, udp_socket);
    // while(ports[checksum_port] == 0 || ports[oracle_port] == 0 || ports[simple_port] == 0 || ports[evil_port] == 0){
    //     send_to_available_ports(oports, ip, udp_socket);
    // }

    queue<string> oracle_info = oracle_information(oports, ip, udp_socket, server_address.sin_addr);

}