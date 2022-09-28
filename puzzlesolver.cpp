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
#include <map>
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

char initial_message[] = "$group_60$";

// beginning of secret messages
string CHECKSUM = "Hello, group_60!";
string ORACLE = "I am the oracle,";
string SECRET = "My boss told me ";
string DARKSIDE = "The dark side of";

// map for open ports and their messages
map<string, int> ports;

string get_message_from_port(int port, int sockfd, char *ip_address, char *buffer, int length) {
    string message = "";
    char recv_buffer[1400];

    // set destination address
    struct sockaddr_in destination_address;
    destination_address.sin_family = AF_INET;
    inet_aton(ip_address, &destination_address.sin_addr);
    destination_address.sin_port = htons(port);
    int destination_address_len = sizeof(destination_address);

    fd_set masterfds;
    FD_SET(sockfd, &masterfds);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));

    if (sendto(sockfd, buffer, length, 0, (const struct sockaddr *)&destination_address, sizeof(destination_address)) < 0)
    {
        perror("Failed to send");
        exit(1);
    }
    if (recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (sockaddr *)&destination_address, (socklen_t *)&destination_address_len) >= 0){
        message = recv_buffer;
    }

    return message; // returns empty string or message from port
}

// adds ports to their corresponding messages in the ports map
void map_open_ports(set<int> open_ports, int sockfd, char *ip_address) {
    // for each port, send the message and add it to the ports map with its corresponding message
    for (int port : open_ports) {
        
        // get message from port
        string message = "";

        while (message == "") {
            message = get_message_from_port(port, sockfd, ip_address, initial_message, strlen(initial_message));
        }

        if (strstr(message.c_str(), CHECKSUM.c_str())) {
            ports[CHECKSUM] = port;
        }

        else if (strstr(message.c_str(), ORACLE.c_str())) {
            ports[ORACLE] = port;
        }

        else if (strstr(message.c_str(), SECRET.c_str())) {
            ports[SECRET] = port;
        }

        else if (strstr(message.c_str(), DARKSIDE.c_str())) {
            ports[DARKSIDE] = port;
        }

        // clear message
        message.clear();
    }
}

// returns source address from checksum message
string get_source_address(string message) {
    string source_address;
    string substring = "source address being ";  // substring before source address 
    
    int i = message.find(substring) + substring.length(); // find the index where the substring ends

    // get source address from message, '!' appears after the source address
    while (message[i] != '!') {
        source_address += message[i];
        i++;
    }

    return source_address;
}

// returns checksum string from checksum message
string get_checksum_string(string message) {
    string checksum_string;
    string substring = "UDP checksum of "; // substring before checksum string
    
    int i = message.find(substring) + substring.length(); // find the index where the substring ends

    // get checksum string from message, ',' appears after the checksum string
    while (message[i] != ',') {
        checksum_string += message[i];
        i++;
    }

    return checksum_string;
}

// generic checksum calculation function from binarytides.com
u_short calculate_checksum(unsigned short *udpheader, u_short len){
    long checksum;
    u_short odd_byte;
    short checksum_short;

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

void oracle_solver() { vector<string> hidden_ports; }


int create_udp_packet(int sockfd, char *ip_address, char* udp_buffer, u_short checksum, string source_address) {
    // IP header
    struct ip *iphdr = (struct ip *)udp_buffer;
    // UDP header
    struct udphdr *udphdr = (struct udphdr *)(udp_buffer + sizeof(struct ip));
    // Pseudo header
    struct pseudo_header psh;

    char *data = udp_buffer + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

    // set source address
    struct sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = inet_addr(source_address.c_str());
    src_addr.sin_port = htons(80);

    // set IP header values
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_off = 0;
    iphdr->ip_id = htonl(54321);
    iphdr->ip_sum = 0;

    struct in_addr source;
    inet_aton(source_address.c_str(), &source);
    iphdr->ip_src = source;

    struct in_addr destination;
    inet_aton("130.208.242.120", &destination);
    iphdr->ip_dst = destination;
    
    iphdr->ip_sum = calculate_checksum((unsigned short *)udp_buffer, iphdr->ip_len);

    // set destination address
    // struct in_addr dst_addr;
    // inet_aton("130.208.242.120", &dst_addr);
    // iphdr->ip_dst = dst_addr;

    // set UDP header values
    udphdr->uh_dport = htons(ports[CHECKSUM]);
    udphdr->uh_sport = htons(64436); // ?
    udphdr->uh_sum = 0;
    udphdr->uh_ulen = htons(8 + strlen(data));

    // set pseudo header values
    psh.source_address = inet_addr(source_address.c_str());
    psh.dest_address = src_addr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
   
   char *pseudogram = (char *)malloc(psize);
    
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udphdr, sizeof(struct udphdr) + strlen(data));

    udphdr->uh_sum = calculate_checksum((unsigned short *)udp_buffer, iphdr->ip_len);

    return iphdr->ip_len;
}

// sends udp message where the payload is a UDP packet, return the response (secret phrase)
string send_udp_message(int sockfd, char *ip_address, char *udp_packet, int length) {
    string secret_phrase = "";


    while (secret_phrase == "") {
        secret_phrase = get_message_from_port(ports[CHECKSUM], sockfd, ip_address, udp_packet, length);
    }
}

void checksum_solver(int sockfd, char *ip_address) {
    // get message from checksum port
    string message = "";
    while (message == "")  {
        message = get_message_from_port(ports[CHECKSUM], sockfd, ip_address, initial_message, strlen(initial_message));
    }

    // get source address and checksum from message
    string source_address = get_source_address(message);
    cout << "Source address: " << source_address << endl;
    string checksum_string = get_checksum_string(message);
    cout << "Checksum string: " << checksum_string << endl;
    
    // convert checksum string to unsigned short
    u_short checksum = (unsigned short) (stoul(checksum_string, 0, 16));

    // create valid UDP IPv4 packet
    char udp_buffer[IP_MAXPACKET];
    memset (udp_buffer, 0, IP_MAXPACKET);  // zero out the packet buffer

    // FOR TESTING
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

    int length = create_udp_packet(sockfd, ip_address, udp_buffer, checksum, source_address);
    // send udp message and get secret phrase
    string secret_phrase = send_udp_message(sockfd, ip_address, udp_buffer, length);
    cout << secret_phrase << endl;
}


// returns secret port from SECRET message
string get_secret_port(string message) {
    string secret_port;
    string substring = "secret port is "; // substring before secret port

    int i = message.find(substring) + substring.length(); // find the index where the substring ends

    // get secret port from message
    for (int j = 0; j < 4; j++) {
        secret_port += message[i];
        i++;
    }

    return secret_port;
}

void secret_port_solver(int sockfd, char *ip_address) {
    string secret_port = get_secret_port(SECRET);
    cout << "Secret port: " << secret_port << endl;


    // get message from secret port
    string message = get_message_from_port(stoi(secret_port), sockfd, ip_address, initial_message, strlen(initial_message));
    cout << "Message from secret port: " << message << endl;
}


void evil_bit_solver() {}



int main(int argc, char *argv[]) {
    struct sockaddr_in server_address;

    char *ip;
    int sockfd;

    set<int> open_ports;

    if (argc == 2) {
        ip = argv[1];
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            cout << "Error creating socket" << endl;
            exit(0);
        }

        // find open ports from 4000-4100
        // open_ports = Scanner(ip).scan(4000, 4100);
    }

    else if (argc == 6) {
        ip = argv[1];
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            cout << "Error creating socket" << endl;
            exit(0);
        };

        // set given ports as open
        for (int i = 2; i < 6; i++) {
            open_ports.insert(atoi(argv[i]));
        }
    }

    else {
        cout << "usage: ./puzzlesolver <ip>" << endl;
        cout << "or" << endl;
        cout << "usage: ./puzzlesolver <ip> <port1> <port2> <port3> <port4>" << endl;
        exit(0);
    }

    // map open ports to their secret message
    map_open_ports(open_ports, sockfd, ip);
    // for (auto it = ports.begin(); it != ports.end(); it++) {
    //     cout << it->first << " " << it->second << endl;
    // }

    checksum_solver(sockfd, ip);
    // secret_port_solver(sockfd, ip);
    return 0;
}