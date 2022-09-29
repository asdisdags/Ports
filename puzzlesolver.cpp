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
#include <sstream>
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
string EVIL = "The dark side of";

string SECRET_PHRASE = "Ennyn Durin Aran Moria. Pedo Mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion teithant i thiw hin.";

// map for open ports and their messages
map<string, int> ports;

string get_message_from_port(int port, int sockfd, char *ip_address, char *buffer, int length, int rcv_sock = 0, sockaddr_in *rcv_addr = nullptr) {
    string message = "";
    char recv_buffer[1400];
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // establish connection to port
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(ip_address);

    if (rcv_sock == 0) {
        rcv_sock = sockfd;
    }

    if (rcv_addr == nullptr) {
        rcv_addr = &sin;
    }

    unsigned int rcv_addr_len = sizeof(*rcv_addr);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    setsockopt(rcv_sock, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));

    while (strlen(recv_buffer) == 0) {
        if (sendto(sockfd, buffer, length, 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            perror("Failed to send");
            exit(1);
        }

        if (recvfrom(rcv_sock, recv_buffer, sizeof(recv_buffer), 0, (sockaddr *)rcv_addr, (socklen_t *)&rcv_addr_len) >= 0){
            message = recv_buffer;
            return message; 

        }
    }

    return message; // returns empty string
}

// adds ports to their corresponding messages in the ports map
void map_open_ports(set<int> open_ports, int sockfd, char *ip_address) {
    // for each port, send the message and add it to the ports map with its corresponding message
    for (int port : open_ports) {
        
        // get message from port
        string message = get_message_from_port(port, sockfd, ip_address, initial_message, strlen(initial_message));

        if (strstr(message.c_str(), CHECKSUM.c_str())) {
            ports[CHECKSUM] = port;
        }

        else if (strstr(message.c_str(), ORACLE.c_str())) {
            ports[ORACLE] = port;
        }

        else if (strstr(message.c_str(), SECRET.c_str())) {
            ports[SECRET] = port;
        }

        else if (strstr(message.c_str(), EVIL.c_str())) {
            ports[EVIL] = port;
        }

        // clear message
        message.clear();
    }
}

// returns source address from checksum message
string get_source_address(string message) {
    string source_address;
    int i;
    string substring = "source address being ";  // substring before source address 
    
    if (message.find(substring) != string::npos) {
        i = message.find(substring) + substring.length(); // find the index where the substring ends

        // get source address from message, '!' appears after the source address
        while (message[i] != '!') {
            source_address += message[i];
            i++;
        }
    }

    return source_address;
}

// returns checksum string from checksum message
string get_checksum_string(string message) {
    string checksum_string;
    string substring = "UDP checksum of "; // substring before checksum string
    
    if (message.find(substring) != string::npos) {
        int i = message.find(substring) + substring.length(); // find the index where the substring ends

        // get checksum string from message, ',' appears after the checksum string
        while (message[i] != ',') {
            checksum_string += message[i];
            i++;
        }
    }

    return checksum_string;
}

// code from https://www.binarytides.com/raw-udp-sockets-c-linux/
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
    checksum = checksum + (checksum >> 16);
    checksum_short = (short)~checksum;

    return checksum_short;
}

// code from https://www.binarytides.com/raw-udp-sockets-c-linux/
int create_udp_packet(int port, char *ip_address, char* udp_buffer, u_short checksum, string source_address) {
    char *data, *pseudogram;
    // IP header
    struct ip *iphdr = (struct ip *)udp_buffer;
    // UDP header
    struct udphdr *udphdr = (struct udphdr *)(udp_buffer + sizeof(struct ip));
    
    struct sockaddr_in sin;
    struct pseudo_header psh;

    u_short checksum_htonsed = htons(checksum);
    data = udp_buffer + sizeof(struct ip) + sizeof(struct udphdr);

    // set destination address
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(ip_address);

    // set IP header values
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen(data));
    iphdr->ip_ttl = 255;
    iphdr->ip_p = IPPROTO_UDP;
    iphdr->ip_off = 0;
    iphdr->ip_id = htons(54321);
    iphdr->ip_sum = 0;
    iphdr->ip_src.s_addr = inet_addr(source_address.c_str());	// Spoof the source ip address
    iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;
    
    iphdr->ip_sum = htons(calculate_checksum((unsigned short *)udp_buffer, iphdr->ip_len));

    // set UDP header values
    udphdr->uh_dport = htons(port);
    udphdr->uh_sport = htons(64436); // ?
    udphdr->uh_sum = 0;
    udphdr->uh_ulen = htons(sizeof(struct udphdr));

    // set pseudo header values
    psh.source_address = inet_addr(source_address.c_str());
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
   
    pseudogram = (char *)malloc(psize);
    
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udphdr, sizeof(struct udphdr));

    unsigned short p_checksum = calculate_checksum((unsigned short *) pseudogram, psize);
   
    memcpy(data, &initial_message, strlen(initial_message));

    for (int i = 0; i < IP_MAXPACKET; i++) {
        if (p_checksum != checksum_htonsed) {
            udphdr->uh_sport = htons(i);
            udphdr->uh_sum = calculate_checksum((unsigned short *)udp_buffer, iphdr->ip_len);

            memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header), udphdr, sizeof(struct udphdr));

            p_checksum = calculate_checksum((unsigned short *) pseudogram, psize);
        }
    }
    
    udphdr->uh_sum = p_checksum;

    return htons(iphdr->ip_len);
}

string checksum_solver(int sockfd, char *ip_address) {
    // get message from checksum port
    string message = get_message_from_port(ports[CHECKSUM], sockfd, ip_address, initial_message, strlen(initial_message));
    
    // in case we didn't recieve the correct message
    while (strstr(message.c_str(), CHECKSUM.c_str()) == NULL) {
        string message = get_message_from_port(ports[CHECKSUM], sockfd, ip_address, initial_message, strlen(initial_message));
    }
    cout << "Message recieved: " << message << endl;
    // get source address and checksum from message
    string source_address = get_source_address(message);
    string checksum_string = get_checksum_string(message);
    
    // convert checksum string to unsigned short
    unsigned int checksum = stoul(checksum_string, nullptr, 16);

    // create valid UDP IPv4 packet
    char udp_buffer[IP_MAXPACKET];
    memset (udp_buffer, 0, IP_MAXPACKET);  // zero out the packet buffer

    int length = create_udp_packet(ports[CHECKSUM], ip_address, udp_buffer, checksum, source_address); // length of ip header
    
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (udp_sock < 0) {
		perror("Failed to create udp socket");
		exit(0);
	}
    string succeed_msg = "Congratulations group_60!";
    while(true){
    // send udp message to checksum port and get secret phrase
        string secret_phrase = get_message_from_port(ports[CHECKSUM], sockfd, ip_address, udp_buffer, length);
        if(strstr(secret_phrase.c_str(), succeed_msg.c_str())){
            close(udp_sock);
            cout << "Got secret phrase "<<  endl;
            return secret_phrase;
        }
        else{
            cout << "Failed to get secret phrase, trying again" << endl;
        }


        
    }
}


// returns secret port from SECRET message
int get_secret_port(int sockfd, char *ip_address) {
    while(true){
        string message = get_message_from_port(ports[SECRET], sockfd, ip_address, initial_message, strlen(initial_message));
        
        // while (strstr(message.c_str(), "SECRET") == NULL) {
        //     message = get_message_from_port(ports[SECRET], sockfd, ip_address, initial_message, strlen(initial_message));
        // }

        string secret_port;
        string substring = "secret port is "; // substring before secret port

        int i = message.find(substring) + substring.length(); // find the index where the substring ends
    
        // get secret port from message
        for (int j = 0; j < 4; j++) {
            secret_port += message[i];
            i++;
        }  
    
        if (strstr(message.c_str(), SECRET.c_str())) {
            cout <<"get_secret: " <<secret_port << endl;
            return stoi(secret_port);
        } else{
            cout << "Failed to get secret port, trying again" << endl;
        }
    }
    
}


int evil_bit_solver(const char* ip, struct sockaddr_in destination){
    inet_aton(ip, &destination.sin_addr);
    int the_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local;
    unsigned int desired_port;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(ip);
    local.sin_port = htons(ports[EVIL]);

    if(connect(the_socket, (const struct sockaddr *)&local, sizeof(local)) < 0){
        cout << "connect error" << endl;
        exit(0);
    } 

    struct sockaddr_in name;
    int name_len = sizeof(name);
    bzero(&name, name_len);
    socklen_t namelen = sizeof(name);
    getsockname(the_socket, (struct sockaddr *)&name, &namelen);
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
    udphdr->uh_dport = htons(ports[EVIL]);
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
    for(int i = 0; i < 5; i++){
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
            if(stoi(secret_port_evil)){
                return stoi(secret_port_evil);
            } else{
                cout << "not a valid port" << endl;
            }
        }
    }





return -1;
}

string knock_knock(vector<string> ports_in_order, string secret_message, char* ip, int sockfd){
    string knock_msg;
    string receiver;
    cout << "before for loop" << endl;
    for(int i = 0; i < ports_in_order.size(); i++){
        char msg_buf[1400];
        int port_to_send = stoi(ports_in_order.at(i));
        strcpy(msg_buf, secret_message.c_str());
        receiver = get_message_from_port(port_to_send, sockfd, ip, msg_buf, 1400);
        knock_msg = receiver;
        cout << "port " << port_to_send << " knock msg: "<< knock_msg << endl;
        
    }
    return knock_msg;
}


void knock(string message, string the_secret_phrase, char* ip, int sockfd){
    char msg_buf[1400];
    vector<string> order_of_knock_ports;
    strcpy(msg_buf, message.c_str());
    cout << "msg_buf: " << msg_buf << endl;
    string oracle_message = get_message_from_port(ports[ORACLE], sockfd, ip, msg_buf, 1400);
    cout << "Oracle Message : " << oracle_message << endl;
    //int port, int sockfd, char *ip_address, char *buffer, int length, int rcv_sock = 0, sockaddr_in *rcv_addr = nullptr)
    stringstream s_streamer(oracle_message);
    while(s_streamer.good()){
        string substr;
        getline(s_streamer, substr, ',');
        order_of_knock_ports.push_back(substr);
    }
    cout << "order_of_knock_ports: " << order_of_knock_ports[0] << " " << order_of_knock_ports[1] << " " << order_of_knock_ports[2] << " " << order_of_knock_ports[3]<< " " << order_of_knock_ports[4] << " " <<order_of_knock_ports[5] <<endl;
    string knock_msg = knock_knock(order_of_knock_ports, the_secret_phrase, ip, sockfd);
    cout << "knock_msg: " << knock_msg << endl;

}


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

    string secret_phrase = checksum_solver(sockfd, ip);
    cout << "secret phrase: " << secret_phrase << endl;
    server_address.sin_family = AF_INET;
    
    int evil_secret_port = evil_bit_solver(ip, server_address);
    cout << "evil secret port: " << evil_secret_port << endl;
    int secret_port = get_secret_port(sockfd, ip); 
    cout << "secret port: " << secret_port << endl;
    
    string secret_comma_ports = to_string(secret_port) + "," + to_string(evil_secret_port);
    cout << "secret comma ports: " << secret_comma_ports << endl;
    knock(secret_comma_ports, secret_phrase, ip, sockfd);
    // close(sockfd);
    // secret_port_solver(sockfd, ip);
    return 0;
}