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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h> 

using namespace std;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main (int argc, char* argv[]) {
    
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sockfd < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    char client_buffer[2048];
    char server_buffer[2048];

    memset(client_buffer, '\0', sizeof(client_buffer));
    memset(server_buffer, '\0', sizeof(server_buffer));

    char datagram[4096], source_ip[32], *data, *pseudogram;
    memset(datagram, 0, 4096);

    // IP header
    struct ip *iph = (struct ip *) datagram;

    // UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    data = datagram + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(data, "$group_60$");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(argv[1]);

    struct in_addr in;
    in.s_addr = inet_addr(source_ip);

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof (struct ip) + sizeof (struct udphdr) + strlen(data);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0;
    iph->ip_src = in;
    iph->ip_dst = sin.sin_addr;
    iph->ip_sum = csum((unsigned short *) datagram, iph->ip_len);

    udph->uh_sport = htons(5678);
    udph->uh_dport = htons(80);
    udph->uh_ulen = htons(8 + strlen(data));
    udph->uh_sum = 0;

    psh.source_address = inet_addr(argv[1]);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = htons(sizeof(struct udphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

    udph->uh_sum = csum( (unsigned short*) pseudogram , psize);

    if (sendto(sockfd, datagram, iph->ip_len, 0, (struct sockaddr*) &sin, sizeof(sin)) < 0){
        cout << "Error sending packet" << endl;
    }

    else {
        cout << "Packet sent" << endl;
    }

    cout << "Setting server address" << endl;
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    
    server_address.sin_port = htons(80); // ??? Segmentation fault here ??? 
    server_address.sin_addr.s_addr = inet_addr(argv[1]);
    cout << "Server address set" << endl;

    if (sendto(sockfd, client_buffer, strlen(client_buffer), 0, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        cout << "Error sending message" << endl;
    }

    else {
        cout << "Message sent" << endl;

        if (recvfrom(sockfd, server_buffer, sizeof(server_buffer), 0, (struct sockaddr*)&server_address, (socklen_t*)&server_address) >= 0) {
            printf("%s\n", server_buffer);
        }
    }

    return 0;
}