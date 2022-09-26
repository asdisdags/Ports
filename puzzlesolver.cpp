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
    register long sum;
    unsigned short oddbyte;
    register short answer;

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

int main(int argv, char* argc[]){
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0){
        perror("Failed to create socket");
    }
    char client_buffer[2048] = "$group_60$";
    char server_buffer[2048];
    char datagram[4096], source_ip[32], *data, *pseudogram;
    memset(datagram, 0, 4096);
    struct iphdr *iph = (struct iphdr *) datagram;
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

    strcpy(data, client_buffer);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(argc[1]);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(argc[1]);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum((unsigned short *) datagram, iph->tot_len);

    udph->source = htons(5678);
    udph->dest = htons(80);
    udph->len = htons(8 + strlen(data));
    udph->check = 0;


    psh.source_address = inet_addr(argc[1]);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = htons(sizeof(struct udphdr) + strlen(data) );

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

    udph->check = csum( (unsigned short*) pseudogram , psize);

    if(sendto(sockfd, datagram, iph->tot_len, 0, (struct sockaddr*) &sin, sizeof(sin)) < 0){
        cout << "Error sending packet" << endl;
    }
    else{
        cout << "Packet sent" << endl;
        cout << datagram << endl;

    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(atoi(argc[2]));
    server_address.sin_addr.s_addr = inet_addr(argc[1]);

    sendto(sockfd, client_buffer, strlen(client_buffer), 0, (struct sockaddr*)&server_address, sizeof(server_address));
    recvfrom(sockfd, server_buffer, sizeof(server_buffer), 0, (struct sockaddr*)&server_address, (socklen_t*)&server_address);
    cout << server_buffer << endl;
}