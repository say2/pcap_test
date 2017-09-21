#include <iostream>
#include <pcap.h>
#include <libnet.h>
/*
 * Ethernet Header의 src mac / dst mac

(IP인 경우) IP Header의 src ip / dst ip

(TCP인 경우) TCP Header의 src port / dst port

(Data가 존재하는 경우) 해당 Payload(Data)의 hexa decimal value(16바이트까지만)
 */


void usage(){
    puts("./pcap_test <interfacee>");
}

int anal(pcap_t* handle){

    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct libnet_ethernet_hdr *eth_hdr;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;\


    int res = pcap_next_ex(handle, &header, &packet);
    if (res == -1 || res == -2)
        return -1;

    eth_hdr=(struct libnet_ethernet_hdr*)packet;

    printf("smac : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("dmac : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
        return 1;
    ip_hdr=(libnet_ipv4_hdr*)(packet+LIBNET_ETH_H);
    printf("ip_src : %s\n",inet_ntoa(ip_hdr->ip_src));
    printf("ip_des : %s\n",inet_ntoa(ip_hdr->ip_dst));

    if(ip_hdr->ip_p != IPPROTO_TCP)
        return 1;

    tcp_hdr=(libnet_tcp_hdr*)(packet+LIBNET_IPV4_H+LIBNET_ETH_H);//(int)(*(&(ip_hdr->ip_len)-1))/16*5);//
    printf("src_port : %d\n",ntohs(tcp_hdr->th_sport));
    printf("des_port : %d\n",ntohs(tcp_hdr->th_dport));

    int hdr_len=LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_TCP_H;
    for(int i=hdr_len;i<header->len;i++){
        printf("%hhx ",*(packet+i));
    }
    puts("");

    printf("%u bytes captured\n", header->caplen);
    puts("-----------------------------------------------");
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct pcap_pkthdr* header;
    const u_char* packet;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    while (true) {
        if(anal(handle)==-1)
            break;
    }
    pcap_close(handle);

    return 0;
}
