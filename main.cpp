#include <iostream>
#include <pcap.h>
#include <stdint.h>
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

int anal(pcap_t* handle,char* dev){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct libnet_link_init *network;
    int packet_size;
    u_int32_t ip_addr;
    struct libnet_ether_addr *mac_addr;
    libnet_t *l;


    int res = pcap_next_ex(handle, &header, &packet);
    if (res == -1 || res == -2)
        return -1;


    //if(network=libnet_open   ())
    packet_size=LIBNET_IPV4_H+LIBNET_ETH_H+LIBNET_ICMPV4_MASK_H;
    l=libnet_init(LIBNET_RAW4,dev,errbuf);
    if(!l){
        puts("libnet_init_error");
        return -1;
    }
    ip_addr=libnet_build_ipv4(l);
    if ( ip_addr != -1 )
        printf("IP address: %s\n", libnet_addr2name4(ip_addr,LIBNET_DONT_RESOLVE));
    else {
        fprintf(stderr, "Couldn't get own IP address: %s\n", libnet_geterror(l));
        puts("error");
    }
    printf("asdf\n");
    printf("%u bytes captured\n", header->caplen);
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
    pcap_close(handle,dev);

    return 0;
}
