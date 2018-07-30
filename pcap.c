#include <pcap.h>
        #include <netinet/ip.h>
        #include <netinet/tcp.h>
        #include <linux/if_ether.h>
        #include <arpa/inet.h>
        #include <stdio.h>
        #include <stdint.h>

        #define ETHERTYPE_IP  0x0800
        #define IPPROTO_TCP   0x06

        typedef struct pcap_pkthdr pcap_pkthdr;
        typedef struct ethhdr ethhdr;
        typedef struct tcphdr tcphdr;
        typedef struct ip ip;
        void print_data(unsigned char *data, int size)
        {
        if (size > 16)
        size = 16;
        printf("received data:\t\t");
        if (!size)
        {
        printf("no data detected\n");
        return;
        }
        for(int i = 0; i < size; i++)
        {
        if (!(i % 8) && i)
        printf("\n\t\t\t");
        printf("%02x ", data[i]);
        }
        printf("\n");
        }

        void print_mac_address(const char *head, unsigned char *data)
        {
        printf("%s%02x:%02x:%02x:%02x:%02x:%02x\n", head,
        data[0], data[1], data[2], data[3], data[4], data[5]);
        }

        int main(int argc, char* argv[]) {
        char* dev = argv[1]; // device name
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n please check device", dev, errbuf);
        return -1;
        }

        while (1) {
            //packet listen
        pcap_pkthdr* header;
        ethhdr* eth_header;
        tcphdr* tcp_header;
        ip* ip_header;

        const u_char* packet;

        unsigned char *data;
        unsigned short eth_type;
        unsigned char ip_proto;


        unsigned int ip_len;
        u_int8_t tcp_len;
        int data_size;

        int returnCode = pcap_next_ex(handle, &header, &packet); //packet capture
        if (returnCode == 0) continue; // time limit
        if (returnCode == -1) break; // error occur!!!!
        printf("##################################################\n");
        printf("%u bytes packet received\n", header->caplen);
        eth_header = (ethhdr*)packet;
        eth_type = htons(eth_header->h_proto);
        if (eth_type == ETHERTYPE_IP)
        {
        ip_header = (ip*)(packet + sizeof(ethhdr));
        ip_len = ip_header->ip_hl * 4;
        ip_proto = ip_header->ip_p;
        if (ip_proto == IPPROTO_TCP)
        {
        tcp_header = (tcphdr*)((void *)ip_header + ip_len);
        tcp_len = tcp_header->th_off * 4;
        data = (unsigned char *)(tcp_header + tcp_len);
        data_size = header->caplen - (sizeof(ethhdr) + ip_len + tcp_len);

        printf("source ip:\t\t%s\n", inet_ntoa(ip_header->ip_src));
        printf("destination ip:\t\t%s\n", inet_ntoa(ip_header->ip_dst));
        printf("source port:\t\t%u\n", htons(tcp_header->th_sport));
        printf("destination port:\t%u\n", htons(tcp_header->th_dport));
        print_mac_address("source mac address:\t", (unsigned char *)eth_header->h_source);
        print_mac_address("destination mac address:", (unsigned char *)eth_header->h_dest);
        print_data((unsigned char *)data,data_size);
        }
        }
        printf("##################################################\n");
        }

        pcap_close(handle);
        return 0;
        }