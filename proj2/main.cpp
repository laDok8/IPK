#include <iostream>
#include <pcap/pcap.h>
#include <vector>
#include <string>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>

using namespace std;
char ERRBUF[PCAP_ERRBUF_SIZE];

//RFC3339 date format
void printDate(pcap_pkthdr header) {
    char buff[100];
    char buff2[10];

    const struct tm *epoch_time = localtime(&header.ts.tv_sec);
    string foo = "%FT%T." + to_string(header.ts.tv_sec % 1000);
    strftime(buff, sizeof(buff) - 1, foo.c_str(), epoch_time);
    //timezone part may be empty need to check
    strftime(buff2, sizeof(buff) - 1, "%z", epoch_time);
    if (strlen(buff2) == 0)
        exit(5);
    memmove(&buff2[4], &buff2[3], 2);
    buff2[3] = ':';
    printf("date: %s%s\n", buff, buff2);
}

void printInterfaces() {
    pcap_if *interfaces;
    //get interface list
    if (pcap_findalldevs(&interfaces, ERRBUF) == -1) {
        exit(1);
    }
    //print available interfaces
    for (pcap_if *temp = interfaces; temp; temp = temp->next) {
        printf("\n%s ", temp->name);
    }
    //free device list
    pcap_freealldevs(interfaces);
}

int parseArgs(int argc, char **argv, string *interface, string *filter) {
    vector<int> args = {0, 0, 0, 0};
    int packet_count = 1;
    string port;

    if (argc == 1) {
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            //is next arg interface?
            // list interface can be only first(and only argument)
            i++;
            if (i == argc && argc == 2) {
                printInterfaces();
                exit(0);
            } else if (i >= argc)
                exit(1);

            interface->assign(argv[i]);
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            i++;
            if (i >= argc)
                exit(1);

            port =" port "+string(argv[i]);
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
            args[0] = 1;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            args[1] = 1;
        } else if (strcmp(argv[i], "--icmp") == 0) {
            args[2] = 1;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--arp") == 0) {
            args[3] = 1;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--number") == 0) {
            //number of packets
            i++;
            if (i >= argc)
                exit(1);
            try {
                packet_count = std::stol(argv[i]);
            } catch (...) {
                exit(1);
            }
        } else {
            exit(1);
        }
    }

    //prepare packet filter
    vector <string> args_alias = {"tcp" + port, "udp" + port, "icmp or icmp6", "arp"};
    for (unsigned long i = 0; i < args.size(); i++) {
        if (args[i]) {
            filter->append(args_alias[i]);
            //add OR in case other is next parameter
            filter->append(" or ");
        }
    }

    //remove last OR
    if (!filter->empty())
        filter->assign(filter->erase(filter->length() - 3));
    //only port was set
    if (filter->empty() && !port.empty()) {
        filter->assign(port);
    }

    return packet_count;
}

void hexdump(void *ptr, int size) {
    u_char *buf = (u_char *) ptr;
    //16B on line
    for (int i = 0; i < size; i += 16) {
        printf("0x%04x: ", i);
        //hex or padding
        for (int j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
            if (j % 8 == 7)
                printf("  ");
        }
        //ASCII
        for (int j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            if (j % 8 == 7)
                printf("  ");
        }
        printf("\n");
    }
}


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    //prepare variable for all different packet types ( only 1 is ued per packet)
    struct ether_header *eth_header = (struct ether_header *) packet;
    struct ip *ip = (struct ip *) (packet + sizeof(ether_header));
    struct ip6_hdr *ip6 = (struct ip6_hdr *) (packet + sizeof(ether_header));

    //ipv4/6
    string sport = "-", dport = "-";
    if (ip->ip_v == 4 && ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        udphdr *transp_head = (udphdr * )(packet + sizeof(ether_header) + ip->ip_hl * 4);
        uint8_t ip_proto = ip->ip_p;
        if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP) {
            dport = to_string(ntohs(transp_head->uh_dport));
            sport = to_string(ntohs(transp_head->uh_sport));
        }
    } else if (ip->ip_v == 6 && ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        udphdr *transp_head = (udphdr * )(packet + sizeof(ether_header) + 40);
        uint8_t ip_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        if (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP) {
            dport = to_string(ntohs(transp_head->uh_dport));
            sport = to_string(ntohs(transp_head->uh_sport));
        }
    }

    printDate(*header);

    //ip to printable
    string ip_src = "-", ip_dst = "-";
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct arp_dummy {
            uint8_t x[14];
            uint8_t ip1[4];
            uint8_t mac2[6];
            uint8_t ip2[4];
        };
        struct arp_dummy *arp = (struct arp_dummy *) (packet + sizeof(ether_header));

        char ip4_src[INET_ADDRSTRLEN];
        char ip4_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &arp->ip1, ip4_src, sizeof(ip4_src));
        inet_ntop(AF_INET, &arp->ip2, ip4_dst, sizeof(ip4_src));
        ip_src.assign(ip4_src);
        ip_dst.assign(ip4_dst);
    } else if (ip->ip_v == 4) {
        char ip4_src[INET_ADDRSTRLEN];
        char ip4_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, ip4_src, sizeof(ip4_src));
        inet_ntop(AF_INET, &ip->ip_dst, ip4_dst, sizeof(ip4_src));
        ip_src.assign(ip4_src);
        ip_dst.assign(ip4_dst);
    } else if (ip->ip_v == 6) {
        char ip6_src[INET6_ADDRSTRLEN];
        char ip6_dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, ip6_src, sizeof(ip6_src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, ip6_dst, sizeof(ip6_src));
        ip_src.assign(ip6_src);
        ip_dst.assign(ip6_dst);
    }

    //print ip (if available) and hexdump
    cout << ip_src << ": " << sport << " > " << ip_dst << ": " << dport << ", length: " << header->caplen << endl;
    hexdump((void *) packet, (int) header->caplen);
}

int main(int argc, char **argv) {
    //parsing arguments
    string interface, filter;
    int packet_count = parseArgs(argc, argv, &interface, &filter);

    //open interface for sniffing
    pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, ERRBUF);
    if (!handle) {
        cerr << "Couldn't open device " << interface << endl;
        exit(1);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << "Device " << handle << "doesn't provide Ethernet headers" << endl;
        exit(1);
    }

    //set pcap filter so only relevant packet are caught
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 1, (bpf_u_int32) 0) == -1) {
        cerr << "Couldn't parse filter" << filter << endl;
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't install filter" << filter << endl;
        exit(1);
    }

    //actual sniffing packet
    pcap_loop(handle, packet_count, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
