#include <stdio.h>
#include <pcap.h> 
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void dump(const u_char* p, int len) {
  if(len<=0) {
    printf("None\n");
    return;
  }
  for(int i =0; i < len; i++) {
    printf("%02x " , *p);
    p++;
    if((i & 0x0f) == 0x0f)
      printf("\n");
  }
  printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
		
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    struct ether_header *eth;
    struct ip *iph;
    struct tcphdr *tcph;
    const u_char* packet;
    int tHL;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
   
    eth = (struct ether_header *) packet;
    
    printf("---Ethernet---\n");
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
  	
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
      printf("\n");
      continue; //not IP, big endian -> little endian
    }
    iph = (struct ip *)(packet + sizeof(struct ether_header)); 

    printf("---IPv4---\n");
    printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));

    if(iph->ip_p != IPPROTO_TCP) { printf("\n"); continue; }
    tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + iph->ip_hl*4);
    //tHL = (sizeof(struct ether_header)) + iph->ip_hl*4 + tcph->th_off*4 ; 
    tHL = iph->ip_hl*4 + tcph->th_off*4 ;    
    printf("---TCP---\n");
    printf("Source PORT: %d\n" , ntohs(tcph->th_sport));
    printf("Destiantion PORT: %d\n", ntohs(tcph->th_dport));
  	
    printf("---Data---\n");
    if(ntohs(iph->ip_len) - tHL >= 32) // have payload && longer than 32 bytes
      dump(packet + tHL + sizeof(struct ether_header),32); 
    else if(ntohs(iph->ip_len) - tHL < 32) 
      dump(packet + tHL + sizeof(struct ether_header), ntohs(iph->ip_len) - tHL);
    	
    printf("\n");


  }
  pcap_close(handle);
  return 0;
}
