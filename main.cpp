#include <stdio.h>
#include <stdint.h>
#include <pcap.h> 
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
/*struct Ethernet {
    u_char srcMac[6];
    u_char desMac[6];
    uint16_t type;
};
void parsMac(const u_char* flag, u_char *Mac) {
  for(int i=0; i<6 ; i++) {
    Mac[i] = *flag;
    //printf("%d\n",eth.desMac[i]);
    flag ++;
  }	
} */
void dump(const u_char* p, int len) {
  if(len<=0) {
    printf("None\n");
    return;
  }
  for(int i =0; i < len; i++){
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
    
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue; //not IP, big endian -> little endian
    iph = (struct ip *)(packet + sizeof(struct ether_header)); 
    if(iph->ip_p != IPPROTO_TCP) continue;
    tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + iph->ip_hl*4);
    tHL = (sizeof(struct ether_header)) + iph->ip_hl*4 + tcph->th_off*4 ;
  	
    printf("---Ethernet---\n");
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
  	
    printf("---IPv4---\n");
    printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));
  	
    printf("---TCP---\n");
    printf("Source PORT: %d\n" , ntohs(tcph->th_sport));
    printf("Destiantion PORT: %d\n", ntohs(tcph->th_dport));
  	
    printf("---Data---\n");
    if(header->caplen - tHL >= 32) // have payload && longer than 32 bytes
      dump(packet+tHL,32);
    else if(header->caplen - tHL < 32) 
      dump(packet+tHL, header->caplen - tHL);
  	
    printf("\n");
    /*struct Ethernet eth;
    parsMac(packet,eth.desMac);
    parsMac(packet+6,eth.srcMac);
    eth.type = *(packet+12);
    printf("%04x\n",eth.type); 
    if (eth.type != 0x0008) continue; //IP , little endian 
		
    for(int i=0 ; i< 6 ; i++) 
      printf("%d ", eth.desMac[i]);
    printf("\n");
    for(int i=0 ; i< 6 ; i++) 
      printf("%d ", eth.srcMac[i]);
    printf("\n"); */
    
    //dump(packet , header->caplen);
  }
  pcap_close(handle);
  return 0;
}
