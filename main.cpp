#include <pcap_test.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


void checkType(const u_char* n){

        if (n[12]==8 && n[13]==00) {printf("Next to Ehternet is IP\n"); }
        else {printf("Not IP\n");}

        if (n[23]==6) {printf("Next to IP is TCP\n"); }
        else {printf("Not TCP\n");}



    return ;
}

void printmac(const u_char *packet){
    printf("Destination MAC: %02x:%02x: %02x : %02x: %02x: %02x\n", packet[0], packet[1], packet[2],packet[3],packet[4],packet[5]);
    printf("Source MAC     : %02x:%02x: %02x : %02x: %02x: %02x\n", packet[6], packet[7], packet[8],packet[9],packet[10],packet[11]);
}

void printip(const u_char *packet){
    printf("Source IP : %d.%d.%d.%d \n", packet[0], packet[1], packet[2],packet[3]);
    printf("Dest IP   : %d.%d.%d.%d \n", packet[4], packet[5], packet[6],packet[7]);
}

void printtcp(const u_char *packet){
    printf("tcp spsort : %d\n", packet[0]*256+packet[1]);
    printf("tcp spsort : %d\n", packet[2]*256+packet[3]);
}
void printPayload(const u_char *packet){
    int totalsize=packet[16]*16+packet[17];
    printf("total size: %d\n",totalsize);
    int ipheadersize=(packet[14]&0x0F)*4;
    printf("ipheader size: %d \n",ipheadersize);
    int tcpsize=((packet[14+ipheadersize+12]&0xF0)>>4)*4;
    printf("tcpsize : %d\n",tcpsize);
    int datasize=totalsize-ipheadersize-tcpsize;
    //printf("tcp data : %02x, %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n", packet[0],packet[1],packet[2],packet[3]
    //        ,packet[4],packet[5],packet[6],packet[7],packet[8],packet[9]);
    printf("tcp data :");
    printf("datasize: %d\n",datasize);
    if(datasize==0){
        printf("00 00 00 00 00 00 00 00 00 00");
    }
    for(int i=0;i<datasize && i<10;i++){
        printf(" %02x  ",packet[i]);
    }
    printf("\n---------------------------------\n");


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
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("%u bytes captured\n", header->caplen);
    checkType(&packet[0]);
    printmac(packet);
    printip(&packet[26]);
    printtcp(&packet[34]);
    printPayload(&packet[0]);








  }

  pcap_close(handle);
  return 0;
}
