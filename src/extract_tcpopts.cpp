#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>     /* malloc, free, rand */
#include <iostream> // for argc and argv

// this does not compile on macOS, just use Linux ;)

/*
 Based on code by https://www.insinuator.net/2011/04/extracting-data-from-very-large-pcap-files-part-1-tools-and-hardware/
 //      This program is free software; you can redistribute it and/or modify
 //      it under the terms of the GNU General Public License as published by
 //      the Free Software Foundation; either version 2 of the License, or
 //      (at your option) any later version.
 //
 //      This program is distributed in the hope that it will be useful,
 //      but WITHOUT ANY WARRANTY; without even the implied warranty of
 //      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 //      GNU General Public License for more details.
 //
 //      You should have received a copy of the GNU General Public License
 //      along with this program; if not, write to the Free Software
 //      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 //      MA 02110-1301, USA.

 Modified by scheitle@net.in.tum.de
*/

using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char** argv) {
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  // open capture file for offline processing
  if(argc != 2) {
    std::cout << "Usage: ./program pcap-file" << std::endl;
    exit(1);
  }
  descr = pcap_open_offline(argv[1], errbuf);
  if (descr == NULL) {
      std::cerr << "pcap_open_offline() failed: " << errbuf << endl;
      return 1;
  }
  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      std::cerr << "pcap_loop() failed: " << pcap_geterr(descr) << endl;
      return 1;
  }
  return 0;
}

const struct ether_header* ethernetHeader;
const struct tcphdr* tcpHeader;
char sourceIp[INET6_ADDRSTRLEN];
char destIp[INET6_ADDRSTRLEN];
u_int sourcePort, destPort;
u_char *data;
string dataStr = "";


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  unsigned int i,j=0;
  unsigned char cur;
  int dataLength = 0;
  static char buf[200];
  static char buft[200];
  ethernetHeader = (struct ether_header*)packet;
  unsigned int headersize=0;
  unsigned int ts;
  bool tcp=false;
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
      const struct ip* ipHeader;
      ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
      inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
      headersize=sizeof(struct ether_header) + sizeof(struct ip);
      if (ipHeader->ip_p == IPPROTO_TCP) tcp=true;
    } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
      const struct ip6_hdr* ipHeader;
      ipHeader = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
      inet_ntop(AF_INET6, &(ipHeader->ip6_src), sourceIp, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &(ipHeader->ip6_dst), destIp, INET6_ADDRSTRLEN);
      headersize=sizeof(struct ether_header) + sizeof(struct ip6_hdr);
      if (ipHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) tcp=true;
    } else {
      return;
  }
  if (!tcp){
    printf("NOT TCP!\n");
    return;
  }

  tcpHeader = (tcphdr*) (packet + headersize);
  if(!(tcpHeader->syn && tcpHeader->ack)){
    // skip non-syn-ack packets
    return;
  }
  sourcePort = ntohs(tcpHeader->source);
  destPort = ntohs(tcpHeader->dest);
   // tcp->th_off = # of 32-bit words in header, of which 5 are basic header
  unsigned int option_bytes = (4*((unsigned int) 0xf & tcpHeader->th_off))-20;
  //unsigned int option_bytes = (4*((unsigned int) 0xf & tcpHeader->th_off))- sizeof(struct tcphdr);
  char* opts = (char*)&tcpHeader[1];
  //static char* buft;
	//buft = (char*) malloc(200); //
  //buft[200];
  if(option_bytes > 40){
    printf("TCP options > 40 bytes! (%u) bytes. \n",option_bytes);
  }
  //unsigned int i=0;
  //static char* buf;
  //buf = (char*) malloc(200);
  //printf("option bytes: %d\n",option_bytes);
  snprintf(buf,3,"0x");
  for (i=0;i<option_bytes && i<40;i++){
    snprintf(&buf[i*2+2],3,"%02x",0xff & opts[i]);
  }
  // safety stop
  buf[41*2+2] = '\0';
  //printf("options: %s , option_bytes: %d \n", buf, option_bytes);
  buft[0] = '\0';

  for (i=0;i<option_bytes;){
    cur=0xff & opts[i];
    //printf("-%s.%02x-",buft,cur);
    switch(cur) {
      case 0:
        if(	(0xff & opts[i+1]) == 0 &&
          (0xff & opts[i+2]) == 0 &&
          (0xff & opts[i+3]) == 0)
        {
          snprintf(&buft[j],3,"E-"); j=j+2; // End of Options
        } else {
          snprintf(&buft[j],2,"X"); j++;
        }
        i=option_bytes;
        break;
      case 1: // NOP
        snprintf(&buft[j],3,"N-"); j=j+2;
        i++;
        break;
      case 2: // MSS
        if( (0xff & opts[i+1]) == 4){
          snprintf(&buft[j],5,"MSS-"); j=j+4;
          i=i+4;
        } else { // invalid case, exit parsing
          snprintf(&buft[j],5,"MXX-"); j=j+4;
          i=option_bytes;
        }
        break;
      case 4: // SACK permitted
        snprintf(&buft[j],6,"SACK-"); j=j+5;
        i=i+2;
        break;
      case 8: // timestamps
      if( (0xff & opts[i+1]) == 0x0a){
        snprintf(&buft[j],4,"TS-"); j=j+3;
        //fs_modify_uint64(fs, "tsval", (uint64_t)(ntohl(*(unsigned int*) &opts[i+2])));
        //fs_modify_uint64(fs, "tsecr", (uint64_t)(ntohl(*(unsigned int*) &opts[i+6])));
        //fs_modify_uint64(fs, "tsdiff", (uint64_t) 1^(*(unsigned int*) &opts[i+2]==*(unsigned int*) &opts[i+6]));
        i=i+10;
      } else {
        snprintf(&buft[j],5,"TXX-"); j=j+4;
        i=option_bytes;
      }
      break;
      case 3: // Window Scale
        //snprintf(&buft[j],4,"WS-"); j=j+3;
        snprintf(&buft[j],6,"WS%02d-",0xff & opts[i+2]); j=j+5;
        //fs_modify_uint64(fs, "wscale", (uint64_t) (0xff &opts[i+2]));
        i=i+3;
        break;
      case 30: // MPTCP
        snprintf(&buft[j],7,"MPTCP-"); j=j+6;
        i=i+(unsigned int)(0xff & opts[i+1]);
        break;
      case 34: // TFO
        if((unsigned int)(0xff & opts[i+1])>2){
          // response with cookie
          snprintf(&buft[j],6,"TFOC-"); j=j+5;
          //fs_modify_uint64(fs, "mptcpdiff", (uint64_t) 0);
          //static char *tfobuf;
          //tfobuf = xmalloc(60); // 2(0x) + 16*2 (1byte=2hexzahlen) + delim
          //snprintf(&tfobuf[0],3,"0x");
          //for (unsigned int k=2;k<(unsigned int)(0xff & opts[i+1]) && ((2+(k-2)*2) < 40);k++){
          //  snprintf(&tfobuf[2+(k-2)*2],3,"%02x",0xff & opts[i+k]); 
          //}
          //fs_modify_string(fs, "tfocookie", (char*)tfobuf,1);
        } else {
          // tfo reply without cookie (stupid middlebox option echo)
          snprintf(&buft[j],6,"TFOE-"); j=j+5;
        }
        i=i+ (unsigned int)(0xff & opts[i+1]);
        break;
      case 64: // unknown option sent by us
        snprintf(&buft[j],3,"U-"); j=j+2;
        i=i+2;
        break;
      // CASES THAT SHOULD NOT APPEAR
      case 5: // SACK, only permitted in SYN
        snprintf(&buft[j],2,"X"); j++;
        i=i+ (unsigned int)(0xff & opts[i+1]);
        break;
      case 6: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+6;
        break;
      case 7: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+6;
        break;
      case 9: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+2;
        break;
      case 10: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+3;
        break;
      case 14: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+3;
        break;
      case 15: // SACK, only permitted in SYN
        snprintf(&buft[j],2,"X"); j++;
        i=i+ (unsigned int)(0xff & opts[i+1]);
        break;
      case 18: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+3;
        break;
      case 19: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+18;
        break;
      case 27: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+8;
        break;
      case 28: // obsolete
        snprintf(&buft[j],2,"X"); j++;
        i=i+4;
        break;
      case 253: // experimental
        snprintf(&buft[j],2,"X"); j++;
        i=i+ (unsigned int)(0xff & opts[i+1]);
        break;
      case 254: // experimental
        snprintf(&buft[j],2,"X"); j++;
        i=i+ (unsigned int)(0xff & opts[i+1]);
        break;
      default: // even crazier crazyness ...
      // unrec. option
      snprintf(&buft[j],3,"X-"); j=j+2;
      i=option_bytes;
      break;
    } // switch option byte
  } // for option bytes
  //snprintf(&buft[0],2,"T");
  //printf("%s,%s,%s\n",sourceIp,buft,buf);
  printf("%s,%s\n",sourceIp,buft);
  //free(buft);
  //free(buf);
  return;
} // packethandler function
