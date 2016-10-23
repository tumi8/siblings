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

  //cout << "capture finished" << endl;
  return 0;
}

const struct ether_header* ethernetHeader;
//const struct ip* ipHeader;
const struct tcphdr* tcpHeader;
char sourceIp[INET6_ADDRSTRLEN];
char destIp[INET6_ADDRSTRLEN];
u_int sourcePort, destPort;
u_char *data;
int dataLength = 0;
string dataStr = "";
unsigned int i,j=0;
unsigned char cur;
static char buf[200];
//buf = (char*)malloc(200); // buf[200];
static char buft[200];
//buft = (char*)malloc(200); // buf[200];

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  //cout << "." << std::flush;
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
      if (tcp) {
          tcpHeader = (tcphdr*)(packet + headersize);
          sourcePort = ntohs(tcpHeader->source);
          destPort = ntohs(tcpHeader->dest);
	         // tcp->th_off = # of 32-bit words in header, of which 5 are basic header
	        unsigned int option_bytes = (4*((unsigned int) 0xf & tcpHeader->th_off))-20;
	        //cout << "option bytes: " << option_bytes << std::endl;
          char* opts = (char*)&tcpHeader[1];

          //std::cout << "option_bytes: " << option_bytes << std::endl;
          for (i=0;i<option_bytes;){
            // we need a full TCP option parser here to find the TCP TS option
            // we step through all option until finding TCP TS
            cur=0xff & opts[i];
            switch(cur) {
              case 0:
                i=option_bytes;
                break;
              case 1: // NOP
                i++;
                break;
              case 2: // MSS
                if( (0xff & opts[i+1]) == 4){
                  i=i+4;
                } else { // invalid MSS case, exit parsing
                  i=option_bytes;
                }
                break;
              case 4: // SACK permitted
                i=i+2;
                break;
              case 8: // timestamps
                // check that length is 10 bytes as per RFC1323
                if( (0xff & opts[i+1]) == 0x0a){
                  // human readable
                  /*std::cout << "sourceIP: "<< sourceIp  << " tsval: "<< ntohl(*(unsigned int*) &opts[i+2])
                  << " rcv_ts: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << std::endl; */
                  //csv
                  //std::cout << sourceIp  << "," << ntohl(*(unsigned int*) &opts[i+2])
                  //<< "," << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << std::endl;
                  // better csv: http://stackoverflow.com/questions/14432043/c-float-formatting
                  ts=ntohl(*(unsigned int*) &opts[i+2]);
                  if(ts==0) {
                    // empty TS -> skip packet
                  i=option_bytes;
                  break;
                  }
                  // print output line
                  printf("%s,%u,%u%06u\n",sourceIp,ts,pkthdr->ts.tv_sec,pkthdr->ts.tv_usec);
                  i=i+10;
                } else {
                  j=j+4;
                  i=option_bytes;
                }
                i=option_bytes;
                break;
              case 3: // Window Scale
                i=i+3;
                break;
              case 30: // MPTCP
                i=i+(unsigned int)(0xff & opts[i+1]);
                break;
              case 34: // TFO
                i=i+ (unsigned int)(0xff & opts[i+1]);
                break;
              // CASES THAT SHOULD NOT APPEAR
              case 5: // SACK, only permitted in SYN
                i=i+ (unsigned int)(0xff & opts[i+1]);
                break;
              case 6: // obsolete
                i=i+6;
                break;
              case 7: // obsolete
                i=i+6;
                break;
              case 9: // obsolete
                i=i+2;
                break;
              case 10: // obsolete
                i=i+3;
                break;
              case 14: // obsolete
                i=i+3;
                break;
              case 15: // SACK, only permitted in SYN
                i=i+ (unsigned int)(0xff & opts[i+1]);
                break;
              case 18: // obsolete
                i=i+3;
                break;
              case 19: // obsolete
                i=i+18;
                break;
              case 27: // obsolete
                i=i+8;
                break;
              case 28: // obsolete
                i=i+4;
                break;
              case 253: // exp
                i=i+ (unsigned int)(0xff & opts[i+1]);
                break;
              case 254: // exp
                i=i+ (unsigned int)(0xff & opts[i+1]);
              break;
              default: // even crazier crazyness ...
              // unrec. option, jump to end of options
                i=option_bytes;
                break;
            }
          }
      }
}
