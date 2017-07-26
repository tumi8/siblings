
#include "sibling_tool.h"
#include "candidate_identification.cpp"
#include "candidate_decision.cpp"
#include "ring_buffer.cpp"


using namespace std;

int main(int argc, char** argv)
{
	
	if(!(argc == 3 || argc == 5 || argc == 7)) {
		cout << "Usage:" << argv[0] << "-i/-f interface/file.pcap [-r result.csv] [-n negative_decisions.csv]" << endl;
		return -1;
	}
	
	signal(SIGINT, on_exit);
	
	//string interface = "", file = "", result = "", negatives = "";
	char *interface = NULL, *file = NULL, *result = NULL, *negatives = NULL;
	for(int i = 1; i < argc; i+=2) {
		if(!strncmp(argv[i], "-i", 2)) {
			interface = argv[i+1];
			continue;
		} else if(!strncmp(argv[i], "-f", 2)) {
			file = argv[i+1];
			continue;
		} else if(!strncmp(argv[i], "-r", 2)) {
			result = argv[i+1];
			continue;
		} else if(!strncmp(argv[i], "-n", 2)) {
			negatives = argv[i+1];
			continue;
		}
	}
	
	//open descriptor for interface or file
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(interface != NULL && file != NULL) {
		cerr << "Error: Defined multiple sources." << endl;
		return -1;
	} else {
		if(interface != NULL) {
			descr = pcap_open_live(interface, BUFSIZ, 0, 0, errbuf);
		} else {
			if(file != NULL) {
				descr = pcap_open_offline(file, errbuf);
			} else {
				cerr << "Error: No source defined. Use option -f or -i." << endl;
				return -1;
			}
		}
	}
	
	if(descr == NULL) {
		cerr << "Initializing pcap failed: " << errbuf << endl;
		return -1;
	}
	
	//Candidate Identification
	thread t1(&CandidateIdentification::start_identification, &identification);
	//Sibling Decision
	string filename = argv[2];
	thread t2(&CandidateDecision::start_decisions, &decision, result, negatives);
	//Buffer cleanup
	thread t3(&RingBuffer::cleanup_loop, &archive);
	
	t1.detach();
	t2.detach();
	t3.detach();

	//loop delivering packets to our packetHandler function
	if(pcap_loop(descr, 0, packetHandler, NULL) < 0) {
		cerr << "pcap_loop() failed: " << pcap_geterr(descr) << endl;
		return -1;
	}
	
	//Candidate Decision will automatically set all connections to finished and process the left over candidates,
	//since the capture is closed
	current_packet_time.tv_sec += 10;
	
	//wait for threads to finish
	while(true) {
		if(identification.empty() && decision.empty()) break;
		if(identification.empty()) cout << "Waiting for Decisions...\n";
		if(decision.empty()) cout << "Waiting for new Candidates...\n";
		sleep(2);
	}
	
	cout << "Total amount of packets: " << total_packets << endl;
	cout << "TCP packets: " << tcp_packets << " ; " << ((double) tcp_packets/total_packets)*100 << "%\n";

	return 0;
}

//Main Packet Handler, called for each incoming packet
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	packet_info info; //this is the structure used to extract only the most important data from the packet
	const struct ether_header* ethernet_hdr = (struct ether_header*)packet;
	const struct tcphdr* tcpHeader;
	
	info.time = pkthdr->ts; //save capturing time
	total_packets++;
	
	//IPv4 or IPv6?
	if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP) {
		//IPv4 packet
		struct ip* ip_h = (struct ip*)(packet + SIZE_ETHERNET);
		if(ip_h->ip_p != IPPROTO_TCP) {
			//not a tcp packet -> discard
			return;
		}
		info.type = '4';
		tcpHeader = (tcphdr*)(packet + (sizeof(struct ether_header) + sizeof(struct ip)));
		memcpy((void*) &info.ipv4_hdr, (void*) ip_h, sizeof(info.ipv4_hdr));
	} else {
		if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IPV6) {
			//IPv6 packet
			struct ip6_hdr* ip6_h = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
			if(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
				//not a tcp packet -> discard
				return;
			}
			info.type = '6';
			tcpHeader = (tcphdr*)(packet + (sizeof(struct ether_header) + sizeof(struct ip6_hdr)));
			memcpy((void*) &info.ipv6_hdr, (void*) ip6_h, sizeof(info.ipv6_hdr));
		} else {
			//neither IPv4 nor IPv6
			return;
		}
	}

	//valid option size?
	unsigned int option_size = (4*((unsigned int) 0xf & tcpHeader->th_off))-20;
	if(option_size > 40) {
		cerr << "Invalid option size " << option_size << " for packet #" << total_packets << endl;
		return;
	}
	
	//copy tcp header and options to packet_info struct
	info.option_size = option_size;
	memcpy((void*) &info.options, (void*) &tcpHeader[1], option_size);
	memcpy((void*) &info.tcp_hdr, (void*) tcpHeader, sizeof(info.tcp_hdr));
	
	parse_tcp_options(info);//stores a comparable string representation of the TCP options and the timestamp value in info
	
	if(info.timestamp == 0) {
		//check if it is a RST packet -> set the affected connection to finished
		//only connections that are marked as finished will be made an decision upon, otherwise they will remain in the queue till we have all packets
		if((tcpHeader->th_flags & TH_RST) == TH_RST) {
			archive.lock();
			if(info.type == '6') {
				archive.set_finished(true, info.ipv6_hdr.ip6_src);
				archive.set_finished(true, info.ipv6_hdr.ip6_dst);
			} else {
				archive.set_finished(true, info.ipv4_hdr.ip_src);
				archive.set_finished(true, info.ipv4_hdr.ip_dst);
			}
			archive.unlock();
		}
		//we don't need packets without timestamp
		return;
	}
	
	archive.lock();
	//add packet to archive
	if(info.type == '6') {
		in6_addr& ip6 = info.ipv6_hdr.ip6_src;
		archive.add(ip6, info);
	} else {
		in_addr& ip4 = info.ipv4_hdr.ip_src;
		archive.add(ip4, info);
	}
	
	//set host as finished when all packets have arrived (FIN or FIN ACK)
	if((tcpHeader->th_flags & TH_FIN) == TH_FIN) {
		if(info.type == '6') {
			archive.set_finished(true, info.ipv6_hdr.ip6_src);
		} else {
			archive.set_finished(true, info.ipv4_hdr.ip_src);
		}
	} else if((tcpHeader->th_flags & TH_SYN) == TH_SYN) {
		//when new SYN is coming, reset the host to unfinished
		if(info.type == '6') {
			archive.set_finished(false, info.ipv6_hdr.ip6_src);
		} else {
			archive.set_finished(false, info.ipv4_hdr.ip_src);
		}
	}
	
	archive.unlock();

	//give packet to identification instance
	identification.process_packet(info);
	
	//update global time
	current_packet_time = info.time;
	
	tcp_packets++;
	
	usleep(200);
}


//  LINEAR REGRESSION
//  taken from https://stackoverflow.com/a/19039500
double linear_regression_slope(const std::vector<double>& x, const std::vector<double>& y) {
	const auto n    = x.size();
	const auto s_x  = std::accumulate(x.begin(), x.end(), 0.0);
	const auto s_y  = std::accumulate(y.begin(), y.end(), 0.0);
	const auto s_xx = std::inner_product(x.begin(), x.end(), x.begin(), 0.0);
	const auto s_xy = std::inner_product(x.begin(), x.end(), y.begin(), 0.0);
	const auto a    = (n * s_xy - s_x * s_y) / (n * s_xx - s_x * s_x);
	return a;
}


//Least Squares, returns R^2
//taken from http://codesam.blogspot.de/2011/06/least-square-linear-regression-of-data.html
double leastSqrRegression(vector<double>& x, vector<double>& y)
{
	if (x.size() == 0 || y.size() == 0)
	{
		printf("Empty data set!\n");
		return -1;
	}
	
	double SUMx = 0;     //sum of x values
	double SUMy = 0;     //sum of y values
	double SUMxy = 0;    //sum of x * y
	double SUMxx = 0;    //sum of x^2
	double SUMres = 0;   //sum of squared residue
	double res = 0;      //residue squared
	double slope = 0;    //slope of regression line
	double y_intercept = 0; //y intercept of regression line
	double SUM_Yres = 0; //sum of squared of the discrepancies
	double AVGy = 0;     //mean of y
	double AVGx = 0;     //mean of x
	double Yres = 0;     //squared of the discrepancies
	double Rsqr = 0;     //coefficient of determination
	
	//calculate various sums
	for (int i = 0; i < x.size(); i++)
	{
		//sum of x
		SUMx = SUMx + x[i];
		//sum of y
		SUMy = SUMy + y[i];
		//sum of squared x*y
		SUMxy = SUMxy + x[i] * y[i];
		//sum of squared x
		SUMxx = SUMxx + x[i] * x[i];
	}
	
	//calculate the means of x and y
	AVGy = SUMy / y.size();
	AVGx = SUMx / x.size();
	
	//slope or a1
	slope = (y.size() * SUMxy - SUMx * SUMy) / (x.size() * SUMxx - SUMx*SUMx);
	
	//y itercept or a0
	y_intercept = AVGy - slope * AVGx;
	
	//calculate squared residues, their sum etc.
	for (int i = 0; i < x.size(); i++)
	{
		//current (y_i - a0 - a1 * x_i)^2
		Yres = pow((y[i] - y_intercept - (slope * x[i])), 2);
		
		//sum of (y_i - a0 - a1 * x_i)^2
		SUM_Yres += Yres;
		
		//current residue squared (y_i - AVGy)^2
		res = pow(y[i] - AVGy, 2);
		
		//sum of squared residues
		SUMres += res;
		
	}
	
	return (SUMres - SUM_Yres) / SUMres;
}


//Parse TCP options into String and extract timestamp value.
//taken from https://github.com/tumi8/siblings/blob/master/src/extract_tcpopts.cpp
void parse_tcp_options(packet_info& info) {
	char* opts = (char*) &info.options;
	int option_bytes = info.option_size;
	unsigned char cur;
	unsigned int i,j=0;
	char* buft = info.options_parsed;
	for (i=0;i<option_bytes;){
		cur=0xff & opts[i];
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
					info.timestamp = ntohl(*(unsigned int*) &opts[i+2]);
					i=i+10;
				} else {
					snprintf(&buft[j],5,"TXX-"); j=j+4;
					i=option_bytes;
				}
				break;
			case 3: // Window Scale
				snprintf(&buft[j],6,"WS%02d-",0xff & opts[i+2]); j=j+5;
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
}

double time_diff(timeval& t1, timeval& t2) {
	return (double)(t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec)/1000000.0;
}

void on_exit(int signal) {
	cout << "\nTotal amount of packets: " << total_packets << endl;
	cout << "TCP packets: " << tcp_packets << " ; " << ((double) tcp_packets/total_packets)*100 << "%\n";
	exit(0);
}
