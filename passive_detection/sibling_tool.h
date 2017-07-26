#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <iostream>
#include <array>
#include <fstream>
#include <string.h>
#include <math.h>
#include <unordered_map>
#include <sstream>
#include <queue>
#include <thread>
#include <unistd.h>
#include <signal.h>
#include <algorithm>
#include <numeric>
#include <mutex>
#include <stdlib.h>

#define SIZE_ETHERNET 14
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define TH_ANY 0x17


#ifndef _candidate_identification_
#define _candidate_identification_

using namespace std;

//struct to keep only neccessary packet information
struct packet_info {
	char type;		//'4' or '6'
	timeval time;	//time of receivement
	union {			//IP address
		ip ipv4_hdr;
		ip6_hdr ipv6_hdr;
	};
	tcphdr tcp_hdr;
	char options[40] = {0};
	char options_parsed[40] = {0};	//parsed String representation of options
	unsigned int option_size = 0;
	unsigned int timestamp = 0;		//extracted timestamp value
};

/*--------------------------------------------------------------------------------------*/
//stuff necessary if you use in6_addr or in_addr as the key in an unordered_map
struct in6_addr_hash {
	std::size_t operator ()(const in6_addr &addr) const {
		//combine hash values for each of the 16 uint8_t values
		//https://stackoverflow.com/questions/1646807/quick-and-simple-hash-code-combinations/1646913#1646913
		size_t hash = 17;
		std::hash<char> hasher;
		for(int i = 0; i < 16; i++) {
			hash = hash * 31 + hasher(addr.s6_addr[i]);
		}
		return hash;
	}
};

struct in_addr_hash {
	std::size_t operator ()(const in_addr &addr) const {
		std::hash<uint32_t> hasher;
		return hasher(addr.s_addr);
	}
};

bool operator==(const in_addr& addr1, const in_addr &addr2) {
	return addr1.s_addr == addr2.s_addr;
}

bool operator==(const in6_addr& addr1, const in6_addr &addr2) {
	return !memcmp((void*) &addr1, (void*) &addr2, sizeof(in6_addr));
}
/*--------------------------------------------------------------------------------------*/


class CandidateDecision {
private:
	struct ip_pair{in6_addr ip6; in_addr ip4;};		//siblign addresses
	vector<ip_pair> siblings;						//vector to save old decisions
	deque<ip_pair> new_candidates;					//buffer for new candidate pairs
	mutex mtx;										//for access to the new_candidates deque
public:
	bool contains(const in6_addr&);					//true if address is either in siblings or buffer
	bool contains(const in_addr&);					//true if address is either in siblings or buffer
	bool contains(const in6_addr&, const in_addr&);	//true if address pair is either in siblings or buffer
	void add(in6_addr, in_addr);					//add address pair to new_candidates buffer
	void print();									//print siblings to stdout
	bool empty();									//are therer new packets in the buffer to process?
	void save(string filename);						//save siblings to filename
	void start_decisions(char* outfile, char* neg_dec_file);	//initiates infinite loop for decisions
	bool check_timestamps(vector<packet_info>* ipv6, vector<packet_info>* ipv4, string& error);		//perform either timestamp estimation or comparison of absolute ts values
	bool decision_algorithm6(vector<packet_info>* ipv6, vector<packet_info>* ipv4, string& error);	//adopted decision algorithm from El Deib et al.
};

//Buffer that serves as archive for packet_infos
class RingBuffer {
	typedef deque<vector<packet_info>> PacketCache;
public:
	void add(in_addr, packet_info);			//add new IPv4 address
	void add(in6_addr, packet_info);		//add new IPv6 address
	bool ip4_full();						//true if IPv4 archieve is full
	bool ip6_full();						//true if IPv6 archieve is full
	vector<packet_info>* get(in_addr);		//pointer to vector of packets for requested IPv4 address
	vector<packet_info>* get(in6_addr);		//pointer to vector of packets for requested IPv6 address
	bool get_finished(in_addr&);			//true if the connection for requested address was finished by FIN or RST
	bool get_finished(in6_addr&);			//true if the connection for requested address was finished by FIN or RST
	void set_finished(bool, in_addr&);		//set connection for address finished
	void set_finished(bool, in6_addr&);		//set connection for address finished
	void cleanup_loop();					//delete data for connections that are too old
	void lock();							//lock mutex
	void unlock();							//unlock mutex
private:
	mutex mtx;
	unordered_map<in_addr, PacketCache::iterator, in_addr_hash> ip4_map;		//maps address to iterator that points to packet array
	unordered_map<in6_addr, PacketCache::iterator, in6_addr_hash> ip6_map;		//maps address to iterator that points to packet array
	PacketCache ip4_cache;
	PacketCache ip6_cache;
	unordered_map<in_addr, bool, in_addr_hash> ip4_finished;					//tells if the connection for specific IP has been ended by a RST or FIN
	unordered_map<in6_addr, bool, in6_addr_hash> ip6_finished;					//-> we wait with the sibling decision until we have all packets for a certain connection
};

class CandidateIdentification {
public:
	void process_packet(packet_info);		//add new packet to buffer
	void start_identification();			//initiate infinite candidate identification loop
	bool empty();							//are therer new packets in the buffer to process?
	static const int threshold = 30;		//seconds; threshold for timespan between two sibling addresses' connections
private:
	mutex mtx;								//for access to the new_packets queue
	queue<packet_info> new_packets;
};


//Global Functions
void on_exit(int signal);			//print out stats on exit
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);	//main packet handler
double linear_regression_slope(const std::vector<double>& x, const std::vector<double>& y);		//returns slope for linear regression
double leastSqrRegression(vector<double>& x, vector<double>& y);			//least squares, returns coefficient of correlation R^2
void parse_tcp_options(packet_info& info);			//parse TCP options into String representation and extrat timstamp value, both is saved in the same packet_info
double time_diff(timeval& t1, timeval& t2);			//timedifference in seconds

//Global Variables
unsigned long tcp_packets = 0;
unsigned long total_packets = 0;

RingBuffer archive;							//holds all received packets, mapped to the source ip
CandidateDecision decision;					//decision instance
CandidateIdentification identification;		//candidate identification instance
timeval current_packet_time;				//time of the current packet that is processes by the main packet handler

#endif
