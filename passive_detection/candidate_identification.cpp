#include "sibling_tool.h"

using namespace std;

bool CandidateIdentification::empty() {
	return new_packets.size() == 0;
}

void CandidateIdentification::start_identification() {
	//struct used to store which IP with time of connection start
	struct buf_entry {
		timeval time;
		char type;//6 or 4
		union {
			in6_addr ip6;
			in_addr ip4;
		};
	};
	
	//deques hold the IPs and start time of connection for each connection within the last 30 seconds
	deque<buf_entry> syn_deque; //stores hosts for source side
	deque<buf_entry> syn_ack_deque; //stores hosts for destination side
	packet_info* info; //pointer to current packet data
	
	while(true) {
		mtx.lock();
		//sleep if buffer is empty
		if(new_packets.size() == 0) {
			mtx.unlock();
			usleep(100000);
			continue;
		}

		//pop new packet
		
		info = &(new_packets.front());
		
		//check if packet is SYN or SYN ACK, and choose the respective queue for further processing
		deque<buf_entry>* buf;
		if((info->tcp_hdr.th_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
			//SYN
			buf = &syn_deque;
		} else {
			//SYN ACK
			buf = &syn_ack_deque;
		}
		
		packet_info curr;
		
		timeval threshold = {0};
		threshold.tv_sec = CandidateIdentification::threshold;
		timeval start;
		timersub(&(info->time), &threshold, &start);

		//delete packets that are more than CandidateIdentification::threshold microsceonds older than current packet
		while(buf->size() != 0 && timercmp(&((*buf)[0].time), &start, <)) {
			buf->pop_front();
		}

		//make candidate pair with IP of current packet and every IP of other IP protocol that is in our buffer
		for(int i = 0; i < buf->size(); i++) {

			if(info->type != (*buf)[i].type) {
				if(info->type == '6') {
					decision.add(info->ipv6_hdr.ip6_src, (*buf)[i].ip4);
				} else {
					decision.add((*buf)[i].ip6, info->ipv4_hdr.ip_src);
				}
			}
		}

		//add packet into buffer queue
		buf_entry entry;
		entry.time = info->time;
		entry.type = info->type;
		if(info->type == '6') {
			entry.ip6 = info->ipv6_hdr.ip6_src;
		} else {
			entry.ip4 = info->ipv4_hdr.ip_src;
		}
		buf->push_back(entry);
		new_packets.pop();
		mtx.unlock();
		
		usleep(200);
	}
}

//gets calles for each new packet by the main packet handler
void CandidateIdentification::process_packet(packet_info info) {
	int flags = info.tcp_hdr.th_flags & TH_ANY;
	//only process SYN or SYN ACK packets
	if((flags == TH_SYN) || (flags == (TH_SYN | TH_ACK))) {
		mtx.lock();
		new_packets.push(info);
		mtx.unlock();
	} else {
		return;
	}
}
