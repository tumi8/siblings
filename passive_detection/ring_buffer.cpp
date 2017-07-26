#include "sibling_tool.h"

void RingBuffer::lock() {
	mtx.lock();
}

void RingBuffer::unlock() {
	mtx.unlock();
}

void RingBuffer::set_finished(bool finished, in_addr& addr) {

	ip4_finished[addr] = finished;

}

void RingBuffer::set_finished(bool finished, in6_addr& addr) {

	ip6_finished[addr] = finished;

}

bool RingBuffer::get_finished(in_addr& addr) {

	bool ret = ip4_finished[addr];

	return ret;
}

bool RingBuffer::get_finished(in6_addr& addr) {

	bool ret = ip6_finished[addr];

	return ret;
}

//throughout data form hosts that is older than 5 minutes
void RingBuffer::cleanup_loop() {
	in6_addr* ip6;
	timeval now, threshold, start;
	threshold.tv_sec = 300;
	while(true) {
		sleep(30);
		gettimeofday(&now, NULL);
		timersub(&now, &threshold, &start);
		mtx.lock();
		for(int i = 0; i != ip6_cache.size(); i++) {
			if(timercmp(&(ip6_cache[0].back().time), &start, <)) {
				ip6_map.erase(ip6_cache[0].back().ipv6_hdr.ip6_src);
				ip6_finished.erase(ip6_cache[0].back().ipv6_hdr.ip6_src);
				ip6_cache.erase(ip6_cache.begin() + i);
				i--;
			}
		}
		
		for(int i = 0; i != ip4_cache.size(); i++) {
			if(timercmp(&(ip4_cache[0].back().time), &start, <)) {
				ip4_map.erase(ip4_cache[0].back().ipv4_hdr.ip_src);
				ip4_finished.erase(ip4_cache[0].back().ipv4_hdr.ip_src);
				ip4_cache.erase(ip4_cache.begin() + i);
				i--;
			}
		}
		mtx.unlock();
	}
}

void RingBuffer::add(in_addr addr, packet_info info) {

	if(ip4_map.find(addr) == ip4_map.end()) {
		//add new vector to cache
		if(ip4_full()) {
			cout << "Buffer is filled. Deleting old data.\n";
			ip4_map.erase(ip4_cache[0][0].ipv4_hdr.ip_src);
			ip4_finished.erase(ip4_cache[0][0].ipv4_hdr.ip_src);
			ip4_cache.pop_front();
		}
		vector<packet_info> v;
		v.push_back(info);
		ip4_cache.push_back(v);
		ip4_map[addr] = ip4_cache.end() - 1;
	} else {
		(*(ip4_map[addr])).push_back(info);
	}

}

void RingBuffer::add(in6_addr addr, packet_info info) {

	if(ip6_map.find(addr) == ip6_map.end()) {
		//add new vector to cache
		if(ip6_full()) {
			cout << "Buffer is filled.Deleting old data.\n";
			ip6_map.erase(ip6_cache[0][0].ipv6_hdr.ip6_src);
			ip6_finished.erase(ip6_cache[0][0].ipv6_hdr.ip6_src);
			ip6_cache.pop_front();
		}
		vector<packet_info> v;
		v.push_back(info);
		ip6_cache.push_back(v);
		ip6_map[addr] = ip6_cache.end() - 1;
	} else {
		(*(ip6_map[addr])).push_back(info);
	}

}

vector<packet_info>* RingBuffer::get(in_addr addr) {
	vector<packet_info>* ret;

	if(ip4_map.find(addr) == ip4_map.end()) {
		ret = NULL;
	} else {
		ret = &(*(ip4_map[addr]));
	}

	return ret;
}

vector<packet_info>* RingBuffer::get(in6_addr addr) {
	vector<packet_info>* ret;

	if(ip6_map.find(addr) == ip6_map.end()) {
		ret = NULL;
	} else {
		ret = &(*(ip6_map[addr]));
	}

	return ret;
}

bool RingBuffer::ip4_full() {
	return ip4_cache.size() == ip4_cache.max_size();
}

bool RingBuffer::ip6_full() {
	return ip6_cache.size() == ip6_cache.max_size();
}



