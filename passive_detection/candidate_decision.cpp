#include "sibling_tool.h"

using namespace std;

//write all sibling pairs to filename
void CandidateDecision::save(string filename) {
	ofstream os(filename, ofstream::app);
	if(!os) {
		cerr << "Error opening " << filename;
	}
	char ip6_addr[INET6_ADDRSTRLEN];
	char ip4_addr[INET_ADDRSTRLEN];
	
	for(int i = 0; i < siblings.size(); i++) {
		inet_ntop(AF_INET, &(siblings[i].ip4), ip4_addr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(siblings[i].ip6), ip6_addr, INET6_ADDRSTRLEN);
		
		os << ip6_addr << "," << ip4_addr << endl;
	}
}

//print all sibling pairs to stdout
void CandidateDecision::print() {
	char ip6_addr[INET6_ADDRSTRLEN];
	char ip4_addr[INET_ADDRSTRLEN];
	
	for(int i = 0; i < siblings.size(); i++) {
		inet_ntop(AF_INET, &(siblings[i].ip4), ip4_addr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(siblings[i].ip6), ip6_addr, INET6_ADDRSTRLEN);
		cout << ip6_addr << " , " << ip4_addr << endl;
	}
	cout << "Total of " << siblings.size() << " candidate pairs found." << endl;
}

//checks if IP is already in siblings or buffer
bool CandidateDecision::contains(const in6_addr& ip) {
	for(int i = 0; i < siblings.size(); i++) {
		if(!memcmp(siblings[i].ip6.s6_addr, ip.s6_addr, 16)) {
			return true;
		}
	}
	for(int i = 0; i < new_candidates.size(); i++) {
		if(!memcmp(new_candidates[i].ip6.s6_addr, ip.s6_addr, 16)) {
			return true;
		}
	}
	return false;
}

//checks if IP is already in siblings or buffer
bool CandidateDecision::contains(const in_addr& ip) {
	for(int i = 0; i < siblings.size(); i++) {
		if(siblings[i].ip4.s_addr == ip.s_addr) {
			return true;
		}
	}
	for(int i = 0; i < new_candidates.size(); i++) {
		if(new_candidates[i].ip4.s_addr == ip.s_addr) {
			return true;
		}
	}
	return false;
}

//checks if IP pair is already in siblings or buffer
bool CandidateDecision::contains(const in6_addr& ip1, const in_addr& ip2) {
	for(int i = 0; i < siblings.size(); i++) {
		if(siblings[i].ip4.s_addr == ip2.s_addr && !memcmp(siblings[i].ip6.s6_addr, ip1.s6_addr, 16)) {
			return true;
		}
	}
	for(int i = 0; i < new_candidates.size(); i++) {
		if(new_candidates[i].ip4.s_addr == ip2.s_addr && !memcmp(new_candidates[i].ip6.s6_addr, ip1.s6_addr, 16) && i != 0) {
			return true;
		}
	}
	return false;
}

void CandidateDecision::add(in6_addr ip1, in_addr ip2) {
	//discard sibling candidate when buffer is full
	mtx.lock();
	if(new_candidates.size() == new_candidates.max_size()) {
		mtx.unlock();
		return;
	}
	
	//we don't process a candidate pair again that is already in the siblings or the buffer
	if(!contains(ip1, ip2)) {
		ip_pair p;
		p.ip6 = ip1;
		p.ip4 = ip2;
		new_candidates.push_back(p);
	}
	mtx.unlock();
}

bool CandidateDecision::empty() {
	return new_candidates.size() == 0;
}

void CandidateDecision::start_decisions(char* outfile, char* neg_dec_file) {
	//open files if defined
	ofstream os;//output file for siblings
	if(outfile != NULL) {
		os.open(outfile, ofstream::app);
		if(!os) {
			cerr << "Error opening " << *outfile << endl;
		}
	}
	
	ofstream neg;//output file for non_siblings
	if(neg_dec_file != NULL) {
		neg.open(neg_dec_file, ofstream::app);
		if(!neg) {
			cerr << "Error opening " << *neg_dec_file << endl;
		}
	}
	
	char ip4[INET_ADDRSTRLEN] = {0};
	char ip6[INET6_ADDRSTRLEN] = {0};
	ip_pair* curr;
	//in_addr ipv4_addr;
	//in6_addr ipv6_addr;
	
	cout << "Sibling Pairs:\n";
	while(true) {
		mtx.lock();
		if(new_candidates.size() == 0) {
			mtx.unlock();
			usleep(100000);
			continue;
		}

		//pop next candidate pair
		curr = &(new_candidates.front());
		
		//memcpy(&ipv6_addr, &(curr->ip6), sizeof(ipv6_addr));
		//ipv4_addr = curr->ip4;
		
		//check if we have already found this sibling pair
		if(contains(curr->ip6, curr->ip4)) {
			new_candidates.pop_front();
			mtx.unlock();
			continue;
		}
		mtx.unlock();
		
		//parse IPs to String
		inet_ntop(AF_INET6, &(curr->ip6), ip6, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &(curr->ip4), ip4, INET_ADDRSTRLEN);
		
		
		archive.lock();

		//get reference to vector of packages for each ip
		vector<packet_info>* pi6 = archive.get(curr->ip6);
		vector<packet_info>* pi4 = archive.get(curr->ip4);
		
		if(pi6 == NULL || pi4 == NULL) {
			archive.unlock();
			mtx.lock();
			new_candidates.pop_front();
			mtx.unlock();
			continue;
		}

		
		//we wait with the decision until both IPs have finished their connection
		if(!archive.get_finished(pi4->front().ipv4_hdr.ip_src) || !archive.get_finished(pi6->front().ipv6_hdr.ip6_src)) {
			//discard packets where we have not received an answer within the last 5 seconds
			if(time_diff(pi6->back().time, current_packet_time) > 5) {
				archive.set_finished(true, pi6->front().ipv6_hdr.ip6_src);
			}
			if(time_diff(pi4->back().time, current_packet_time) > 5) {
				archive.set_finished(true, pi4->front().ipv4_hdr.ip_src);
			}
			archive.unlock();
			mtx.lock();
			new_candidates.push_back(*curr);
			new_candidates.pop_front();
			mtx.unlock();
			continue;
		}
		
		
		//less than 2 packets available?
		if(pi6->size() < 2 || pi4->size() < 2) {
			archive.unlock();
			mtx.lock();
			new_candidates.pop_front();
			mtx.unlock();
			continue;
		}

		//checks based on timestamps
		string error = "";
		if(!check_timestamps(pi6, pi4, error)) {
	 		archive.unlock();
			mtx.lock();
			new_candidates.pop_front();
			mtx.unlock();
			if(neg) {
				neg << ip6 << "," << ip4 << "," << error << endl;
			}
			continue;
		}

		//check if options are different or have different order
		if(strcmp((*pi6)[0].options_parsed, (*pi4)[0].options_parsed)) {
			archive.unlock();
			mtx.lock();
			new_candidates.pop_front();
			mtx.unlock();
			if(neg) {
				neg << ip6 << "," << ip4 << ",TCP options differ" << endl;
			}
			continue;
		}
		

		//save siblings together with the capturing time of the respective first SYN
		string ip4_time = ctime((const time_t *) &((*pi4)[0].time.tv_sec));
		string ip6_time = ctime((const time_t *) &((*pi6)[0].time.tv_sec));
		ip4_time = ip4_time.substr(0, ip4_time.size() - 1);
		ip6_time = ip6_time.substr(0, ip6_time.size() - 1);
		if(os) {
			os << ip6 << "," << ip4 << "," << ip6_time << "," << ip4_time << "," << pi6->front().timestamp << "," << pi4->front().timestamp << endl;
		}
		cout << ip6 << "," << ip4 << "," << ip6_time << "," << ip4_time << endl;
		archive.unlock();
		
		mtx.lock();
		siblings.push_back(*curr);
		new_candidates.pop_front();
		mtx.unlock();
		
		usleep(200);
	}
}

//adopted decision algorithm from El Deib et al.
bool CandidateDecision::decision_algorithm6(vector<packet_info>* ipv6, vector<packet_info>* ipv4, string& error) {
	double local_offset = abs((double)(ipv6->front().time.tv_sec - ipv4->front().time.tv_sec) + (double)(ipv6->front().time.tv_usec - ipv4->front().time.tv_usec)/1000000);
	double remote_offset = abs((int)(ipv6->front().timestamp - ipv4->front().timestamp));
	double calc_hz = remote_offset / local_offset;
	
	char i4[INET_ADDRSTRLEN] = {0};
	char i6[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET6, &((*ipv6)[0].ipv6_hdr.ip6_src), i6, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &((*ipv4)[0].ipv4_hdr.ip_src), i4, INET_ADDRSTRLEN);
	
	//less than 4 datapoints?
	if(ipv6->size() < 4 || ipv4->size() < 4) {
		
		if(calc_hz >= 9 && calc_hz <= 1100) {
			return true;
		} else {
			stringstream ss;
			ss << "Less than four packets, clock frequency invalid: " << calc_hz;
			error = ss.str();
		}
	} else {
		vector<double> v6_remote_offsets;
		vector<double> v6_local_offsets;
		vector<double> v4_remote_offsets;
		vector<double> v4_local_offsets;
		
		for(int i = 1; i < ipv6->size(); i++) {
			v6_remote_offsets.push_back((*ipv6)[i].timestamp - (*ipv6)[0].timestamp);
			v6_local_offsets.push_back((double)((*ipv6)[i].time.tv_sec - (*ipv6)[0].time.tv_sec) + (double)((*ipv6)[i].time.tv_usec - (*ipv6)[0].time.tv_usec)/1000000);
		}
		for(int i = 1; i < ipv4->size(); i++) {
			v4_remote_offsets.push_back((*ipv4)[i].timestamp - (*ipv4)[0].timestamp);
			v4_local_offsets.push_back((double)((*ipv4)[i].time.tv_sec - (*ipv4)[0].time.tv_sec) + (double)((*ipv4)[i].time.tv_usec - (*ipv4)[0].time.tv_usec)/1000000);
		}
		double hz6 = linear_regression_slope(v6_remote_offsets, v6_local_offsets);
		double hz4 = linear_regression_slope(v4_remote_offsets, v4_local_offsets);
		
		if(hz6 >= hz4 * 0.8 && hz6 <= hz4 * 1.2) {
			//compare raw timestamp values
			//(raw_local is the same as local_offset from above)
			double raw_remote = abs((*ipv6)[0].timestamp / hz6 - (*ipv4)[0].timestamp / hz4);
			if(abs(raw_remote - local_offset) <= 1 && calc_hz <= 1100) {
				return true;
			} else {
				if(calc_hz >= 9 && calc_hz <= 1100) {
					return true;
				}
			}
		}
		double m=0, b=0, r6=0, r4=0;
		r6 = leastSqrRegression(v6_remote_offsets, v6_local_offsets);
		r4 = leastSqrRegression(v4_remote_offsets, v4_local_offsets);

		
		if(r6 == -1 || r4 == -1) {
			cerr << "Failed to calculate R^2\n";
			error = "Invalid coefficients R^2";
			return false;
		}
		if(r6 != 0 && r4 != 0 && calc_hz <= 1100 && r6 >= 0.81 && r4 >= 0.81) {
			if(r6 >= r4*0.9 && r6 <= r4*1.1) {
				return true;
			} else {
				stringstream ss;
				ss << "R^2 deviation too big: r4 = " << r4 << " , r6 = " << r6;
				error = ss.str();
			}
		} else {
			stringstream ss;
			ss << "Values not valid: r6 != 0 && r4 != 0 && calc_hz <= 1100 && r6 >= 0.81 && r4 >= 0.81 failed, actual values: r6 = " << r6;
			ss << " , r4 = " << r4 << " , calc_hz = " << calc_hz << " , r6 = " << r6 << " , r4 = " << r4;
			error = ss.str();
		}
	}
	
	return false;
}

bool CandidateDecision::check_timestamps(vector<packet_info>* ipv6, vector<packet_info>* ipv4, string& error) {
	//timediff between first and last packet of connections
	double timediff6 = (double)(ipv6->back().time.tv_sec - ipv6->front().time.tv_sec) + (double)(ipv6->back().time.tv_usec - ipv6->front().time.tv_usec)/1000000;
	double timediff4 = (double)(ipv4->back().time.tv_sec - ipv4->front().time.tv_sec) + (double)(ipv4->back().time.tv_usec - ipv4->front().time.tv_usec)/1000000;
	//timediff between first packets of the two connections
	double timediff = abs((double)(ipv6->front().time.tv_sec - ipv4->front().time.tv_sec) + (double)(ipv6->front().time.tv_usec - ipv4->front().time.tv_usec)/1000000);
	
	//remote clock frequency
	long rateIPv4 = (long)((ipv4->back().timestamp - ipv4->front().timestamp) / timediff4);
	long rateIPv6 = (long)((ipv6->back().timestamp - ipv6->front().timestamp) / timediff6);
	
	if(timediff < 0.45) {
		//probably HappyEybeballs
		//  --> rough comparison of absolute timestamp values
		if(abs((int)(ipv6->front().timestamp - ipv4->front().timestamp)) > 400) {
			stringstream ss;
			ss << "Timediff < 0.45s, but timestamps difference is larger than threshold 400: " << abs((int)(ipv6->front().timestamp - ipv4->front().timestamp));
			error = ss.str();
			return false;
		} else {
			//if packets cover a timespan of more than 250 ms, additionally compare clock frequencies to be roughly the same
			if(timediff6 < 0.25 || timediff4 < 0.25 || abs(rateIPv6 - rateIPv4) < 0.25*rateIPv6) {
				return true;
			} else {
				stringstream ss;
				ss << "timediff6 < 0.25 || timediff4 < 0.25 || abs(rateIPv6 - rateIPv4) < 0.25*rateIPv6 failed: timediff6 = " << timediff6 << " , timediff4 = " << timediff4;
				ss << " , ratediff = " << abs(rateIPv6 - rateIPv4);
				error = ss.str();
				return false;
			}
		}
	} else {
		//timestamp estimation
		if(timercmp(&ipv6->front().time, &ipv4->front().time, <)) {
			//the IPv6 connection started first
			
			//check if difference between estimated timestamp and received timestamp is too high
			if(abs((long)ipv6->front().timestamp + timediff * rateIPv6 - ipv4->front().timestamp) > timediff*0.13*rateIPv6) {
				stringstream ss;
				ss << "Timestamp estimation failed: Estimation = " << abs((long)ipv6->front().timestamp + timediff * rateIPv6);
				ss << " , threshold for difference from true ts = " << timediff*0.13*rateIPv6 << " , difference = ";
				ss << abs((long)ipv6->front().timestamp + timediff * rateIPv6 - ipv4->front().timestamp);
				error = ss.str();
				return false;
			}
		} else {
			//the IPv4 connection started first

			//check if difference between estimated timestamp and received timestamp is too high
			if(abs((long)ipv4->front().timestamp + timediff * rateIPv4 - ipv6->front().timestamp) > timediff*0.13*rateIPv4) {
				stringstream ss;
				ss << "Timestamp estimation failed: Estimation = " << abs((long)ipv4->front().timestamp + timediff * rateIPv4);
				ss << " , threshold for difference from true ts = " << timediff*0.13*rateIPv4 << " , difference = ";
				ss << abs((long)ipv4->front().timestamp + timediff * rateIPv4 - ipv6->front().timestamp);
				error = ss.str();
				return false;
			}
		}
		
		//run adopted decision algorithm
		if(decision_algorithm6(ipv6, ipv4, error)) {
			return true;
		} else {
			return false;
		}
	}
}



