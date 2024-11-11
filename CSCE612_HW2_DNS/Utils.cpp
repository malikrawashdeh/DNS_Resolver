// Malik Rawashdeh
// CSCE 612 Fall 2024
#include "pch.h"
#include "Utils.h"

u_short Utils::GetQueryType(char* lookup_str) {
	// To decide whether the query is an IP or hostname, pass it through inet_addr(). If this function
	// succeeds, proceed with a type - PTR query.Otherwise, use type - A.
	if (inet_addr(lookup_str) == INADDR_NONE) {
		return DNS_A;
	}
	else {
		return DNS_PTR;
	}
}

u_short Utils::GenerateTransactionID() {
	// Initialize random seed
	srand(static_cast<unsigned int>(time(0)));  // seed with current time

	// 16 bit random number
	return static_cast<u_short>(rand() % 0xFFFF);  // random number between 0 and 65535
}

string Utils::ReformatIP(char* ip) {
	// Reformat the IP address to the format required by the DNS server
	string ip_str(ip);
	string new_ip = "";
	vector<string> octets;
	size_t i = 0;

	// 1-- split the IP address into octets
	while ((i = ip_str.find(".")) != string::npos) {
		octets.push_back(ip_str.substr(0, i));
		ip_str.erase(0, i + 1);
	}
	octets.push_back(ip_str);

	// reverse
	for (int i = octets.size() - 1; i >= 0; i--) {
		new_ip += octets[i];
		if (i != 0) {
			new_ip += ".";
		}
	}

	new_ip += ".in-addr.arpa";

	return new_ip;
}