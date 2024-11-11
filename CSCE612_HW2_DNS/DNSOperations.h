// Malik Rawashdeh
// CSCE 612 Fall 2024

#include "pch.h"

#pragma once
class DNSOperations
{
private:
	// private members
	// query buff
	char query_packet[MAX_DNS_SIZE];

	// response buff
	char response_buff[MAX_DNS_SIZE];
	int response_size = MAX_DNS_SIZE;

	// hashmap of query types to strings
	std::map<u_short, std::string> query_types = {
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{12, "PTR"},
		{15, "MX"},
		{28, "AAAA"},
		{33, "SRV"},
		{255, "ALL"}
	};

	// print the answers for the current section of the packet
	// take in cur_pos and the number of answers to print
	bool PrintDNSAnswers(int& cur_pos, int num_answers);

	// private methods
	// construct the DNS query
	bool ConstructDNSQuery(char* lookup_str, u_short query_type, u_short transaction_ID);

	// send the query to the DNS server
	bool SendDNSQuery(char* dns_server, int query_size);

	bool ParseDNSRecord(unsigned char* buffer, int& cur_pos, DNSRecord& record);

	// parse the DNS domain name 
	std::string ParseDNSDomainName(unsigned char* buffer, int& cur_pos);

	// parse the DNS response
	bool ParseDNSResponse(u_short orig_txid);


public:
	DNSOperations();
	~DNSOperations();
	bool ProcessDNS(char* lookup, char* dns_server);
};

