// Malik Rawashdeh
// CSCE 612 Fall 2024
#include "pch.h"
#include "DNSOperations.h"

DNSOperations::DNSOperations() {

}

DNSOperations::~DNSOperations() {
}

bool DNSOperations::PrintDNSAnswers(int& cur_pos, int num_answers) {
	for (int i = 0; i < num_answers; i++) {

		string domain_name = ParseDNSDomainName((unsigned char*)response_buff, cur_pos);
		if (domain_name.empty()) {
			return false;
		}

		if (cur_pos + sizeof(DNSanswerHdr) > response_size) {
			printf("  ++ invalid record: truncated RR answer header\n");
			// throw exception
			return false;
		}

		DNSanswerHdr* dah = (DNSanswerHdr*)(response_buff + cur_pos);

		u_short type = ntohs(dah->type);

		u_short dns_class = ntohs(dah->dns_class);

		u_int ttl = ntohl(dah->ttl);

		u_short data_length = ntohs(dah->len);



		string record_type = "";
		// chek if the type is in the map
		if (query_types.find(type) != query_types.end()) {
			record_type = query_types[type];
		}
		else {
			record_type = "UNKNOWN";
		}

		// get the domain name 
		cur_pos += sizeof(DNSanswerHdr);

		if (cur_pos + data_length > response_size) {
			printf("  ++ invalid record: truncated data\n");
			// throw exception
			return false;
		}

		// get the resource data into a string (ie ip if A record or domain name if PTR)
		string resource_data = "";
		if (type == DNS_A) {
			struct in_addr addr;
			// check if there is enough data to read the ip address
			if (cur_pos + data_length > response_size) {
				printf("  ++ invalid record: truncated data\n");
				// throw exception
				return false;
			}

			memcpy(&addr, response_buff + cur_pos, sizeof(addr));
			resource_data = inet_ntoa(addr);
			cur_pos += data_length;
		}
		else if (type == DNS_PTR || type == DNS_NS || type == DNS_CNAME) {
			resource_data = ParseDNSDomainName((unsigned char*)response_buff, cur_pos);
			if (resource_data.empty()) {
				return false;
			}
		}  // skip if AAAA 

		printf("        %s %s %s TTL = %d\n", domain_name.c_str(), record_type.c_str(), resource_data.c_str(), ttl);
	}
	return true;
}

bool DNSOperations::ParseDNSRecord(unsigned char* buffer, int& cur_pos, DNSRecord& record) {
	string domain_name = ParseDNSDomainName((unsigned char*)response_buff, cur_pos);
	if (domain_name.empty()) {
		return false;
	}

	if (cur_pos + sizeof(DNSanswerHdr) > response_size) {
		printf("  ++ invalid record: truncated RR answer header\n");
		// throw exception
		return false;
	}

	DNSanswerHdr* dah = (DNSanswerHdr*)(response_buff + cur_pos);

	u_short type = ntohs(dah->type);

	u_short dns_class = ntohs(dah->dns_class);

	u_int ttl = ntohl(dah->ttl);

	u_short data_length = ntohs(dah->len);



	string record_type = "";
	// chek if the type is in the map
	if (query_types.find(type) != query_types.end()) {
		record_type = query_types[type];
	}
	else {
		record_type = "UNKNOWN";
	}

	// get the domain name 
	cur_pos += sizeof(DNSanswerHdr);

	if (cur_pos + data_length > response_size) {
		printf("  ++ invalid record: RR value length stretches the answer beyond packet\n");
		// throw exception
		return false;
	}

	// get the resource data into a string (ie ip if A record or domain name if PTR)
	string resource_data = "";
	if (type == DNS_A) {
		struct in_addr addr;
		// check if there is enough data to read the ip address
		if (cur_pos + data_length > response_size) {
			printf("  ++ invalid record: RR value length stretches the answer beyond packet\n");
			// throw exception
			return false;
		}

		memcpy(&addr, response_buff + cur_pos, sizeof(addr));
		resource_data = inet_ntoa(addr);
		cur_pos += data_length;
	}
	else if (type == DNS_PTR || type == DNS_NS || type == DNS_CNAME) {
		resource_data = ParseDNSDomainName((unsigned char*)response_buff, cur_pos);
		if (resource_data.empty()) {
			return false;
		}
	}  // skip if AAAA 

	record.name = domain_name;
	record.type = type;
	record.dns_class = dns_class;
	record.ttl = ttl;
	record.len = data_length;
	record.data = resource_data;
}

string DNSOperations::ParseDNSDomainName(unsigned char* buffer, int& cur_pos) {
	// parse the domain name
	string domain_name = "";
	bool jumped = false;
	int orig_pos = cur_pos;
	bool first = true;
	// set to check if there is jump loop
	set<int> jump_set;

	while (buffer[cur_pos] != 0) {
		// check if compressed 
		if (buffer[cur_pos] >= 0xC0) {
			if (!jumped) {
				orig_pos = cur_pos + 2;
				jumped = true;
			}
			// check if current pos + 1 is beyond the packet boundary
			if (cur_pos + 1 >= response_size) {
				printf("  ++ invalid record: truncated jump offset\n");
				// return empty string
				return "";
			}

			// Calculates the 14-bit offset for the compressed domain name
			// Mask the first byte to get the last 6 bits and shift them left 8 bits, then add the next byte
			int new_offset = (buffer[cur_pos] & 0x3F) << 8 | buffer[cur_pos + 1];

			// check if jump into fixed dns header
			if (new_offset < sizeof(FixedDNSheader)) {
				printf("  ++ invalid record: jump into fixed DNS header\n");
				// return empty string
				return "";
			}

			// Check if the new_offset is beyond the packet boundary
			if (new_offset >= response_size) {
				printf("  ++ invalid record: jump beyond packet boundary (new_offset = %d, response_size = %d)\n", new_offset, response_size);
				// return empty string
				return "";
			}

			// check if the new_offset is in the jump set
			// detexts loops
			if (jump_set.find(new_offset) != jump_set.end()) {
				printf("  ++ invalid record: jump loop\n");
				// return empty string
				return "";
			}
			jump_set.insert(new_offset);

			cur_pos = new_offset;
		}
		else {
			int length = buffer[cur_pos];
			cur_pos++;
			if (!first) {
				domain_name.append(".");
			}
			for (int i = 0; i < length; i++) {
				// check if cur_pos + i is beyond the packet boundary or if end of domain name
				if (cur_pos + i < response_size && buffer[cur_pos + i] != 0) {
					domain_name.append(1, buffer[cur_pos + i]);

				}
				else {
					printf("  ++ invalid record: truncated name\n");
					// throw exception
					return "";
				}

			}
			first = false;
			cur_pos += length;
		}
	}

	if (jumped) {
		cur_pos = orig_pos;
	}
	else {
		cur_pos++;
	}
	return domain_name;
}

bool DNSOperations::ParseDNSResponse(u_short orig_txid) {

	FixedDNSheader* dh = (FixedDNSheader*)response_buff;
	// read fdh->ID and other fields
	u_short tx_id = ntohs(dh->ID);
	u_short flags = ntohs(dh->flags);
	u_short num_questions = ntohs(dh->questions);
	u_short num_answers = ntohs(dh->answers);
	u_short num_authority_rrs = ntohs(dh->authority_rrs);
	u_short num_additional_rrs = ntohs(dh->additional_rrs);
	u_short rcode = flags & 0xF;

	// print out TXID 0x0001, flags 0x8180, questions 1, answers 3, authority 5, additional 6 
	printf("  TXID %X, flags %X, questions %d, answers %d, authority %d, additional %d\n",
		tx_id, flags, num_questions, num_answers, num_authority_rrs, num_additional_rrs);

	if (tx_id != orig_txid) {
		// ex: ++ invalid reply: TXID mismatch, sent 0x0871, received 0x0872 
		printf("  ++ invalid reply: TXID mismatch, sent 0x%X, received 0x%X\n", orig_txid, tx_id);
		return false;
	}

	// print succeeded with Rcode = 0
	if (rcode != 0) {
		printf("  failed with Rcode = %d\n", rcode);
		return false;
	}

	printf("  Succeeded with Rcode = %d\n", rcode);

	int total_records = num_answers + num_authority_rrs + num_additional_rrs;

	int cur_pos = sizeof(FixedDNSheader);
	if (num_questions) {
		printf("  ------------ [questions] ----------\n");
		// parse questions and arrive to answer
		for (int i = 0; i < num_questions && cur_pos < response_size; i++) {
			string domain_name = ParseDNSDomainName((unsigned char*)response_buff, cur_pos);
			// check if domain name is null
			if (domain_name.empty()) {
				return false;
			}
			QueryHeader* qh = (QueryHeader*)(response_buff + cur_pos);
			u_short qType = ntohs(qh->qType);
			u_short qClass = ntohs(qh->qClass);
			// format:  yahoo.com type 1 class 1
			printf("        %s type %d class %d\n", domain_name.c_str(), qType, qClass);
			// read qh->qType and other fields
			cur_pos += sizeof(QueryHeader);
		}
	}


	vector<DNSRecord> records;
	// keep parsing the answers until we reach the end of the packet
	while (cur_pos < response_size) {
		DNSRecord record;
		if (!ParseDNSRecord((unsigned char*)response_buff, cur_pos, record)) {
			return false;
		}
		records.push_back(record);
		total_records--;
	}

	// check if we have the correct number of records
	if (total_records != 0) {
		printf("  ++ invalid section: not enough records\n");
		return false;
	}

	// now print the records
	if (num_answers > 0) {
		printf("  ------------ [answers] ----------\n");
		for (int i = 0; i < num_answers; i++) {
			DNSRecord record = records[i];
			printf("        %s %s %s TTL = %d\n", record.name.c_str(), query_types[record.type].c_str(), record.data.c_str(), record.ttl);
		}
	}

	if (num_authority_rrs > 0) {
		printf("  ------------ [authority] ----------\n");
		for (int i = num_answers; i < num_answers + num_authority_rrs; i++) {
			DNSRecord record = records[i];
			printf("        %s %s %s TTL = %d\n", record.name.c_str(), query_types[record.type].c_str(), record.data.c_str(), record.ttl);
		}
	}

	if (num_additional_rrs > 0) {
		printf("  ------------ [additional] ----------\n");
		for (int i = num_answers + num_authority_rrs; i < num_answers + num_authority_rrs + num_additional_rrs; i++) {
			DNSRecord record = records[i];
			printf("        %s %s %s TTL = %d\n", record.name.c_str(), query_types[record.type].c_str(), record.data.c_str(), record.ttl);
		}
	}


	/*
	if (num_answers > 0) {
		printf("  ------------ [answers] ----------\n");
		if (!PrintDNSAnswers(cur_pos, num_answers)) {
			return false;
		}
	}


	// parse answers

	if (num_authority_rrs > 0) {
		printf("  ------------ [authority] ----------\n");
		if (!PrintDNSAnswers(cur_pos, num_authority_rrs)) {
			return false;
		}
	}

	if (num_additional_rrs > 0) {
		printf("  ------------ [additional] ----------\n");
		if (!PrintDNSAnswers(cur_pos, num_additional_rrs)) {
			return false;
		}
	}
	*/
	return true;
}

bool DNSOperations::ConstructDNSQuery(char* lookup_str, u_short query_type, u_short transaction_ID) {

	int pkt_size = sizeof(FixedDNSheader) + strlen(lookup_str) + 2 + sizeof(QueryHeader);

	// fixed field initialization
	FixedDNSheader* dh = (FixedDNSheader*)query_packet;
	QueryHeader* qh = (QueryHeader*)(query_packet + pkt_size - sizeof(QueryHeader));
	dh->ID = htons(transaction_ID);
	dh->flags = htons(0x0100);  // Standard query with recsion 
	dh->questions = htons(1);  // 1 question
	// na stuff 
	dh->answers = 0;
	dh->authority_rrs = 0;
	dh->additional_rrs = 0;

	// fill in the query using the lookup string and query type we decided
	qh->qType = htons(query_type);
	qh->qClass = htons(1);  // internet class



	// fill in the question
	char* qname = query_packet + sizeof(FixedDNSheader);
	/*
	/*
	makeDNSquestion (char* buf, char *host) {
		while(words left to copy){
		buf[i++] = size_of_next_word;
		memcpy (buf+i, next_word, size_of_next_word);
		i += size_of_next_word;
		}
		buf[i] = 0; // last word NULL-terminated
	}
	*/
	int i = 0;
	const char* nxt_word = lookup_str;
	while (*nxt_word != '\0') {
		const char* found_dot = strchr(nxt_word, '.');
		if (found_dot == NULL) {
			// last word
			qname[i++] = strlen(nxt_word);
			memcpy(qname + i, nxt_word, strlen(nxt_word));
			i += strlen(nxt_word);
			break;
		}
		else {
			// not last word
			qname[i++] = found_dot - nxt_word;
			memcpy(qname + i, nxt_word, found_dot - nxt_word);
			i += found_dot - nxt_word;
			nxt_word = found_dot + 1;
		}
	}
	qname[i] = 0;  // End of domain name

	return true;
}

bool DNSOperations::SendDNSQuery(char* dns_server, int query_size) {

	// Create a socket
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return false;
	}

	// Set up the destination address
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(DNS_PORT);
	dest.sin_addr.s_addr = inet_addr(dns_server);

	int timeout_ms = 10000; // 10 seconds
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
	struct sockaddr_in response_from;
	int from_len = sizeof(response_from);

	for (int i = 0; i < MAX_RETRY; i++) {
		printf("Attempt %d with %d bytes... ", i, query_size);
		// time the send
		clock_t start = clock();
		// Send the DNS query
		int sendResult = sendto(sock, query_packet, query_size, 0, (struct sockaddr*)&dest, sizeof(dest));

		if (sendResult == SOCKET_ERROR) {
			printf("sendto failed with error: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			return false;
		}

		// Receive the DNS response
		memset(response_buff, 0, MAX_DNS_SIZE);

		int recvResult = recvfrom(sock, response_buff, MAX_DNS_SIZE, 0, (struct sockaddr*)&response_from, &from_len);
		// get num ms 
		clock_t end = clock();
		unsigned int elapsedTime = 1000.0 * (end - start) / CLOCKS_PER_SEC;

		if (recvResult == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAETIMEDOUT) {
				printf(" timeout in %d ms\n", elapsedTime);
				if (i == MAX_RETRY - 1) {
					closesocket(sock);
					WSACleanup();
					return false;
				}
				continue;
			}
			printf("recvfrom failed with error: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			return false;
		}
		// check if the this packet cane frin tge server we sent the query to
		if (response_from.sin_addr.s_addr != dest.sin_addr.s_addr || response_from.sin_port != dest.sin_port) {
			printf("received packet from unknown source\n");
			closesocket(sock);
			WSACleanup();
			return false;
		}


		printf("response in %d ms with %d bytes\n", elapsedTime, recvResult);
		// check if the response is valid
		if (recvResult < sizeof(FixedDNSheader)) {
			printf("  ++ invalid reply: packet smaller than fixed DNS header\n");
			closesocket(sock);
			WSACleanup();
			return false;
		}

		response_size = recvResult;
		break;
	}

	closesocket(sock);
	WSACleanup();

	return true;
}

bool DNSOperations::ProcessDNS(char* lookup_str, char* dns_server) {
	// Decide query type either A or PTR (1 for A, 12 for PTR)
	u_short query_type = Utils::GetQueryType(lookup_str);
	char* lookup_str_ptr;
	// reformat the lookup string if it is an IP address
	string new_lookup_str;
	if (query_type == DNS_PTR) {
		// reformat the lookup string if it is an IP address
		new_lookup_str = Utils::ReformatIP(lookup_str);
		lookup_str_ptr = new char[new_lookup_str.length() + 1];
		strcpy_s(lookup_str_ptr, new_lookup_str.length() + 1, new_lookup_str.c_str());
	}
	else {
		lookup_str_ptr = lookup_str;
	}

	u_short transaction_ID = Utils::GenerateTransactionID();
	printf("Lookup  : %s\n", lookup_str);
	printf("Query   : %s, type %d, TXID %X\n", lookup_str_ptr, query_type, transaction_ID);
	printf("Server  : %s\n", dns_server);
	printf("********************************\n");

	// Construct the DNS query
	if (!ConstructDNSQuery(lookup_str_ptr, query_type, transaction_ID)) {
		// delete the lookup string if it was reformatted
		if (query_type == DNS_PTR) {
			delete[] lookup_str_ptr;
		}
		return false;
	}
	if (!SendDNSQuery(dns_server, sizeof(FixedDNSheader) + strlen(lookup_str_ptr) + 2 + sizeof(QueryHeader))) {
		if (query_type == DNS_PTR) {
			delete[] lookup_str_ptr;
		}
		return false;
	}
	if (!ParseDNSResponse(transaction_ID)) {
		if (query_type == DNS_PTR) {
			delete[] lookup_str_ptr;
		}
		return false;
	}
	if (query_type == DNS_PTR) {
		delete[] lookup_str_ptr;
	}
	return true;
}
