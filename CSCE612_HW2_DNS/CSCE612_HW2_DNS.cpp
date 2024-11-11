// Malik Rawashdeh
// CSCE 612 Fall 2024\
// CSCE612_HW2_DNS.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

// CSCE612_HW2_DNS.cpp : This file contains the 'main' function. Program execution begins and ends there.
// input: look up string (IP or hostname) and DNS server IP to which the query is sent
int main(int argc, char* argv[])
{
	if (argc != 3) {
		printf("Usage: %s <lookup string> <DNS Server IP>\n", argv[0]);
		return 1;
	}

	WSADATA wsaData;
	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	char* lookup = argv[1];
	char* dns_server = argv[2];
	DNSOperations dns;
	if (!dns.ProcessDNS(lookup, dns_server)) {
		return 1;
	}

	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
