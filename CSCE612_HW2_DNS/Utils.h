// Malik Rawashdeh
// CSCE 612 Fall 2024

#include "pch.h"

#pragma once

class Utils
{
public:
	/****
	* Function Name: Utils::GetQueryType
	* Description: This function is used to get the query type from the user input: 1 for A, 2 for NS, 5 for CNAME, 6 for SOA, 12 for PTR, 15 for MX, 28 for AAAA, 33 for SRV, 255 for ALL
	*/
	static u_short GetQueryType(char* queryType);

	/****
	* Function Name: Utils::GenerateTransactionID
	* Description: This function is used to generate a random transaction ID
	*/
	static u_short GenerateTransactionID();

	static std::string ReformatIP(char* ip);

};

