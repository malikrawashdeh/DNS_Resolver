// Malik Rawashdeh
// CSCE 612 Fall 2024

#include "pch.h"
/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */ 

/* query classes */
#define DNS_INET 1

/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */

/* result codes */
#define DNS_OK 0 /* success */
#define DNS_FORMAT 1 /* format error (unable to interpret) */
#define DNS_SERVERFAIL 2 /* can’t find authority nameserver */
#define DNS_ERROR 3 /* no DNS entry */
#define DNS_NOTIMPL 4 /* not implemented */
#define DNS_REFUSED 5 /* server refused the query */ 

//
#define MAX_DNS_SIZE 512 // largest valid UDP packet 

// DNS port 
#define DNS_PORT 53

// MAX RETRY
#define MAX_RETRY 3



#pragma once
#pragma pack(push,1)   // sets struct padding/alignment to 1 byte

class DNSRecord {
public:
	std::string name;
	u_short type;
	u_short dns_class;
	u_int ttl;
	u_short len;
	std::string data;
};

class QueryHeader {
public:
	u_short qType;
	u_short qClass;
};

class FixedDNSheader {
public:
	u_short ID;
	u_short flags;
	u_short questions;
	u_short answers;
	u_short authority_rrs;
	u_short additional_rrs;
};

class DNSanswerHdr {
public:
	u_short type;
	u_short dns_class;
	u_int ttl;
	u_short len;
};

#pragma pack(pop)  // restores old packing