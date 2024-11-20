# DNS_Resolver
DNS resolver to resolve hostname -> IPv4 lookups (A record) or IPv4 -> hostname (PTR)  
This project implements a custom DNS resolver that communicates directly with a DNS server over UDP, issuing recursive queries and parsing responses without relying on high-level libraries. The resolver supports various query types, error handling, and retransmission for robustness.

## Features

- Direct communication with DNS servers over UDP.
- Parsing and outputting DNS responses, including:
  - Questions
  - Answers
  - Authority
  - Additional sections
- Support for compressed and uncompressed DNS responses.
- Error handling for:
  - Malformed packets
  - Timeout scenarios
  - Invalid responses
- Retransmission mechanism for robust querying.
- Support for both **DNS_A** (hostname to IP) and **DNS_PTR** (IP to hostname) query types.

## Usage

The program requires two command-line arguments:
1. The lookup string (hostname or IP).
2. The DNS server's IP address.

### Example Commands

```bash
./dns_resolver www.google.com 8.8.8.8
./dns_resolver 192.0.2.1 8.8.4.4
```

### Example Output
```plaintext
Lookup  : www.google.com
Query   : www.google.com, type 1, TXID 0x34C9
Server  : 8.8.8.8
********************************
Attempt 0 with 32 bytes... response in 25 ms with 112 bytes
  TXID 0x34C9 flags 0x8180 questions 1 answers 5 authority 0 additional 0
  succeeded with Rcode = 0
  ------------ [questions] ----------
        www.google.com type 1 class 1
  ------------ [answers] ------------
        www.google.com A 74.125.227.244 TTL = 299
        www.google.com A 74.125.227.243 TTL = 299
        www.google.com A 74.125.227.240 TTL = 299
        www.google.com A 74.125.227.241 TTL = 299
        www.google.com A 74.125.227.242 TTL = 299
```

## Technical Highlights

- **Programming Language**: C++
- **Network Protocol**: UDP for direct DNS communication.
- **Platform**: Tested on Windows using Winsock.

## Key Components

### DNS Packet Structure
- Fixed header: 12 bytes as per RFC 1035.
- Variable-length question and resource records for queries and responses.
- Compression handling for response parsing.

### Retransmission Mechanism
- Retries up to 3 times with a 10-second timeout for each attempt.

### Error Detection
- Identifies and reports:
  - Malformed packets
  - Truncated responses
  - Invalid or mismatched transaction IDs
  - Socket errors and timeouts

### Supported Query Types
- **DNS_A**: Hostname to IP address.
- **DNS_PTR**: IP address to hostname.

## Performance Metrics

The resolver provides detailed output for each query, including:
- Bytes sent and received.
- Response time in milliseconds.
- DNS flags and section counts (questions, answers, authority, additional).
- Parsed results for all supported record types (A, CNAME, PTR, NS).

## References

- [RFC 1034](https://www.ietf.org/rfc/rfc1034.txt) and [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt) for DNS protocol standards.
- [Network Sorcery's DNS Reference](http://www.networksorcery.com/enp/protocol/dns.htm) for protocol details.
- Wireshark for packet analysis and debugging.
