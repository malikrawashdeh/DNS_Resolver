
// Malik Rawashdeh
// CSCE 612 Fall 2024
// 
// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "Ws2_32.lib")



// add headers that you want to pre-compile here
// printf
#include <stdio.h>
#include <cstdlib>  // for rand()
#include <ctime>    // for time()
#include <chrono>  // for high_resolution_clock
#include <iostream>
#include <string>
#include <vector>
#include <map> // for map of query types to strings
#include <set>
#include <stdexcept>
#include <ws2tcpip.h> 

#include <WinSock2.h>
#include <windows.h>

#include "DNSHeaders.h"
#include "Utils.h"
#include "DNSOperations.h"

// using...
using std::string;
using std::map;
using std::vector;
using std::runtime_error;
using std::set;
// type def
typedef unsigned short u_short;

#endif //PCH_H
