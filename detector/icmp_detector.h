/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2012-2024 Applied Communication Sciences
 * (now Peraton Labs Inc.)
 *
 * This software was developed in work supported by the following U.S.
 * Government contracts:
 *
 * HR0011-20-C-0160 HR0011-16-C-0061
 * 
 *
 * Any opinions, findings and conclusions or recommendations expressed in
 * this material are those of the author(s) and do not necessarily reflect
 * the views, either expressed or implied, of the U.S. Government.
 *
 * DoD Distribution Statement A
 * Approved for Public Release, Distribution Unlimited
 *
 * DISTAR 40011, cleared July 24, 2024
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __ICMPDETECTOR_H__
#define __ICMPDETECTOR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include "../common/config.h"
#include "rangeTree.h"
#include "stdutil/stddll.h"

#define icmpDetectorBufferSize 10000000

#define LOG( ...) \
        icmpDetectorLog( __func__,  __LINE__,  __VA_ARGS__);

    struct ICMPDetectorData {
        uint32_t port;
        uint32_t ip;
        uint32_t protocol;
        uint32_t count;

    };
    typedef struct ICMPDetectorData ICMPDetectorData;

    struct WhitelistDataNode {
        //Prod3__CIDR* cidr;
        uint32_t ip;
        uint32_t port_from;
        uint32_t port_to;
        uint32_t protocol;
    };
    typedef struct WhitelistDataNode WhitelistDataNode;

    struct WhitelistInfo {

        uint32_t ip;
        WhitelistDataNode *whitelist;
        int whitelistSize;
        int whitelistSent;
    };
    typedef struct WhitelistInfo WhitelistInfo;

    struct WhitelistInfoKey {
        //Prod3__IPAddress ip;
        uint32_t ip;
    };
    typedef struct WhitelistInfoKey WhitelistInfoKey;

    ICMPDetectorData icmpDetectorPeek();

    bool icmpDetectorIsEmpty();

    bool icmpDetectorIsFull();

    int icmpDetectorItemsInBuffer();

    void icmpDetectorInsert(ICMPDetectorData data);
    void icmpDetectorInsertValues(uint32_t port, uint32_t protocol, uint32_t ip, uint32_t count);

    ICMPDetectorData icmpDetectorRemoveData();

    void icmpDetectorLog(const char *func, const unsigned int line, const char *format, ...);
    void icmpDetectorNotice(char *format, ...);
    void icmpDetectorErrorVpp(char *format, ...);
    void icmpDetectorErrorFatal(char *format, ...);
    void icmpDetectorSSV(const char *format, ...);

    void *icmpDetectorThreadFunction(void *arg);

    void initialize_icmp_detector();
    void destroy_icmp_detector();

    int processAlert_icmp(ICMPDetectorData item);

    void setMyIp(struct in_addr *ip);
    void setupLogs_icmp();

    struct ICMPCountNode {

        long unsigned timestamp;
        int count;
        int port;
        int newPortFlag;        //0 - existing port; 1 - new port
    };
    typedef struct ICMPCountNode ICMPCountNode;
    struct IPInfo {

        long unsigned lastTimeSent;
        RangeTree *portTree;
        int changedRangesNum;
        //Prod3__IPAddress ip;
        uint32_t ip;
        uint32_t protocol;
        WhitelistDataNode *icmpDetectorWhitelist;
        int icmpDetectorWhitelistSize;
        int whitelistSent;
        stddll countList;       //linked list of counts with timestamps
        int newPortCount;       //count of unique ports per lookback interval
        int packetCount;        //count of icmp packets per lookback interval
    };
    typedef struct IPInfo IPInfo;
    struct IPInfoKey {
        //Prod3__IPAddress ip;
        uint32_t ip;
        uint32_t protocol;
    };
    typedef struct IPInfoKey IPInfoKey;
/**********************
struct WhitelistInfo {

        uint32_t ip;
	WhitelistDataNode *icmpDetectorWhitelist;
	int icmpDetectorWhitelistSize;
	int whitelistSent;
};
typedef struct WhitelistInfo WhitelistInfo;
struct WhitelistInfoKey {
        //Prod3__IPAddress ip;
        uint32_t ip;
};
typedef struct WhitelistInfoKey WhitelistInfoKey;
*******************************/

    extern pthread_cond_t icmpDetectorQueueCond;
    extern pthread_mutex_t icmpDetectorMutex;

    void sendDDOS(IPInfo * node);
    void sendWhitelist_icmp(IPInfo * IPInfoNode);
    void calculateRate(IPInfo * node);
    void sendDDOSIfThreshold(IPInfo * node);
#ifdef __cplusplus
}
#endif
#endif
