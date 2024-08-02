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
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "icmp_detector.h"
#include "rangeTree.h"
#include "stdutil/stdcarr.h"
#include "stdutil/stdhash.h"

extern int getSequenceNumber(void);

static pthread_mutex_t icmp_init_mutex = PTHREAD_MUTEX_INITIALIZER;     //lock for initializer function
pthread_cond_t icmpDetectorQueueCond;
pthread_mutex_t icmpDetectorMutex;
stdhash IPHash;
stdhash WhitelistHash;

char MYHOSTNAME_ICMP[HOST_NAME_MAX];

#define IPHASH_ERROR 50
#define USEC_PER_SEC 1000000
#define SOCKET_ERROR 30
#define MAX_RANGES_PER_MESSAGE_DEFAULT 2048
#define MAX_HOLD_TIME_DEFAULT 100
#define MAX_HOLD_TIME_EXTRA 10000
#define  LOOK_BACK_TIME_ICMP_DEFAULT 10000
#define REMEDIATION_PORT_BLACKLIST_DEFAULT 4444
#define REMEDIATION_PORT_WHITELIST_DEFAULT 4446
#define BUF_SIZE 512
int MYHOSTNAMELEN_ICMP = 0;
int MAX_RANGES_PER_MESSAGE = MAX_RANGES_PER_MESSAGE_DEFAULT;
int USE_WHITELIST_ICMP = 0;
int PORTS_ATTACKED_THRESHOLD = 0;
int MAX_HOLD_TIME = MAX_HOLD_TIME_DEFAULT;
int LOOK_BACK_TIME_ICMP = LOOK_BACK_TIME_ICMP_DEFAULT;
int NEW_PORT_COUNT_THRESHOLD = -1;
int PACKETS_PER_INTERVAL_THESHOLD = -1;
uint32_t REMEDIATION_PORT_BLACKLIST = REMEDIATION_PORT_BLACKLIST_DEFAULT;
uint32_t REMEDIATION_PORT_WHITELIST = REMEDIATION_PORT_WHITELIST_DEFAULT;
char *REMEDIATION_IP = "172.20.30.11";
FILE *ssvFile;
FILE *logFile;
FILE *configFile;
int remediationSockfdBlacklist = 0;
int remediationSockfdWhitelist = 0;

pthread_t t;
pthread_mutex_t CS;

void enterCS()
{
    pthread_mutex_lock(&CS);
}

void exitCS()
{
    pthread_mutex_unlock(&CS);
}

int32_t strToI(char *s)
{
    char *e = 0;
    long int t = strtol(s, &e, 0);
    if ((t == LONG_MIN) || (t == LONG_MAX) || (e == s)) {
        t = -INT_MAX;
    }
    if (t > INT_MAX) {
        t = -INT_MAX;
    }
    return (t);
}

int32_t strToPI(char *s)
{
    char *e = 0;
    long int t = strtol(s, &e, 0);
    if ((t == LONG_MIN) || (t == LONG_MAX) || (e == s)) {
        t = -1;
    }
    if ((t < 0) || (t > INT_MAX)) {
        t = -1;
    }
    return (t);
}

pthread_t icmpDetectorThread;
pthread_t readFifoThread;

PortRange rangeBuf[MAX_PORT + 1];
int recsInRangeBuf = 0;

static void die(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    exit(1);
}

static void *xmalloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }
    void *rv = malloc(size);
    if (rv == NULL) {
        die("out-of-memory allocating %u bytes", (unsigned)size);
    }
    return rv;
}

/* Buffer definitions */

ICMPDetectorData icmpDetectorIntArray[icmpDetectorBufferSize];
int icmpDetectorFront = 0;
int icmpDetectorRear = -1;
int icmpDetectorItemCount = 0;

ICMPDetectorData icmpDetectorPeek()
{
    return icmpDetectorIntArray[icmpDetectorFront];
}

bool icmpDetectorIsEmpty()
{
    return icmpDetectorItemCount == 0;
}

bool icmpDetectorIsFull()
{
    return icmpDetectorItemCount == icmpDetectorBufferSize;
}

int icmpDetectorItemsInBuffer()
{
    return icmpDetectorItemCount;
}

void icmpDetectorInsert(ICMPDetectorData data)
{
    if (!icmpDetectorIsFull()) {

        if (icmpDetectorRear == icmpDetectorBufferSize - 1) {
            icmpDetectorRear = -1;
        }

        icmpDetectorIntArray[++icmpDetectorRear] = data;
        icmpDetectorItemCount++;
    }
}

void *readFifo()
{
    static FILE *fp = 0;
    if (fp == 0) {
        char *fifoName = get_config_string(configFile, "icmp_sensor_fifo");

        if (fifoName == 0) {
            fifoName = "/tmp/icmpSensorFifo";
        }

        if ((fp = fopen(fifoName, "r+e")) == NULL) {
            LOG("Could not open fifo %s\n", fifoName);
            perror(fifoName);
            exit(-1);
        }
    }
    char buf[BUF_SIZE];
    while (fgets(buf, BUF_SIZE, fp) != NULL) {
        char *ip_str = strtok(buf, ":");
        char *port_str = strtok(NULL, ":");
        struct in_addr addr;
        int s = inet_pton(AF_INET, ip_str, &addr);
        if (s <= 0) {
            if (s == 0) {
                LOG("Not in presentation format");
            } else {
                perror("inet_pton");
            }
            exit(EXIT_FAILURE);
        }
        int portInt = strToPI(port_str);
        if (portInt == -1) {
            LOG("bad port: %s\n", port_str);
            exit(EXIT_FAILURE);
        }
        icmpDetectorInsertValues(portInt, IPPROTO_UDP, ntohl(addr.s_addr), 1);
    }
    return (0);
}

void icmpDetectorInsertValues(uint32_t port, uint32_t protocol, uint32_t ip, uint32_t count)
{
    LOG("insert port=%u protocol=%u ip=%u count=%u\n", port, protocol, ip, count);
    ICMPDetectorData data;
    data.port = port;
    data.protocol = protocol;
    data.ip = ip;
    data.count = count;
    pthread_mutex_lock(&icmpDetectorMutex);
    icmpDetectorInsert(data);
    pthread_cond_signal(&icmpDetectorQueueCond);
    pthread_mutex_unlock(&icmpDetectorMutex);
}

ICMPDetectorData icmpDetectorRemoveData()
{
    ICMPDetectorData data = icmpDetectorIntArray[icmpDetectorFront++];

    if (icmpDetectorFront == icmpDetectorBufferSize) {
        icmpDetectorFront = 0;
    }

    icmpDetectorItemCount--;
    return data;
}

/* END of buffer definitions*/

#define MaxItemsInICMPDetector 20000    // Maximum items a producer can produce or a icmpDetectorThreadFunction can consume

static void *sendDDOSLoop(void *arg)
{
    (void)arg;

    while (1) {
        enterCS();
        IPInfo *node = NULL;
        stdit it;
        stdhash_begin(&IPHash, &it);
        while (!stdhash_is_end(&IPHash, &it)) {
            node = *((IPInfo **) stdhash_it_val(&it));
            struct timeval tv;
            gettimeofday(&tv, 0);
            long unsigned time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
            if (!node->whitelistSent) {
                if (node->changedRangesNum && ((time_now - node->lastTimeSent) > (unsigned int)MAX_HOLD_TIME)) {
                    icmpDetectorSSV
                        ("In sendDDOSLoop thread: for ip %u protocol %d hold time %ld exceeds %d threshold, sending ddos message\n",
                         node->ip, node->protocol, (time_now - node->lastTimeSent), MAX_HOLD_TIME);
                    LOG("In sendDDOSLoop thread: for ip %u protocol %d hold time %ld exceeds %d threshold, sending ddos message\n", node->ip, node->protocol, (time_now - node->lastTimeSent), MAX_HOLD_TIME);
                    sendDDOS(node);

                }
            }
            stdhash_it_next(&it);
        }
        exitCS();
        usleep(MAX_HOLD_TIME + MAX_HOLD_TIME_EXTRA);
    }
    return (0);
}

void *icmpDetectorThreadFunction(void *arg)
{
    (void)arg;

    //ENABLING THE CANCEL FUNCTIONALITY
    int prevType = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &prevType);
    while (1) {
        pthread_mutex_lock(&icmpDetectorMutex);
        while (icmpDetectorIsEmpty()) {
            // - wait for the condition variable to be signalled
            //Note: This call unlocks the icmpDetectorMutex when called and
            //relocks it before returning!
            pthread_cond_wait(&icmpDetectorQueueCond, &icmpDetectorMutex);
        }
        ICMPDetectorData item = icmpDetectorRemoveData();
        pthread_mutex_unlock(&icmpDetectorMutex);
        processAlert_icmp(item);

        LOG("Consumer : Remove Item port=%d icmpDetectorItemsInBuffer %d\n", item.port, icmpDetectorItemsInBuffer());

    }
}

void calculateRate(IPInfo * node)
{
    stdit it;
    struct timeval tv;
    gettimeofday(&tv, 0);
    long unsigned time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
    //ICMPCountNode counts;
    int newPortCount = 0;
    int packetCount = 0;

    stddll_begin(&(node->countList), &it);
    while (!stddll_is_end(&(node->countList), &it)) {
        ICMPCountNode *n = (ICMPCountNode *) stddll_it_val(&it);
        if (n->timestamp > (time_now - LOOK_BACK_TIME_ICMP)) {
            if (n->newPortFlag) {
                newPortCount++;
            }
            packetCount += n->count;
        } else {
            break;
        }
        stddll_it_next(&it);
    }

    node->newPortCount = newPortCount;
    node->packetCount = packetCount;
    stdit end_list;
    stddll_last(&(node->countList), &end_list);
    if (!stddll_is_end(&(node->countList), &it)) {
        stddll_erase_seq(&(node->countList), &it, &end_list);
    }
}

int processAlert_icmp(ICMPDetectorData item)
{

    char ipstr[INET6_ADDRSTRLEN + 1];

    enterCS();
    struct timeval tv;
    gettimeofday(&tv, 0);
    long unsigned time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
    icmpDetectorSSV("in processAlert_icmp ip %d count %d port %d\n", item.ip, item.count, item.port);
    IPInfoKey key;
    IPInfo *node = NULL;
    stdit it;
    memset(&key, 0, sizeof(IPInfoKey));
    key.ip = item.ip;
    key.protocol = item.protocol;
    stdhash_find(&IPHash, &it, &key);
    if (stdhash_is_end(&IPHash, &it))   //new IP, insert hash record
    {
        node = (IPInfo *) xmalloc(sizeof(IPInfo) );
        memset(node, 0, sizeof(IPInfo));
        node->ip = item.ip;
        node->protocol = item.protocol;
        node->portTree = 0;
        node->lastTimeSent = 0;
        node->changedRangesNum = 0;
        stddll_construct(&(node->countList), sizeof(ICMPCountNode));
        if (stdhash_put(&IPHash, &it, &key, &node) != 0) {
            LOG("could not insert into IPHash\n");
            exit(IPHASH_ERROR);
        }
    } else                      //ip exists
    {
        node = *((IPInfo **) stdhash_it_val(&it));
    }

    ICMPCountNode *countsNode = (ICMPCountNode *) xmalloc(sizeof(ICMPCountNode) );
    memset(countsNode, 0, sizeof(ICMPCountNode));
    countsNode->count = item.count;
    countsNode->port = item.port;
    countsNode->timestamp = time_now;
    countsNode->newPortFlag = 0;

    if (addToRangeTree(&(node->portTree), item.port)) {
        node->changedRangesNum++;
        countsNode->newPortFlag = 1;
    }
    stddll_push_front(&(node->countList), countsNode);

    if (node->ip) {
        long unsigned int ip = htonl(node->ip);
        inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));

        icmpDetectorSSV("%s:%u count %d\n", ipstr, item.ip, item.count);

    }

    stdhash_begin(&IPHash, &it);
    while (!stdhash_is_end(&IPHash, &it)) {
        node = *((IPInfo **) stdhash_it_val(&it));


        if (USE_WHITELIST_ICMP) {
            if (node->whitelistSent) {
                LOG("Whitelist already sent!!!\n");
            } else {
                calculateRate(node);
                if (((NEW_PORT_COUNT_THRESHOLD > 0) && (node->newPortCount >= NEW_PORT_COUNT_THRESHOLD))
                    || ((PACKETS_PER_INTERVAL_THESHOLD > 0) && (node->packetCount >= PACKETS_PER_INTERVAL_THESHOLD))) {
                    sendWhitelist_icmp(node);
                    node->whitelistSent = 1;
                } else {
                    sendDDOSIfThreshold(node);
                }
            }
        } else {
            sendDDOSIfThreshold(node);
        }
        stdhash_it_next(&it);
    }
    exitCS();
    return (0);

}

void sendDDOSIfThreshold(IPInfo * node)
{
    if (node->changedRangesNum > PORTS_ATTACKED_THRESHOLD) {
        icmpDetectorSSV("changed ranges %d exceeds %d threshold, sending ddos message\n",
                        node->changedRangesNum, PORTS_ATTACKED_THRESHOLD);
        sendDDOS(node);

    } else {
        icmpDetectorSSV("changed ranges %d is below %d threshold, NOT sending ddos message\n",
                        node->changedRangesNum, PORTS_ATTACKED_THRESHOLD);
        LOG("for ip %u protocol %d  changed ranges %d is below %d threshold, NOT sending ddos message\n",
            node->ip, node->protocol, node->changedRangesNum, PORTS_ATTACKED_THRESHOLD);

    }
}

void connectRemediationSocket(int *remediationSockfd, uint32_t remediation_port)
{
    if (*remediationSockfd != 0) {
        int error = 0;
        socklen_t len = sizeof(error);
        int retval = getsockopt(*remediationSockfd, SOL_SOCKET, SO_ERROR, &error, &len);
        int reopenSocket = 0;
        if (retval != 0) {
            /* there was a problem getting the error code */
            LOG("error getting socket error code: %s\n", strerror(retval));
            reopenSocket = 1;
        }

        if (error != 0) {
            /* socket has a non zero error status */
            LOG("socket error: %s\n", strerror(error));
            reopenSocket = 1;
        }
        if (reopenSocket) {
            LOG("problem with remediation socket, closing it\n");
            close(*remediationSockfd);
            *remediationSockfd = 0;
        } else {
            //LOG("Remediation socket already connected\n");
            return;
        }
    }
    if (*remediationSockfd == 0) {
        LOG("remediationSockfd is 0, connecting to the remediation server\n");
        struct sockaddr_in servaddr;
        char *remediation_ip = REMEDIATION_IP;

        // socket create and verification
        *remediationSockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (*remediationSockfd == -1) {
            LOG("socket creation failed...\n");
            exit(SOCKET_ERROR);
        } else {
            LOG("Socket successfully created..\n");
        }
        memset(&servaddr, 0, sizeof(servaddr));

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr(remediation_ip);
        servaddr.sin_port = htons(remediation_port);

        // connect the client socket to server socket
        if (connect(*remediationSockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))
            != 0) {
            icmpDetectorSSV("connection with the server %s:%u failed...\n", remediation_ip, remediation_port);
            exit(SOCKET_ERROR);
        } else {
            icmpDetectorSSV("connected to server %s:%u ...\n", remediation_ip, remediation_port);
        }
    }
}

void sendDDOS(IPInfo * node)
{
    static int firstTime = 1;

    if (firstTime) {
        LOG("Starting sendDDOSLoop thread\n");
        pthread_create(&t, 0, sendDDOSLoop, 0);

        firstTime = 0;
    }

    recsInRangeBuf = 0;
    getChangedRanges(node->portTree, rangeBuf, &recsInRangeBuf);

    int chunk = 0;
    long unsigned time_now = 0;
    connectRemediationSocket(&remediationSockfdBlacklist, REMEDIATION_PORT_BLACKLIST);

    for (chunk = 0; chunk * MAX_RANGES_PER_MESSAGE < recsInRangeBuf; chunk++) {
        struct timeval tv;
        gettimeofday(&tv, 0);
        time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;

        int recsInMessage = MIN_INT(MAX_RANGES_PER_MESSAGE, recsInRangeBuf - MAX_RANGES_PER_MESSAGE * chunk);
        LOG("Ranges to send %d, max per message %d, sending chunk %d with %d ranges\n", recsInRangeBuf,
            MAX_RANGES_PER_MESSAGE, chunk, recsInMessage);
        icmpDetectorSSV("Ranges to send %d, max per message %d, sending chunk %d with %d ranges\n", recsInRangeBuf,
                        MAX_RANGES_PER_MESSAGE, chunk, recsInMessage);

        char buff[BUF_SIZE];
        for (int i = 0; i < recsInMessage; i++) {
            uint32_t port_lower = rangeBuf[i + chunk * MAX_RANGES_PER_MESSAGE].rangeFrom;
            uint32_t port_upper = rangeBuf[i + chunk * MAX_RANGES_PER_MESSAGE].rangeTo;
            LOG("added range alert->target_port[%d] = [%d,%d]\n", i, port_lower, port_upper);
            icmpDetectorSSV("Port range %d:[%d,%d]\n", i, port_lower, port_upper);
            memset(buff, 0, sizeof(buff));
            sprintf(buff, "%lu,%d,%u,%u,%u,%d\n", time_now, 0, node->ip, port_lower, port_upper, node->protocol);
            write(remediationSockfdBlacklist, buff, strlen(buff));
            icmpDetectorSSV("SENT MESSAGE:%s", buff);
        }

        write(remediationSockfdBlacklist, "\n", 1);
        icmpDetectorSSV("SENT END OF LINE\n");
    }
    node->changedRangesNum = 0;
    node->lastTimeSent = time_now;

}

WhitelistDataNode *loadWhitelist(int *listSize, uint32_t ip)
{
    WhitelistDataNode *detectorWhitelist = NULL;
    char ipstr[INET6_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));

    *listSize = num_lines(configFile, ipstr);
    if (*listSize) {
        detectorWhitelist = calloc(*listSize, sizeof(WhitelistDataNode));
        static char buf[MAXCONFIGLINE];
        static char buf_orig[sizeof(buf)];
        int i = 0;
        rewind(configFile);
        while (fgets(buf, sizeof(buf), configFile)) {
            memset(buf_orig, 0, sizeof(buf_orig));
            strncpy(buf_orig, buf, sizeof(buf_orig) - 1);
            char *key_str = strtok(buf, ":");
            if (!strncmp(ipstr, key_str, MAXCONFIGLINE)) {
                int parseError = 0;
                char *whitelist_str = strtok(NULL, ":");
                char *word = strtok(whitelist_str, ",");
                if (!word) {
                    parseError = 1;
                    goto parse_error;
                }
                int port_from = strToPI(word);
                if (port_from == -1) {
                    parseError = 1;
                    goto parse_error;
                }
                word = strtok(NULL, ",");
                if (!word) {
                    parseError = 1;
                    goto parse_error;
                }
                int port_to = strToPI(word);
                if (port_to == -1) {
                    parseError = 1;
                    goto parse_error;
                }
                word = strtok(NULL, ",");
                if (!word) {
                    parseError = 1;
                    goto parse_error;
                }
                int protocol = strToPI(word);
                if (protocol == -1) {
                    parseError = 1;
                    goto parse_error;
                }
                detectorWhitelist[i].port_from = port_from;
                detectorWhitelist[i].port_to = port_to - 1;
                detectorWhitelist[i].protocol = protocol;
                detectorWhitelist[i].ip = ip;
                i++;
 parse_error:
                if (parseError) {
                    icmpDetectorSSV("Could not parse whitelist line {%s}\n", buf_orig);
                    LOG("Could not parse whitelist line {%s}\n", buf_orig);
                    (*listSize)--;
                }

            }

        }
    }
    return (detectorWhitelist);
}

void sendWhitelist_icmp(IPInfo * IPInfoNode)
{
    LOG("In sendWhitelist_icmp\n");
    WhitelistInfoKey key;
    WhitelistInfo *node = NULL;;
    stdit it;
    memset(&key, 0, sizeof(WhitelistInfoKey));
    key.ip = IPInfoNode->ip;

    stdhash_find(&WhitelistHash, &it, &key);
    if (stdhash_is_end(&WhitelistHash, &it))    //new Whitelis, insert hash record
    {
        node = (WhitelistInfo *) xmalloc(sizeof(WhitelistInfo) );
        memset(node, 0, sizeof(WhitelistInfo));
        node->ip = IPInfoNode->ip;
        LOG("Getting the whitelist for ip %u\n", node->ip);
        node->whitelist = loadWhitelist(&(node->whitelistSize), ntohl(node->ip));
        LOG("Loaded the whitelist for ip %u of size %d\n", node->ip, node->whitelistSize);
        if (node->whitelistSize == 0) {
            LOG("Whitelist is empty for ip %u", node->ip);
            node->whitelistSent = 1;
        }

        if (stdhash_put(&WhitelistHash, &it, &key, &node) != 0) {
            LOG("could not insert into WhitelistHash\n");
            exit(IPHASH_ERROR);
        }
    } else                      //ip exists
    {
        node = *((WhitelistInfo **) stdhash_it_val(&it));
    }
    if (node->whitelistSent) {
        LOG("Whitelist already sent.\n");
        return;
    }
    connectRemediationSocket(&remediationSockfdWhitelist, REMEDIATION_PORT_WHITELIST);
    struct timeval tv;
    gettimeofday(&tv, 0);
    long unsigned time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
    char buff[BUF_SIZE];
    for (int i = 0; i < node->whitelistSize; i++) {
        memset(buff, 0, sizeof(buff));
        sprintf(buff, "%lu,%d,%u,%u,%u,%d\n",
                time_now,
                1,
                htonl(node->whitelist[i].ip),
                node->whitelist[i].port_from, node->whitelist[i].port_to, node->whitelist[i].protocol);
        write(remediationSockfdWhitelist, buff, strlen(buff));
        icmpDetectorSSV("WHITELIST MESSAGE SENT:%s\n", buff);
        LOG("WHITELIST MESSAGE SENT:%s\n", buff);
    }
    write(remediationSockfdWhitelist, "\n", 1);
    icmpDetectorSSV("WHITELIST SENT END OF LINE\n");
    LOG("WHITELIST SENT END OF LINE\n");

}

void initialize_icmp_detector()
{
    static int firstTime = 1;
    pthread_mutex_lock(&icmp_init_mutex);
    if (!firstTime) {
        return;
    }
    firstTime = 0;
    pthread_mutex_unlock(&icmp_init_mutex);
    configFile = fopen(CONFIGFILE, "r+e");
    if (configFile == 0) {
        fprintf(stderr, "%s() cannot open %s", __func__, CONFIGFILE);
        exit(-1);
    }
    setupLogs_icmp();
    LOG("Initializing detector thread\n");
    //Initialize the icmpDetectorMutex and the condition variable
    pthread_mutex_init(&icmpDetectorMutex, NULL);
    pthread_cond_init(&icmpDetectorQueueCond, NULL);

    gethostname(MYHOSTNAME_ICMP, HOST_NAME_MAX - 1);
    MYHOSTNAME_ICMP[HOST_NAME_MAX - 1] = 0;
    MYHOSTNAMELEN_ICMP = strnlen(MYHOSTNAME_ICMP, HOST_NAME_MAX);

    /* get config from the config server */
    char *temp = get_config_string(configFile, "ports_attacked_threshold");
    if (temp == 0) {
        LOG("no ports_attacked_threshold in ddms.ini\n");
        PORTS_ATTACKED_THRESHOLD = 0;
    } else {
        LOG("from get_config_string PORTS_ATTACKED_THRESHOLD=%s\n", temp);
        if ((PORTS_ATTACKED_THRESHOLD = strToPI(temp)) == -1) {
            LOG("BAD PORTS_ATTACKED_THRESHOLD\n");
        }
    }
    if ((temp = get_config_string(configFile, "max_hold_time")) == 0) {
        LOG("no max_hold_time in ddms.ini\n");
        MAX_HOLD_TIME = MAX_HOLD_TIME_DEFAULT;
    } else {
        LOG("from get_config_string MAX_HOLD_TIME=%s\n", temp);
        if ((MAX_HOLD_TIME = strToPI(temp)) == -1) {
            LOG("BAD MAX_HOLD_TIME\n");
        }
    }
    if ((temp = get_config_string(configFile, "max_ranges_per_message")) == 0) {
        LOG("no MAX_RANGES_PER_MESSAGE in ddms.ini\n");
        MAX_RANGES_PER_MESSAGE = MAX_RANGES_PER_MESSAGE_DEFAULT;
    } else {
        LOG("from get_config_string MAX_RANGES_PER_MESSAGE=%s\n", temp);
        if ((MAX_RANGES_PER_MESSAGE = strToPI(temp)) == -1) {
            LOG("BAD MAX_RANGES_PER_MESSAGE\n");
        }
    }
    if ((temp = get_config_string(configFile, "use_whitelist")) == 0) {
        LOG("use_whitelist is not defined, setting USE_WHITELIST_ICMP to true\n");
        USE_WHITELIST_ICMP = 1;
    } else {
        if ((USE_WHITELIST_ICMP = strToPI(temp)) == -1) {
           LOG("BAD USE_WHITELIST_ICMP\n");
        } else {
           LOG("USE_WHITELIST_ICMP is set to %d\n", USE_WHITELIST_ICMP);
        }

    }
    if ((temp = get_config_string(configFile, "look_back_time")) == 0) {
        LOG("no look_back_time ddms.ini\n");
        LOOK_BACK_TIME_ICMP = LOOK_BACK_TIME_ICMP_DEFAULT;
    } else {
        LOG("from get_config_string LOOK_BACK_TIME_ICMP=%s\n", temp);
        if ((LOOK_BACK_TIME_ICMP = strToPI(temp)) == -1) {
            LOG("BAD LOOK_BACK_TIME_ICMP\n");
        }

    }
    LOG("LOOK_BACK_TIME_ICMP set to %d\n", LOOK_BACK_TIME_ICMP);
    if ((temp = get_config_string(configFile, "new_port_count_threshold")) == 0) {
        LOG("no new_port_count_threshold ddms.ini\n");
        NEW_PORT_COUNT_THRESHOLD = -1;
    } else {
        LOG("from get_config_string NEW_PORT_COUNT_THRESHOLD=%s\n", temp);
        NEW_PORT_COUNT_THRESHOLD = strToI(temp);
        if (NEW_PORT_COUNT_THRESHOLD == -INT_MAX) {
            LOG("BAD NEW_PORT_COUNT_THRESHOLD\n");
        }
    }
    LOG("NEW_PORT_COUNT_THRESHOLD set to %d\n", NEW_PORT_COUNT_THRESHOLD);
    if ((temp = get_config_string(configFile, "packets_per_interval_threshold")) == 0) {
        LOG("no packets_per_interval_threshold ddms.ini\n");
        PACKETS_PER_INTERVAL_THESHOLD = -1;
    } else {
        LOG("from get_config_string PACKETS_PER_INTERVAL_THESHOLD=%s\n", temp);
        if ((PACKETS_PER_INTERVAL_THESHOLD = strToPI(temp)) == -1) {
            LOG("BAD PACKETS_PER_INTERVAL_THRESHOLD\n");
        }
    }
    LOG("PACKETS_PER_INTERVAL_THESHOLD set to %d\n", PACKETS_PER_INTERVAL_THESHOLD);
    if ((temp = get_config_string(configFile, "remediation_ip")) == 0) {
        LOG("no remediation_ip ddms.ini\n");
    } else {
        LOG("from get_config_string REMEDIATION_IP=%s\n", temp);
        REMEDIATION_IP = temp;
    }
    LOG("REMEDIATION_IP set to %d\n", REMEDIATION_IP);
    if ((temp = get_config_string(configFile, "remediation_port_blacklist")) == 0) {
        LOG("no remediation_port_blacklist ddms.ini\n");

    } else {
        LOG("from get_config_string REMEDIATION_PORT_BLACKLIST=%s\n", temp);
        if ((REMEDIATION_PORT_BLACKLIST = strToPI(temp)) == -1) {
            LOG("BAD REMEDIATION_PORT_BLACKLIST\n");
        }
    }
    LOG("REMEDIATION_PORT_BLACKLIST set to %d\n", REMEDIATION_PORT_BLACKLIST);
    if ((temp = get_config_string(configFile, "remediation_port_whitelist")) == 0) {
        LOG("no remediation_port_whitelist ddms.ini\n");

    } else {
        LOG("from get_config_string REMEDIATION_PORT_WHITELIST=%s\n", temp);
        if ((REMEDIATION_PORT_WHITELIST = strToPI(temp)) == -1) {
            LOG("BAD REMEDIATION_PORT_WHITELIST\n");
        }
    }
    LOG("REMEDIATION_PORT_WHITELIST set to %d\n", REMEDIATION_PORT_WHITELIST);
    //

    stdhash_construct(&IPHash, sizeof(IPInfoKey), sizeof(IPInfo *), NULL, NULL, 0);
    stdhash_construct(&WhitelistHash, sizeof(WhitelistInfoKey), sizeof(WhitelistInfo *), NULL, NULL, 0);

    pthread_create(&icmpDetectorThread, NULL, (void *)icmpDetectorThreadFunction, NULL);
}

void destroy_icmp_detector()
{
    pthread_cancel(icmpDetectorThread);
    pthread_join(icmpDetectorThread, NULL);
    pthread_cancel(readFifoThread);
    pthread_join(readFifoThread, NULL);
    pthread_mutex_destroy(&icmpDetectorMutex);
}

void icmpDetectorLog(const char *func, const unsigned int line, const char *format, ...)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    long unsigned time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
    fprintf(logFile, "%lu|%s|%u|", time_now, func, line);
    va_list argptr;
    va_start(argptr, format);
    vfprintf(logFile, format, argptr);
    va_end(argptr);
}

void icmpDetectorSSV(const char *format, ...)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    long unsigned time_now = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
    fprintf(ssvFile, "%lu ", time_now);
    va_list argptr;
    va_start(argptr, format);
    vfprintf(ssvFile, format, argptr);
    va_end(argptr);
}

void setupLogs_icmp()
{

    /* get config from the config file */
    /* it is assumed to be opened */
    char *ssvFileName = get_config_string(configFile, "icmp_detector_ssv_file");
    if (ssvFileName == 0) {
        ssvFileName = "/tmp/icmp_detector.ssv";
    }

    if ((ssvFile = fopen(ssvFileName, "a+e")) == 0) {
        fprintf(stderr, "%s.%d fopen %s %s\n", __func__, __LINE__, ssvFileName, strerror(errno));
        exit(-1);
    }
    setlinebuf(ssvFile);

    char *logFileName = get_config_string(configFile, "icmp_detector_log_file");
    if (logFileName == 0) {
        logFileName = "/tmp/icmp_detector.log";
    }

    if ((logFile = fopen(logFileName, "a+e")) == 0) {
        fprintf(stderr, "%s.%d fopen %s %s\n", __func__, __LINE__, logFileName, strerror(errno));
        exit(-1);
    }
    setlinebuf(logFile);

}

int main()
{
    initialize_icmp_detector();
    readFifo();
}
