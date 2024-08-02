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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../common/config.h"
#include "../common/logMessage.h"
#include "../common/util.h"


#define BUFSIZE 512
#define MSEC_PER_SEC 1000
#define SHUTDOWN_DELAY 5
static long long unsigned int sensorStartTime=0;
static long long unsigned int firstObsTime=0;

size_t icmpSensorObsCnt=0;
double icmpSensorFifoFailRate=0;
size_t obsSent=0;
int icmpSensorFifoFd=0;
int32_t strToPI(char *s){
	char *e=0;
	long int t=strtol(s,&e,0);
	if ((t==LONG_MIN) || (t==LONG_MAX) || (e==s)){
		t=-1;
	}
	if ((t < 0) || (t > INT_MAX)){
		t=-1;
	}
	return(t);
}
void icmpSensorSensor(char *ip, uint32_t serverPort){
	static size_t noWriteError=0;
	static size_t againError=0;
	char buf[BUFSIZE];
	if (icmpSensorFifoFd == 0){
		icmpSensorFifoFailRate=0;
		/* get config from the config server */
        	FILE *configFile=fopen(CONFIGFILE,"r+e");
        	if (configFile==0) {
            		logMessage(stderr,__FUNCTION__,__LINE__,"cannot open config file %s\n",CONFIGFILE);
            		exit(-1);
        	}
		char *fifoName=get_config_string(configFile,"icmp_sensor_fifo");
		if (fifoName==0) {
			fifoName="/tmp/icmpSensorFifo";
        	}
		while ((icmpSensorFifoFd=open(fifoName, O_WRONLY|O_NONBLOCK|O_CLOEXEC))==-1){
			logMessage(stderr,__FUNCTION__,__LINE__,
				"open %s failed %s",
				fifoName,strerror(errno));
			icmpSensorFifoFd=0;
			return;
		}
	}
	sprintf(buf,"%s:%d\n",ip,serverPort);
	size_t toWrite=strlen(buf);
	size_t haveWritten=0;
	while (toWrite > 0){
		int n=write(icmpSensorFifoFd,buf,toWrite);
		if (n==-1){
		//if ((n=fprintf(icmpSensorFifoFd,"%d\n",item))==-1){	
			if (errno == EAGAIN){ ++againError;}
			else {
				logMessage(stderr,__FUNCTION__,__LINE__,
				"TFB write %s %ld %ld",
				strerror(errno),toWrite,haveWritten);
			}
			continue;
		}
		noWriteError++;
		toWrite -= n;
		haveWritten += n;
	}
	icmpSensorFifoFailRate=(double)againError/(double)noWriteError;
	if (icmpSensorFifoFailRate>1){logMessage(stderr,__FUNCTION__,__LINE__,
			"TFB icmpSensorFifoFailRate=%g",
			icmpSensorFifoFailRate);}
}

long long unsigned int relativeObsTime,relativeRealTime;
void adjustSpeed(long long unsigned int obsTime){
	if (firstObsTime==0){firstObsTime=obsTime;}
	long long unsigned int now=msecTime();
	if (sensorStartTime==0){sensorStartTime=now;}
	relativeObsTime=(obsTime-firstObsTime);
	relativeRealTime=now-sensorStartTime;
	if (relativeObsTime==relativeRealTime){
		return;
	}
	if (relativeObsTime>relativeRealTime) {
		logMessage(stderr,__FUNCTION__,__LINE__,"playback is fast %llu\n",(relativeObsTime-relativeRealTime)*MSEC_PER_SEC);
		usleep(((relativeObsTime-relativeRealTime)*MSEC_PER_SEC));
		return;
	}
}
//ARGS:
//	--pcapFile: if present playback from pcap file.

int main(int argc, char *argv[]){
	char *pcapFile=0;
	char b[BUFSIZE];
	time_t lastScreenUpdate=0;
	static long long unsigned int obsCnt=0;
	for(size_t i=1;i<argc;++i){
		if (strcmp("--pcapFile",argv[i])==0){
			pcapFile=argv[++i];
			continue;
		}
	}
	logMessage(stderr,__FUNCTION__,__LINE__,"pcapFile %s\n", pcapFile);
	
	//icmpSensorConfig();
	if (pcapFile == 0) {
		snprintf(b,BUFSIZE,"./tcpdumpCommand");
	} else {
		snprintf(b,BUFSIZE,"./tcpdumpCommand -r %s 2>/tmp/tcpdump.err",pcapFile);
	}
	logMessage(stderr,__FUNCTION__,__LINE__,"%s",b);
	FILE *t=popen(b,"r");
	if (t==0){
		logMessage(stderr,__FUNCTION__,__LINE__,"popen(%s): %s",b,strerror(errno));
		exit(-1);
	}
	fprintf(stdout,"\e[4m\e[1m                 SENSOR               \e[m\n");
	fprintf(stdout,"\033[H\033[J");
	fprintf(stdout,"\e[4m\e[1m                 SENSOR               \e[m\n");
	fprintf(stdout,"%10s %8s %7s %10s\n",
			"Time","RealTime","ObsTime","OBS");
	while (fgets(b,BUFSIZE,t)){
		uint32_t attackedPort=0;
		long double obsTime=0;
		logMessage(stderr,__FUNCTION__,__LINE__,"%s",b);
		char ip1S[BUFSIZE];
		if (sscanf(b,"%Lf IP %s",&obsTime,ip1S)!=2){
		 	logMessage(stderr,__FUNCTION__,__LINE__,"Cannot parse: %s %lf",b,obsTime);
		 	continue;
		}
		char *portMarker = "udp port ";
		char *portLoc = strstr(b, portMarker);
		if ((portLoc) && (sscanf(portLoc+strlen(portMarker),"%u",&attackedPort)!=1)){
		 		logMessage(stderr,__FUNCTION__,__LINE__,"Cannot parse: %s %Lf {%d}",b,obsTime,attackedPort);
		 		continue;
		}
		logMessage(stderr,__FUNCTION__,__LINE__,"Parsed: %s Time:%Lf Port:{%d} IP:{%s}",b,obsTime,attackedPort,ip1S);

		++obsCnt;
		adjustSpeed((long long unsigned int)(obsTime*MSEC_PER_SEC));
		
		icmpSensorSensor(ip1S,attackedPort);
		if (time(0)-lastScreenUpdate>=1){
	                fprintf(stdout, "%10llu %8llu %7llu %10llu\r",
                        msecTime()/MSEC_PER_SEC,relativeRealTime/MSEC_PER_SEC,
			relativeObsTime/MSEC_PER_SEC,obsCnt);
                	lastScreenUpdate=time(0);
                	fflush(stdout);
		}
	}
	pclose(t);
	
	
	sleep(SHUTDOWN_DELAY);
	close(icmpSensorFifoFd);
	
	sleep(SHUTDOWN_DELAY);
	logMessage(stderr,__FUNCTION__,__LINE__,"fifos closed");
	
}
