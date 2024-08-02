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
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "logMessage.h"
long long unsigned int msecTime(){
        struct timespec t;
        clock_gettime(CLOCK_REALTIME,&t);
        return(t.tv_sec*1000+t.tv_nsec/1000000);
}
int mkdirEach(char *path){
	size_t n=strlen(path);
	char part[PATH_MAX];
	size_t k=0;
	for(size_t i=0;i<n;++i){
		if ((part[k++]=path[i])=='/'){
			part[k]='\0';
			if (mkdir(part,0777)!=0){
				if (errno != EEXIST){
		       			return(-1);
				}
			}
		}
	}
	part[k]='\0';
	if (mkdir(part,0777)!=0){
		if (errno != EEXIST){
		       	return(-1);
		}
	}
	return(0);
}
