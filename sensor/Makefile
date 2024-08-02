#/* SPDX-License-Identifier: Apache-2.0 */
#/* Copyright (c) 2012-2024 Applied Communication Sciences
# * (now Peraton Labs Inc.)
# *
# * This software was developed in work supported by the following U.S.
# * Government contracts:
# *
# * HR0011-20-C-0160 HR0011-16-C-0061
# * 
# *
# * Any opinions, findings and conclusions or recommendations expressed in
# * this material are those of the author(s) and do not necessarily reflect
# * the views, either expressed or implied, of the U.S. Government.
# *
# * DoD Distribution Statement A
# * Approved for Public Release, Distribution Unlimited
# *
# * DISTAR 40011, cleared July 24, 2024
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# * http://www.apache.org/licenses/LICENSE-2.0
# */
CFLAGS=\
-Wno-address-of-packed-member \
-g \
-fPIC \
-Werror \
-Wall \
-march=corei7 \
-mtune=corei7-avx  \
-DCLIB_DEBUG \
-fstack-protector \
-DFORTIFY_SOURCE=2 \
-fno-common
INCLUDES = \
-I. \
-I..

CC = gcc

tcpdumpSensor: tcpdumpSensor.o  ../common/config.o  ../common/logMessage.o ../common/util.o
	$(CC) $(CFLAGS) -static tcpdumpSensor.o -o tcpdumpSensor ../common/config.o ../common/logMessage.o ../common/util.o

../common/logMessage.o: ../common/logMessage.c
	cd ../common && $(CC) $(CFLAGS) -c ../common/logMessage.c

../common/util.o: ../common/util.c ../common/config.h
	cd ../common && $(CC) $(CFLAGS) -c ../common/util.c

../common/config.o: ../common/config.c ../common/config.h
	cd ../common && $(CC) $(CFLAGS) -c ../common/config.c

tcpdumpSensor.o: tcpdumpSensor.c ../common/logMessage.h ../common/util.h 
	$(CC) $(CFLAGS) -c tcpdumpSensor.c

clean:
	rm -f tcpdumpSensor *.o ../common/*.o

define runclang
        clang-tidy -checks=*,-hicpp-signed-bitwise,-llvm-header-guard,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling -header-filter=.*\.h $(1) > $1.tidy;
endef
check: tcpdumpSensor.c
	$(call runclang,tcpdumpSensor.c)
all: tcpdumpSensor
