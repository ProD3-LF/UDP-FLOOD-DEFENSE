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
-I../3rdParty/stdutil/src \
-I.. \
-L../3rdParty/stdutil/lib

CC = gcc

LIBS=-lm \
-lstdutil \
-lpthread

.phony: all

all: icmp_detector

SOURCES= icmp_detector.c

../3rdParty/stdutil/lib/libstdutil.so:
	cd ../3rdParty/stdutil;make all

icmp_detector: icmp_detector.o  rangeTree.o ../common/config.o ../3rdParty/stdutil/lib/libstdutil.so
	$(CC) $(CFLAGS) $(INCLUDES) -static icmp_detector.o -o icmp_detector ../common/config.o rangeTree.o $(LIBS)

rangeTree.o: rangeTree.h
	 $(CC) $(CFLAGS) -c rangeTree.c

../common/config.o: ../common/config.c ../common/config.h
	cd ../common && $(CC) $(CFLAGS) -c ../common/config.c

icmp_detector.o: icmp_detector.c rangeTree.h ../common/config.h 
	$(CC) $(CFLAGS) $(INCLUDES) -c icmp_detector.c 

clean:
	rm -f icmp_detector *.o ../common/config.o

define runclang
        clang-tidy -checks=*,-llvm-header-guard,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling -header-filter=.*\.h $(1) -- $(INCLUDES) > $1.tidy;
endef

check:
	$(foreach s,$(SOURCES),$(call runclang,$(s)))

all: icmp_detector
