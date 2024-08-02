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
#ifndef __RANGETREE_H__
#define __RANGETREE_H__

# ifdef __cplusplus
extern "C" {
# endif

#define MIN_INT(a,b) (((a)<(b))?(a):(b))
#define MAX_INT(a,b) (((a)>(b))?(a):(b))

#define MAX_PORT 65535
//typedef RangeTree;
struct RangeTree {
	int rangeFrom;
	int rangeTo;
	int sent;
	struct RangeTree *left;
	struct RangeTree *right;
};
typedef struct RangeTree RangeTree;
struct PortRange {
	int rangeFrom;
	int rangeTo;
	
};
typedef struct PortRange PortRange;

int traverseRangeTree(RangeTree * tree, int verbose);
int addToRangeTree(RangeTree ** tree, int n);
RangeTree * getHighestRange(RangeTree *tree, RangeTree **parent);
RangeTree * getLowestRange(RangeTree *tree, RangeTree **parent);
int mergeRanges(RangeTree* target_node, RangeTree* second_node);
int rangesTouch(RangeTree* r1, RangeTree* r2);
void deleteNode(RangeTree* parent,RangeTree* nodeToDelete);
void freeTree(RangeTree* t);
int getChangedRanges(RangeTree * tree, PortRange* buf, int* size);


# ifdef __cplusplus
}
# endif

#endif
