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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include "rangeTree.h"

int traverseRangeTree(RangeTree * tree, int verbose)
{
	if (!tree) return 0;
	int leftCount = traverseRangeTree(tree->left,verbose);
	if (verbose)
	{
		if (tree->rangeFrom == tree->rangeTo )
			printf("%d,",tree->rangeFrom);
		else
			printf("[%d %d],",tree->rangeFrom,tree->rangeTo);
	}
	int rightCount = traverseRangeTree(tree->right,verbose);
	
	return(leftCount+1+rightCount);
}
int getChangedRanges(RangeTree * tree, PortRange* buf, int* size)
{
	if (!tree) return 0;
	int leftCount = getChangedRanges(tree->left, buf,  size);
	if (!tree->sent)
	{
		buf[*size].rangeFrom = tree->rangeFrom;
		buf[*size].rangeTo = tree->rangeTo;
		tree->sent = 1;
		(*size)++;
	}
	int rightCount = getChangedRanges(tree->right, buf,  size);
		
	return(leftCount+1+rightCount);
}

int addToRangeTree(RangeTree ** tree, int n)
{
	
	if (!tree || !(*tree))
	{
		if (!(*tree = (RangeTree *) malloc(1 * sizeof(RangeTree))))
		{
			fprintf(stderr,"Could not allocate %ld bytes\n",sizeof(RangeTree));
			exit(20);
		}
		(*tree)->rangeTo = n;
		(*tree)->rangeFrom = n;
		(*tree)->left = 0;
		(*tree)->right = 0;
		(*tree)->sent = 0;
		return(1);
	}
	else
	{
		if (n < ((*tree)->rangeFrom - 1) )                // less than range
			return (addToRangeTree(&((*tree)->left),n));      
		if (n > ((*tree)->rangeTo + 1))					  // more than range
			return (addToRangeTree(&((*tree)->right),n));
		if ((n >= (*tree)->rangeFrom) && (n <= (*tree)->rangeTo)) // in range
			return(0);
		if (n == ((*tree)->rangeFrom - 1))                //extends range to the left
		{
			(*tree)->rangeFrom = n;
			(*tree)->sent = 0;
			
			if ((*tree)->left)
			{
				//now see if it touches other ranges
				RangeTree *parent=*tree;
				RangeTree *highestRangeToLeft = 0;
				
				highestRangeToLeft = getHighestRange((*tree)->left,&( parent));
				
				
				if (rangesTouch(*tree, highestRangeToLeft))
				{
					mergeRanges(*tree,highestRangeToLeft);
					deleteNode(parent,highestRangeToLeft);
				}
			}
			return(2);
		}
		if (n == ((*tree)->rangeTo + 1))                //extends range to the right
		{
			
			(*tree)->rangeTo = n;
			(*tree)->sent = 0;
			if ((*tree)->right)
			{
				//now see if it touches other ranges
				RangeTree *parent=*tree;
				RangeTree *lowestRangeToRight = 0;
				lowestRangeToRight = getLowestRange((*tree)->right,&( parent));
			
				if (rangesTouch(*tree, lowestRangeToRight))
				{
					mergeRanges(*tree,lowestRangeToRight);
					deleteNode(parent,lowestRangeToRight);
				}
			}
			return(2);
		}
	}
	return(0);
}
RangeTree * getHighestRange(RangeTree *tree, RangeTree **parent)
{
	RangeTree *rc=0;
	
	if (!tree)
	{ 
		rc=0;
	}
	
	if (tree->right == 0)
		rc=tree;
	else
	{
		*parent = tree;
		rc = getHighestRange(tree->right,parent);
	}
	
	return(rc);	
}
RangeTree * getLowestRange(RangeTree *tree, RangeTree **parent)
{
	RangeTree *rc=0;
	
	if (!tree)
	{ 
		
		rc=0;
	}
	
	if (tree->left == 0)
		rc=tree;
	else
	{
		*parent = tree;
		rc = getLowestRange(tree->left,parent);
	}
	
	return(rc);	
}

int rangesTouch(RangeTree* r1, RangeTree* r2)
{
	int rc=0;
	if (!r1 || !r2)
		rc = 0;
	else if (((r1->rangeFrom >= r2->rangeFrom) && ( r1->rangeFrom <= r2->rangeTo+1)) 
		|| ((r1->rangeTo >= r2->rangeFrom-1) && ( r1->rangeTo <= r2->rangeTo) ))
		rc=1;
	else
		rc=0;
	return(rc);
}

int mergeRanges(RangeTree* target_node, RangeTree* second_node)
{
	
	if (!target_node || !second_node)
	{
		fprintf(stderr, "Passed nulls to mergeRanges  mergeRanges\n");
		exit(30);
	}
	if (!rangesTouch(target_node,second_node))
	{
		fprintf(stderr, "WARNING: called mergeRanges with non-overlaping ranges: [%d,%d] [%d,%d]\n",
					target_node->rangeFrom,
					target_node->rangeTo,
					second_node->rangeFrom,
					second_node->rangeTo);
		return(0);
	}
	else
	{
		target_node->rangeFrom = MIN_INT(target_node->rangeFrom, second_node->rangeFrom);
		target_node->rangeTo = MAX_INT(target_node->rangeTo, second_node->rangeTo);
		return(1);
	}
}

void deleteNode(RangeTree* parent,RangeTree* nodeToDelete)
{
	
	if (parent->left == nodeToDelete)
	{
		
		parent->left = 0 ;
		if (nodeToDelete->left)
		{
			
			parent->left = nodeToDelete->left;
		}
		if (nodeToDelete->right)
		{
			parent->left = nodeToDelete->right;
		}
		free(nodeToDelete);
		
	}
	else if (parent->right == nodeToDelete)
	{
		parent->right = 0;
		if (nodeToDelete->left)
		{
			parent->right = nodeToDelete->left;
		}
		if (nodeToDelete->right)
		{
			parent->right = nodeToDelete->right;
		}
		free(nodeToDelete);
		
	}
	else //should never happen
	{
		fprintf(stderr, "Called deleteNode, but nodeToDelete is not one of the branches");
		exit(40);
	}
}
void freeTree(RangeTree* t)
{
	if (!t)
		return;
	else
	{
		freeTree(t->left);
		freeTree(t->right);
		free(t);
	}
}
