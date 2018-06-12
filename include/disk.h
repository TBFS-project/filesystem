#ifndef DISK_H
#define DISK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <fuse.h>
#include "tree.h"

typedef struct fs_tree_node fs_tree_node;

extern int diskfd;

#define BLOCK_SIZE 4096                         // block size 4 KB
#define MAX_FILE_SIZE 18446744073709551616    // bytes, largest possible value in unsigned 64 bit int; 13.6 EB (Exabytes)
#define MAX_BLOCK_NO 4503599627370496           //MAX_FILE_SIZE / (4*1024)

void *allocate(fs_tree_node *node, uint64_t n);

void *reallocate(fs_tree_node *node, uint64_t n);

void *setBlocks(void *ptr, uint64_t n, int val);

void deallocate(fs_tree_node *node);

uint64_t constructBlock(fs_tree_node *node, void **ret);

fs_tree_node *reconstructNode(void *blockdata);

int openDisk(char *filename, int nbytes);

int readBlock(uint64_t blocknr, void *block);

int writeBlock(uint64_t blocknr, void *block);

uint64_t diskWriter(void *blocks_data, uint64_t blocks, uint64_t first);

fs_tree_node *diskReader(uint64_t block);

uint64_t dataDiskReader(fs_tree_node *node);

#endif