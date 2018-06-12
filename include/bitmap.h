#ifndef BITMAP_H
#define BITMAP_H

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include "disk.h"

#define MAP_BLOCK (8)

extern int diskfd;

uint64_t bmap_size;
uint8_t *bitmap;

int loadBitMap(int fd);

void saveBitMap();

uint64_t first_free_block();

int setBitofMap(uint64_t bitno);

int clearBitofMap(uint64_t bitno);

void print_bitmap();

#endif