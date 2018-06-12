#ifndef tbfs_TREE_H
#define tbfs_TREE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "disk.h"
#include "bitmap.h"

#define DEF_DIR_PERM (0775)
#define DEF_FILE_PERM (0664)

#define NODE_SIZE (346)

#define SUPERBLOCKS 1


typedef struct fs_tree_node {
    uint8_t type;
    char name[256];
    char *fullname;
    
    uint32_t uid, gid;
    uint32_t perms;
    uint8_t nlinks;
    
    struct fs_tree_node *parent;
    struct fs_tree_node **children;
    uint32_t len;
    uint64_t *ch_inodes;

    uint8_t *data;
    uint64_t data_size;
    uint64_t block_count;
    uint64_t inode_no;

    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
}fs_tree_node;

extern int diskfd;

int destroy_node(fs_tree_node *node);

void output_node(fs_tree_node node);

int init_fs();

int dfs_dispatch(fs_tree_node *curr, int (*foo)(fs_tree_node *));

int bfs_dispatch(fs_tree_node *curr, int (*foo)(fs_tree_node *));

fs_tree_node *node_exists(const char *path);

fs_tree_node *add_fs_tree_node(const char *path, uint8_t type);

int remove_fs_tree_node(const char *path);

int copy_nodes(fs_tree_node *from, fs_tree_node *to);

int load_fs(int diskfd);

void fill_fs_tree(fs_tree_node *root);


#endif