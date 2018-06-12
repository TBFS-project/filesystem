#ifndef tbfs_OPERATIONS_H
#define tbfs_OPERATIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <fuse.h>

#include "bitmap.h"
#include "tree.h"
#include "disk.h"

int tbfs_getattr(const char *path, struct stat *s);

int tbfs_mknod(const char *path, mode_t m, dev_t d);

int tbfs_mkdir(const char *path, mode_t m);

int tbfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);

int tbfs_rmdir(const char *path);

int tbfs_rename(const char *from, const char *to);

int tbfs_open(const char *path, struct fuse_file_info *fi);

int tbfs_read(const char *path, char *buf, size_t size, off_t offset,struct fuse_file_info *fi);

int tbfs_write(const char *path, const char *buf, size_t size, off_t offset,struct fuse_file_info *fi);

int tbfs_utimens(const char *path, struct utimbuf *tv);

int tbfs_truncate(const char* path, off_t size);

int tbfs_unlink(const char *path);

int tbfs_chmod(const char *path, mode_t setPerm);

int tbfs_chown(const char *path, uid_t u, gid_t g);

int tbfs_flush(const  char *path, struct fuse_file_info *fi);

#endif
