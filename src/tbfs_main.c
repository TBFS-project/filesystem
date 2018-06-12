#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <fuse.h>
#include "tbfs_operations.h"
#include "tree.h"
#include "log.h"

#define openDisk(x) openDisk(x, 0)

char *path_to_mount;
int diskfd;

static struct fuse_operations tbfs_operations = {
    .getattr    = tbfs_getattr,
    .mknod    = tbfs_mknod,
    .mkdir      = tbfs_mkdir,
    .unlink     = tbfs_unlink,
	.rmdir	    = tbfs_rmdir,
	.rename	    = tbfs_rename,
	.chmod	    = tbfs_chmod,
	.chown	    = tbfs_chown,
	.truncate   = tbfs_truncate,
	.open	    = tbfs_open,
	.read	    = tbfs_read,
	.write	    = tbfs_write,
	.flush	    = tbfs_flush,
	.readdir	= tbfs_readdir,
	.utime	= tbfs_utimens,
};

int main(int argc, char **argv) {
	log_open();
    diskfd = openDisk(argv[argc-1]);
	load_fs(diskfd);
    return fuse_main(argc-1, argv, &tbfs_operations);
}
