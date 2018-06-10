/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using high-level API
 *
 * Compile with:
 *
 *     gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello
 *
 * ## Source code ##
 * \include hello.c
 */


 #define FUSE_USE_VERSION 31
 #define log_struct(st, field, format, typecast) \
   log_msg("    " #field " = " #format "\n", typecast st->field)

 #include <fuse.h>
 #include <stdio.h>
 #include <string.h>
 #include <errno.h>
 #include <fcntl.h>
 #include <stddef.h>
 #include <assert.h>
 #include <stdarg.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <dirent.h>

 #include <sys/types.h>
 #include <sys/stat.h>
 /*
  * Command line options
  *
  * We can't set default values for the char* fields here because
  * fuse_opt_parse would attempt to free() them when the user specifies
  * different values on the command line.
  */

  struct tb_state {
      FILE *logfile;
      char *rootdir;
  };
	#define TB_DATA ((struct tb_state *) fuse_get_context()->private_data)

  FILE *log_open()
  {
      FILE *logfile;

      // very first thing, open up the logfile and mark that we got in
      // here.  If we can't open the logfile, we're dead.
      logfile = fopen("hi.log", "w");
      if (logfile == NULL) {
  	perror("logfile");
  	exit(EXIT_FAILURE);
      }

      // set logfile to line buffering
      setvbuf(logfile, NULL, _IOLBF, 0);

      return logfile;
  }

  void log_msg(const char *format, ...)
  {
      va_list ap;
      va_start(ap, format);

      vfprintf(TB_DATA->logfile, format, ap);
  }

  // Report errors to logfile and give -errno to caller
  int log_error(char *func)
  {
      int ret = -errno;

      log_msg("    ERROR %s: %s\n", func, strerror(errno));

      return ret;
  }

  // fuse context
  void log_fuse_context(struct fuse_context *context)
  {
      log_msg("    context:\n");

      /** Pointer to the fuse object */
      //	struct fuse *fuse;
      log_struct(context, fuse, %08x, );

      /** User ID of the calling process */
      //	uid_t uid;
      log_struct(context, uid, %d, );

      /** Group ID of the calling process */
      //	gid_t gid;
      log_struct(context, gid, %d, );

      /** Thread ID of the calling process */
      //	pid_t pid;
      log_struct(context, pid, %d, );

      /** Private filesystem data */
      //	void *private_data;
      log_struct(context, private_data, %08x, );
      log_struct(((struct tb_state *)context->private_data), logfile, %08x, );
      log_struct(((struct tb_state *)context->private_data), rootdir, %s, );

      /** Umask of the calling process (introduced in version 2.8) */
      //	mode_t umask;
      log_struct(context, umask, %05o, );
  }

  // struct fuse_conn_info contains information about the socket
  // connection being used.  I don't actually use any of this
  // information in bbfs
  void log_conn(struct fuse_conn_info *conn)
  {
      log_msg("    conn:\n");

      /** Major version of the protocol (read-only) */
      // unsigned proto_major;
      log_struct(conn, proto_major, %d, );

      /** Minor version of the protocol (read-only) */
      // unsigned proto_minor;
      log_struct(conn, proto_minor, %d, );

      /** Maximum size of the write buffer */
      // unsigned max_write;
      log_struct(conn, max_write, %d, );

      /** Maximum readahead */
      // unsigned max_readahead;
      log_struct(conn, max_readahead, %d, );

      /** Capability flags, that the kernel supports */
      // unsigned capable;
      log_struct(conn, capable, %08x, );

      /** Capability flags, that the filesystem wants to enable */
      // unsigned want;
      log_struct(conn, want, %08x, );

      /** Maximum number of backgrounded requests */
      // unsigned max_background;
      log_struct(conn, max_background, %d, );

      /** Kernel congestion threshold parameter */
      // unsigned congestion_threshold;
      log_struct(conn, congestion_threshold, %d, );

      /** For future use. */
      // unsigned reserved[23];
  }

  // struct fuse_file_info keeps information about files (surprise!).
  // This dumps all the information in a struct fuse_file_info.  The struct
  // definition, and comments, come from /usr/include/fuse/fuse_common.h
  // Duplicated here for convenience.
  void log_fi (struct fuse_file_info *fi)
  {
      log_msg("    fi:\n");

      /** Open flags.  Available in open() and release() */
      //	int flags;
  	log_struct(fi, flags, 0x%08x, );

      /** In case of a write operation indicates if this was caused by a
          writepage */
      //	int writepage;
  	log_struct(fi, writepage, %d, );

      /** Can be filled in by open, to use direct I/O on this file.
          Introduced in version 2.4 */
      //	unsigned int keep_cache : 1;
  	log_struct(fi, direct_io, %d, );

      /** Can be filled in by open, to indicate, that cached file data
          need not be invalidated.  Introduced in version 2.4 */
      //	unsigned int flush : 1;
  	log_struct(fi, keep_cache, %d, );

      /** Padding.  Do not use*/
      //	unsigned int padding : 29;

      /** File handle.  May be filled in by filesystem in open().
          Available in all other file operations */
      //	uint64_t fh;
  	log_struct(fi, fh, 0x%016llx,  );

      /** Lock owner id.  Available in locking operations and flush */
      //  uint64_t lock_owner;
  	log_struct(fi, lock_owner, 0x%016llx, );
  }

  void log_retstat(char *func, int retstat)
  {
      int errsave = errno;
      log_msg("    %s returned %d\n", func, retstat);
      errno = errsave;
  }

  // make a system call, checking (and reporting) return status and
  // possibly logging error
  int log_syscall(char *func, int retstat, int min_ret)
  {
      log_retstat(func, retstat);

      if (retstat < min_ret) {
  	log_error(func);
  	retstat = -errno;
      }

      return retstat;
  }

  // This dumps the info from a struct stat.  The struct is defined in
  // <bits/stat.h>; this is indirectly included from <fcntl.h>
  void log_stat(struct stat *si)
  {
      log_msg("    si:\n");

      //  dev_t     st_dev;     /* ID of device containing file */
  	log_struct(si, st_dev, %lld, );

      //  ino_t     st_ino;     /* inode number */
  	log_struct(si, st_ino, %lld, );

      //  mode_t    st_mode;    /* protection */
  	log_struct(si, st_mode, 0%o, );

      //  nlink_t   st_nlink;   /* number of hard links */
  	log_struct(si, st_nlink, %d, );

      //  uid_t     st_uid;     /* user ID of owner */
  	log_struct(si, st_uid, %d, );

      //  gid_t     st_gid;     /* group ID of owner */
  	log_struct(si, st_gid, %d, );

      //  dev_t     st_rdev;    /* device ID (if special file) */
  	log_struct(si, st_rdev, %lld,  );

      //  off_t     st_size;    /* total size, in bytes */
  	log_struct(si, st_size, %lld,  );

      //  blksize_t st_blksize; /* blocksize for filesystem I/O */
  	log_struct(si, st_blksize, %ld,  );

      //  blkcnt_t  st_blocks;  /* number of blocks allocated */
  	log_struct(si, st_blocks, %lld,  );

      //  time_t    st_atime;   /* time of last access */
  	log_struct(si, st_atime, 0x%08lx, );

      //  time_t    st_mtime;   /* time of last modification */
  	log_struct(si, st_mtime, 0x%08lx, );

      //  time_t    st_ctime;   /* time of last status change */
  	log_struct(si, st_ctime, 0x%08lx, );

  }

  void log_statvfs(struct statvfs *sv)
  {
      log_msg("    sv:\n");

      //  unsigned long  f_bsize;    /* file system block size */
  	log_struct(sv, f_bsize, %ld, );

      //  unsigned long  f_frsize;   /* fragment size */
  	log_struct(sv, f_frsize, %ld, );

      //  fsblkcnt_t     f_blocks;   /* size of fs in f_frsize units */
  	log_struct(sv, f_blocks, %lld, );

      //  fsblkcnt_t     f_bfree;    /* # free blocks */
  	log_struct(sv, f_bfree, %lld, );

      //  fsblkcnt_t     f_bavail;   /* # free blocks for non-root */
  	log_struct(sv, f_bavail, %lld, );

      //  fsfilcnt_t     f_files;    /* # inodes */
  	log_struct(sv, f_files, %lld, );

      //  fsfilcnt_t     f_ffree;    /* # free inodes */
  	log_struct(sv, f_ffree, %lld, );

      //  fsfilcnt_t     f_favail;   /* # free inodes for non-root */
  	log_struct(sv, f_favail, %lld, );

      //  unsigned long  f_fsid;     /* file system ID */
  	log_struct(sv, f_fsid, %ld, );

      //  unsigned long  f_flag;     /* mount flags */
  	log_struct(sv, f_flag, 0x%08lx, );

      //  unsigned long  f_namemax;  /* maximum filename length */
  	log_struct(sv, f_namemax, %ld, );

  }

  static void hello_fullpath(char fpath[PATH_MAX], const char *path)
  {
      strcpy(fpath, TB_DATA->rootdir);
      strncat(fpath, path, PATH_MAX); // ridiculously long paths will
  				    // break here

      log_msg("    hello_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
  	    TB_DATA->rootdir, path, fpath);
  }

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
	const char *filename;
	const char *contents;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--name=%s", filename),
	OPTION("--contents=%s", contents),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static void *hello_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;


      log_msg("\ntb_init()\n");

      log_conn(conn);
      log_fuse_context(fuse_get_context());
	cfg->kernel_cache = 1;
	return TB_DATA;
}

static int hello_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	int retstat;
	char fpath[PATH_MAX];

	log_msg("\ntb_getattr(path=\"%s\", statbuf=0x%08x)\n",
	path, stbuf);
	hello_fullpath(fpath, path);

	retstat = log_syscall("lstat", lstat(fpath, stbuf), 0);

	log_stat(stbuf);

	return retstat;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	int retstat = 0;
	DIR *dp;
	struct dirent *de;

	log_msg("\ntb_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
		path, buf, filler, offset, fi);
	// once again, no need for fullpath -- but note that I need to cast fi->fh
	dp = (DIR *) (uintptr_t) fi->fh;

	// Every directory contains at least two entries: . and ..  If my
	// first call to the system readdir() returns NULL I've got an
	// error; near as I can tell, that's the only condition under
	// which I can get an error from readdir()
	de = readdir(dp);
	log_msg("    readdir returned 0x%p\n", de);
	if (de == 0) {
	retstat = log_error("tb_readdir readdir");
	return retstat;
	}

	// This will copy the entire directory into the buffer.  The loop exits
	// when either the system readdir() returns NULL, or filler()
	// returns something non-zero.  The first case just means I've
	// read the whole directory; the second means the buffer is full.
	do {
	log_msg("calling filler with name %s\n", de->d_name);
	if (filler(buf, de->d_name, NULL, 0, 0) != 0) {
		log_msg("    ERROR tb_readdir filler:  buffer full");
		return -ENOMEM;
	}
	} while ((de = readdir(dp)) != NULL);

	log_fi(fi);

	return retstat;
}

static int hello_open(const char *path, struct fuse_file_info *fi)
{
	int retstat = 0;
	int fd;
	char fpath[PATH_MAX];

	log_msg("\ntb_open(path\"%s\", fi=0x%08x)\n",
		path, fi);
	hello_fullpath(fpath, path);

	// if the open call succeeds, my retstat is the file descriptor,
	// else it's -errno.  I'm making sure that in that case the saved
	// file descriptor is exactly -1.
	fd = log_syscall("open", open(fpath, fi->flags), 0);
	if (fd < 0)
	retstat = log_error("open");

	fi->fh = fd;

	log_fi(fi);

	return retstat;
}

static int hello_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nhello_opendir(path=\"%s\", fi=0x%08x)\n",
	  path, fi);
    hello_fullpath(fpath, path);

    // since opendir returns a pointer, takes some custom handling of
    // return status.
    dp = opendir(fpath);
    log_msg("    opendir returned 0x%p\n", dp);
    if (dp == NULL)
	retstat = log_error("hello_opendir opendir");

    fi->fh = (intptr_t) dp;

    log_fi(fi);

    return retstat;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	    log_msg("\ntb_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
		    path, buf, size, offset, fi);
	    // no need to get fpath on this one, since I work from fi->fh not the path
	    log_fi(fi);

	    return log_syscall("pread", pread(fi->fh, buf, size, offset), 0);
}

static int hello_statfs(const char *path, struct statvfs *statv)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_statfs(path=\"%s\", statv=0x%08x)\n",
	    path, statv);
    hello_fullpath(fpath, path);

    // get stats for underlying filesystem
    retstat = log_syscall("statvfs", statvfs(fpath, statv), 0);

    log_statvfs(statv);

    return retstat;
}

static int hello_mknod(const char *path, mode_t mode, dev_t dev)
{
    int retstat;
    char fpath[PATH_MAX];

    log_msg("\nbb_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n",
	  path, mode, dev);
    hello_fullpath(fpath, path);

    // On Linux this could just be 'mknod(path, mode, dev)' but this
    // tries to be be more portable by honoring the quote in the Linux
    // mknod man page stating the only portable use of mknod() is to
    // make a fifo, but saying it should never actually be used for
    // that.
    if (S_ISREG(mode)) {
	retstat = log_syscall("open", open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode), 0);
	if (retstat >= 0)
	    retstat = log_syscall("close", close(retstat), 0);
    } else
	if (S_ISFIFO(mode))
	    retstat = log_syscall("mkfifo", mkfifo(fpath, mode), 0);
	else
	    retstat = log_syscall("mknod", mknod(fpath, mode, dev), 0);

    return retstat;
}

/** Create a directory */
int hello_mkdir(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_mkdir(path=\"%s\", mode=0%3o)\n",
	    path, mode);
    hello_fullpath(fpath, path);

    return log_syscall("mkdir", mkdir(fpath, mode), 0);
}

/** Remove a file */
int hello_unlink(const char *path)
{
    char fpath[PATH_MAX];

    log_msg("bb_unlink(path=\"%s\")\n",
	    path);
    hello_fullpath(fpath, path);

    return log_syscall("unlink", unlink(fpath), 0);
}

/** Remove a directory */
int hello_rmdir(const char *path)
{
    char fpath[PATH_MAX];

    log_msg("bb_rmdir(path=\"%s\")\n",
	    path);
    hello_fullpath(fpath, path);

    return log_syscall("rmdir", rmdir(fpath), 0);
}

int hello_flush(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nbb_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);

    return 0;
}

int hello_access(const char *path, int mask)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_access(path=\"%s\", mask=0%o)\n",
	    path, mask);
    hello_fullpath(fpath, path);

    retstat = access(fpath, mask);

    if (retstat < 0)
	retstat = log_error("bb_access access");

    return retstat;
}

int hello_truncate(const char *path, off_t newsize, struct fuse_file_info *fi)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_truncate(path=\"%s\", newsize=%lld)\n",
	    path, newsize);
    hello_fullpath(fpath, path);

    return log_syscall("truncate", truncate(fpath, newsize), 0);
}

int hello_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
    log_msg("\nbb_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
	    path, buf, size, offset, fi
	    );
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);

    return log_syscall("pwrite", pwrite(fi->fh, buf, size, offset), 0);
}

int hello_rename(const char *path, const char *newpath, unsigned int flags)
{
    char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];

    log_msg("\nbb_rename(fpath=\"%s\", newpath=\"%s\")\n",
	    path, newpath);
    hello_fullpath(fpath, path);
    hello_fullpath(fnewpath, newpath);

    return log_syscall("rename", rename(fpath, fnewpath), 0);
}

int hello_link(const char *path, const char *newpath)
{
    char fpath[PATH_MAX], fnewpath[PATH_MAX];

    log_msg("\nbb_link(path=\"%s\", newpath=\"%s\")\n",
	    path, newpath);
    hello_fullpath(fpath, path);
    hello_fullpath(fnewpath, newpath);

    return log_syscall("link", link(fpath, fnewpath), 0);
}
int hello_symlink(const char *path, const char *link)
{
    char flink[PATH_MAX];

    log_msg("\nbb_symlink(path=\"%s\", link=\"%s\")\n",
	    path, link);
    hello_fullpath(flink, link);

    return log_syscall("symlink", symlink(path, flink), 0);
}

int hello_release(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nbb_release(path=\"%s\", fi=0x%08x)\n",
	  path, fi);
    log_fi(fi);

    // We need to close the file.  Had we allocated any resources
    // (buffers etc) we'd need to free them here as well.
    return log_syscall("close", close(fi->fh), 0);
}

int hello_releasedir(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_msg("\nbb_releasedir(path=\"%s\", fi=0x%08x)\n",
	    path, fi);
    log_fi(fi);

    closedir((DIR *) (uintptr_t) fi->fh);

    return retstat;
}

static struct fuse_operations hello_oper = {
	.init           = hello_init,
	.getattr	= hello_getattr,
	.readdir	= hello_readdir,
	.open		= hello_open,
	.opendir = hello_opendir,
	.read		= hello_read,
	.statfs = hello_statfs,
	.mknod = hello_mknod,
	.mkdir = hello_mkdir,
  .unlink = hello_unlink,
  .rmdir = hello_rmdir,
  .flush = hello_flush,
	.access = hello_access,
	.write = hello_write,
	.truncate = hello_truncate,
	.rename = hello_rename,
	.link = hello_link,
	.symlink = hello_symlink,
	.release = hello_release,
	.releasedir = hello_releasedir,

};

static void show_help(const char *progname)
{
	printf("usage: %s [options] <rootDir> <mountpoint>\n\n", progname);
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct tb_state *tb_data;

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.filename = strdup("hello");
	options.contents = strdup("Hello World!\n");
	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr, "Running TBFS as root opens unnacceptable security holes\n");
		return 1;
	}
	fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

	tb_data = malloc(sizeof(struct tb_state));
	if (tb_data == NULL) {
perror("main calloc");
abort();
	}
	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0] = (char*) "";
	}

	tb_data->rootdir = realpath(argv[argc-2], NULL);
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc--;

	tb_data->logfile = log_open();

	// turn over control to fuse
	fprintf(stderr, "about to call fuse_main\n");
	int fuse_stat = fuse_main(argc, argv, &hello_oper, tb_data);
	fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

	return fuse_stat;

}
