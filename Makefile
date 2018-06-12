username = $(shell whoami)
mountpoint = /home/$(username)/Desktop/mountpoint
includepath = -I./include/
srcprefix = ./src/
files = $(srcprefix)tbfs_operations.c $(srcprefix)tree.c $(srcprefix)disk.c $(srcprefix)bitmap.c $(srcprefix)log.c
compileflags = -D_FILE_OFFSET_BITS=64
opflag = -o tbfs
neededflag = `pkg-config fuse --libs` -DFUSE_USE_VERSION=22 -lm

all: run cleanup

run: compile cleanup
	./tbfs $(mountpoint) /home/$(username)/Desktop/disk.img

debug: dcompile cleanup
	./tbfs -d -f -s $(mountpoint) /home/$(username)/Desktop/disk.img

fgrun: compile
	./tbfs -f $(mountpoint) /home/$(username)/Desktop/disk.img

compile: checkdir
	gcc -Wall $(includepath) $(srcprefix)tbfs_main.c $(files) $(compileflags) $(opflag) $(neededflag)

dcompile: checkdir
	gcc -Wall $(includepath) -g -DERR_FLAG $(srcprefix)tbfs_main.c $(files) $(compileflags) $(opflag) $(neededflag)

checkdir:
	if [ -d "$(mountpoint)" ]; then echo "mountpoint exists"; else mkdir $(mountpoint); fi

dmkfs: mkfs_dcompile
	./mkfs /home/$(username)/Desktop/disk.img

mkfs_dcompile: 
	gcc -Wall $(includepath) -g -DERR_FLAG $(files) $(srcprefix)mkfs.c $(compileflags) -o mkfs $(neededflag)

mkfs: mkfs_compile
	./mkfs /home/$(username)/Desktop/disk.img

mkfs_compile: 
	gcc -Wall $(includepath) $(files) $(srcprefix)mkfs.c $(compileflags) -o mkfs $(neededflag)

cleanup :
	fusermount -u $(mountpoint)
