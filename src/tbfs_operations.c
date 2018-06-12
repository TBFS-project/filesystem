#include "tbfs_operations.h"
#include "tree.h"
#include "log.h"

//static void log_msg(char *fmt, ...) {
//#ifdef ERR_FLAG
//    va_list args;
//    va_start(args, fmt);
    
//    printf("\n");
//    printf("tbfs OPS : ");
//    vprintf(fmt, args);
//    printf("\n");

//    va_end(args);
//#endif
//}


int tbfs_getattr(const char *path, struct stat *s) {
    log_msg("%s called on path : %s", __func__, path);

    fs_tree_node *curr = NULL;
    if(!(curr = node_exists(path))) {
        log_msg("curr = %p ; not found returning!", curr);
        return -ENOENT;
    }

    memset(s, 0, sizeof(struct stat));

    s->st_dev = 666;
    s->st_ino = curr->inode_no;

    switch(curr->type) {
        case 1:
            s->st_mode = S_IFREG | curr->perms;
            s->st_nlink = 1;
            break;

        case 2:
            s->st_mode = S_IFDIR | curr->perms;
            s->st_nlink = 2;
            break;

        default:
            log_msg("Type not supported : %d", curr->type);
            return -ENOTSUP;
    }

    s->st_nlink += curr->len;
    s->st_uid = curr->uid;
    s->st_gid = curr->gid;

    s->st_size = curr->data_size;
    s->st_blocks = ((curr->data_size + NODE_SIZE) / 4096) + 1;
    s->st_blocks *= 8;

    s->st_atime = (curr->st_atim).tv_sec;
    s->st_mtime = (curr->st_mtim).tv_sec;
    s->st_ctime = (curr->st_ctim).tv_sec;
    
    return 0;
}


int tbfs_mknod(const char *path, mode_t m, dev_t d) {
    log_msg("%s called on path : %s", __func__, path);

    log_msg("Add FS tree node at path : %s", path);
    long int ret = (uint64_t)add_fs_tree_node(path, 1);
    if(ret < 0) {
        return (int)ret;
    }

    return 0;
}


int tbfs_mkdir(const char *path, mode_t m) {
    log_msg("%s called on path : %s", __func__, path);

    log_msg("Add FS tree node at path : %s", path);
    long int ret = (uint64_t)add_fs_tree_node(path, 2);
    if(ret < 0) {
        return (int)ret;
    }

    return 0;
}


int tbfs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    log_msg("%s called on path : %s", __func__, path);

    fs_tree_node *curr = NULL;

    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);

    curr = node_exists(path);

    if(strcmp(path, "/")) {
        if(!curr) {
            return -ENOENT;
        }
    }

    log_msg("Path : %s : found to exist with %d children", path, curr->len);

    int i;
    for(i = 0 ; i < curr->len ; i++)
        filler(buffer, curr->children[i]->name, NULL, 0);

    return 0;
}


int tbfs_rmdir(const char *path) {
    log_msg("%s called on path : %s", __func__, path);
    if(node_exists(path)->len != 0) {
        return -ENOTEMPTY;
    }

    return remove_fs_tree_node(path);
}


int tbfs_open(const char *path, struct fuse_file_info *fi)
{   
    log_msg("%s called on path : %s", __func__, path);
    
    fs_tree_node *curr = node_exists(path);
    uint32_t check = 0;
    switch(fi->flags & O_ACCMODE) {
        case O_RDWR:
            log_msg("O_RDWR");
            check = check | 0666;
            break;
        
        case O_RDONLY:
            log_msg("O_RDONLY");
            check = check | 0444;
            break;

        case O_WRONLY:
            log_msg("O_WRONLY");
            check = check | 0222;
            break;
    }

    log_msg("%d %d %d", curr->perms, check, curr->perms & check);
    if(curr->perms & check) {
        log_msg("Allowed to open!");
        return 0;
    }

    return -EACCES;
}


int tbfs_read(const char *path, char *buf, size_t size, off_t offset,struct fuse_file_info *fi)
{   
    log_msg("%s called on path : %s \t size = %lu\t offset = %ld", __func__, path, size, offset);

    fs_tree_node *curr = NULL;
    size_t len;
    curr = node_exists(path);
    dataDiskReader(curr);
    log_msg("Data disk read %s", curr->data);

    len = curr->data_size;

    log_msg("curr found at %p with data %d", curr, len);

    if (offset < len) {
        if (offset + size > len)
            size = len - offset;
        
        log_msg("if offset < len\t %ld %d %ld", size, len, offset);
        memcpy(buf, curr->data + offset, size);
    } 
    else {
        size = 0;
        strcpy(buf, "");
    }

    return size;
}


int tbfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{   
    log_msg("%s called on path : %s ; to write : %s ; size = %d ; offset = %d ;", __func__, path, buf, size, offset);

    fs_tree_node *curr = NULL;
    size_t len = 0;
    curr = node_exists(path);
    len = curr->data_size;

    log_msg("curr found at %p with data %d", curr, len);

    if (offset + size >= len){
        void *new_buf = NULL;

        new_buf = reallocate(curr, offset+size+1);
        if (!new_buf && offset+size) {
            log_msg("Failed to realloc! %p && %d = %d", new_buf, offset+size, (!new_buf && offset+size));
            return -ENOMEM;
        }
        else if(new_buf != curr->data)
            curr->data = new_buf;

        log_msg("successfuly realloced to %d!", offset+size+1);

        memset(curr->data + offset, 0, size);
        
        log_msg("Erased data from offset %d to size %d!", offset, size);
        curr->data_size = offset + size;
        log_msg("curr->data_size %lu", curr->data_size);
    }
    
    memcpy(curr->data + offset, buf, size);

    log_msg("Copied data! Returning with size %d!", size);

    tbfs_flush(path, NULL);

    return size;
}


int tbfs_utimens(const char *path, struct utimbuf *tv) {
    log_msg("%s called on path : %s", __func__, path);
    log_msg("atime = %s; mtime = %s ", ctime(&(tv->actime)), ctime(&(tv->modtime)));

    fs_tree_node *curr = node_exists(path);

    if(!curr)
        return -ENOENT;
    
    if(curr->st_atim.tv_sec < tv->actime)
        curr->st_atim.tv_sec = tv->actime;

    if(curr->st_mtim.tv_sec < tv->modtime)
        curr->st_mtim.tv_sec = tv->modtime;

    return 0;
}


int tbfs_truncate(const char* path, off_t size)
{

 	log_msg("%s called on path : %s ; to change to size = %d ;", __func__, path,size);

    fs_tree_node *curr = NULL;
    size_t len;
    curr = node_exists(path);
    len = curr->data_size;

    log_msg("curr found at %p with data %d", curr, len);
    void *new_buf;

    if(len<size)
    {
    	 new_buf = reallocate(curr, size+1);

    	 if(!new_buf)
    	 {
      		return -ENOMEM;
    	 }

   	}
   	else if(len>size)
	{

		 new_buf = reallocate(curr, size+1);

    	 if(!new_buf)
    	 {
      		return -ENOMEM;
    	 }

   	 }

 	 if(len<size)
 	 {
    	memset(curr->data + len, 0, size-len);
  	 }

  	 curr->data_size = size;

  	 return 0;

}


int tbfs_unlink(const char *path)
 {

  	log_msg("%s called on path : %s ;", __func__, path);

    return remove_fs_tree_node(path);

}


int tbfs_rename(const char *from, const char *to) {
    log_msg("%s called from : %s ; to : %s", __func__, from, to);

    fs_tree_node *to_node = node_exists(to);
    fs_tree_node *from_node = node_exists(from);
    fs_tree_node *from_parent;

    if(!from) {
        log_msg("from file not found");
        return -ENOENT;
    }

    if(from_node->type == 1) {
        log_msg("from node is a file");
        dataDiskReader(from_node);
        if(to_node) {
            log_msg("to node exists");
            if(to_node->type == 1) {
                log_msg("to node is a file");

                remove_fs_tree_node(to);
                log_msg("to node was removed");
                to_node = add_fs_tree_node(to, 1);
                log_msg("to node was added");
                copy_nodes(from_node, to_node);
                log_msg("from node was copied to to node");

                from_parent = from_node->parent;
                if(!from_node->fullname)
                    free(from_node->fullname);
                if(!from_node)
                    free(from_node);

                log_msg("from node was freed");

                int i;
                for(i = 0 ; i < from_parent->len ; i++) {
                    if(from_parent->children[i] == from_node) {
                        log_msg("from_node found to be the %d th child of its parent %p", i, from_parent);
                        int j;
                        for(j = i + 1 ; j < from_parent->len ; j++) {
                            from_parent->children[j-1] = from_parent->children[j];
                            from_parent->ch_inodes[j-1] = from_parent->ch_inodes[j];
                        }
                        from_parent->len -= 1;
                        log_msg("from_parents children reduced from %d to %d", from_parent->len-1, from_parent->len);
                        break;  
                    }
                }
            }
            else if(to_node->type == 2) {
                log_msg("to node is a dir, not yet implemented");
                
                return -EISDIR;
            }
        }
        else {
            to_node = add_fs_tree_node(to, 1);
            copy_nodes(from_node, to_node);

            from_parent = from_node->parent;
            if(!from_node->name)
                free(from_node->name);
            if(!from_node->fullname)
                free(from_node->fullname);
            if(!from_node)
                free(from_node);
                
            log_msg("from node was freed");

            int i;
            for(i = 0 ; i < from_parent->len ; i++) {
                if(from_parent->children[i] == from_node) {
                    log_msg("from_node found to be the %d th child of its parent %p", i, from_parent);
                    int j;
                    for(j = i + 1 ; j < from_parent->len ; j++) {
                        from_parent->children[j-1] = from_parent->children[j];
                        from_parent->ch_inodes[j-1] = from_parent->ch_inodes[j];
                    }
                    from_parent->len -= 1;
                    log_msg("from_parents children reduced from %d to %d", from_parent->len-1, from_parent->len);
                    break;  
                }
            }
        }
    }
    else {
        log_msg("from node must be a dir");

        if(to_node) {
            log_msg("to node exists");

            if(to_node->type == 1) {
                log_msg("to node is a file");
                return -EEXIST;
            }
            else {
                log_msg("to node is a dir, deleting");
                remove_fs_tree_node(to);
                log_msg("Deleted!");
            }
        }
        else {
            log_msg("to node does not exist");
        }

        to_node = add_fs_tree_node(to, 2);
        log_msg("Added node");
        copy_nodes(from_node, to_node);
        log_msg("Copied from to to");

        from_parent = from_node->parent;
        if(!from_node->parent)
            free(from_node->name);
        if(!from_node->fullname)
            free(from_node->fullname);
        if(!from_node)
            free(from_node);
        log_msg("from node was freed");

        int i;
        for(i = 0 ; i < from_parent->len ; i++) {
            if(from_parent->children[i] == from_node) {
                log_msg("from_node found to be the %d th child of its parent %p", i, from_parent);
                int j;
                for(j = i + 1 ; j < from_parent->len ; j++) {
                    from_parent->children[j-1] = from_parent->children[j];
                    from_parent->ch_inodes[j-1] = from_parent->ch_inodes[j];
                }
                from_parent->len -= 1;
                from_parent->children = realloc(from_parent->children, sizeof(fs_tree_node *) * from_parent->len);
                from_parent->ch_inodes = realloc(from_parent->ch_inodes, sizeof(from_parent->inode_no) * from_parent->len);
                log_msg("from_parents children reduced from %d to %d", from_parent->len+1, from_parent->len);
                break;  
            }
        }
    }

    void *buf;
    uint64_t newblocks = constructBlock(from_parent, &buf);
    diskWriter(buf, newblocks, from_parent->inode_no);
    if(!buf)
        free(buf);

    newblocks = constructBlock(to_node, &buf);
    diskWriter(buf, newblocks, to_node->inode_no);
    if(!buf)
        free(buf);
    

    log_msg("end of %s reached, going to return 0", __func__);

    return 0;
}


int tbfs_chmod(const char *path, mode_t setPerm) {
    log_msg("%s called on path : %s ; to set : %d", __func__, path, setPerm);

    fs_tree_node *curr = node_exists(path);
    if(!curr) {
        log_msg("File not found!");
        
        return -ENOENT;
    }

    uint32_t curr_uid = getuid();
    if(curr_uid == curr->uid || !curr_uid) {
        log_msg("Current user (%d) has permissions to chmod", curr_uid);

        curr->perms = setPerm;
    }
    else {
        log_msg("Current user (%d) DOESNT permissions to chown", curr_uid); 
        return -EACCES;
    }

    return 0;
}


int tbfs_chown(const char *path, uid_t u, gid_t g) {
    log_msg("%s called on path : %s ; to set : u = %d\t g = %d", __func__, path, u, g);

    fs_tree_node *curr = node_exists(path);
    if(!curr) {
        log_msg("File not found!");
        
        return -ENOENT;
    }

    uid_t curr_user = getuid();

    if(curr_user != 0 && curr_user != curr->uid) {
        log_msg("Current user (%d) DOESNT permissions to chown file owned by %d", curr_user, curr->uid); 
        return -EACCES;
    }
    log_msg("Current user (%d) has permissions to chown", curr_user); 

    if(u != -1)
        curr->uid = u;

    if(g != -1)
        curr->gid = g;

    return 0;
}


int tbfs_flush(const  char *path, struct fuse_file_info *fi) {
    log_msg("%s called on path : %s", __func__, path);

    fs_tree_node *node = node_exists(path);
    void *buf = NULL;
    uint64_t blocks = constructBlock(node, &buf);
    diskWriter(buf, blocks, node->inode_no);
    log_msg("Wrote file!");

    return 0;
}
