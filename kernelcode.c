#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include<linux/file.h>
#include<linux/fsnotify.h>
#include<linux/xattr.h>
#include "sys_xintegrity.h"
int wrapfs_read_file(const char *,void * ,int);
asmlinkage extern long (*sysptr)(void *arg);
//static int ecryptfs_calculate_md5(char *,char *, int );
long do_sys_open(int , const char *, int , int );
//static inline int build_open_flags(int , int , struct *);
asmlinkage long xintegrity(void *arg)
{
        //struct sys_xintegrity *myarg=(struct sys_xintegrity *)arg;
        //printk("\n%c",((struct sys_xintegrity*)myarg)->flag);
        int i,filedesc;
        int ret=0,rc=0;
        struct file *filp;
        struct sys_xintegrity *myarg;
        struct hash_desc desc;
        struct scatterlist sg;
        //struct file *filp;
        //t bytes;
        //myarg->credbuf="password";
        if(arg==NULL)
                return -EINVAL;

        if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg),sizeof(struct sys_xintegrity))){

                printk("Access not ok for structure");
                return -EACCES;
        }
        myarg=kmalloc(sizeof(struct sys_xintegrity),GFP_KERNEL);

        if(myarg==NULL){

                return -ENOMEM;
        }
                                                                                                                                                      
   if(copy_from_user(myarg,arg,sizeof(struct sys_xintegrity))){
                kfree(myarg);
                printk("error copying structure");
                return -EPERM;
        }

        if(myarg->flag=='1'){


                /*if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->filename,PAGE_SIZE)){
                        kfree(myarg);
                        printk("Access not ok for filename");
                        return -EACCES;
                }*/

                myarg->filename=getname(((struct sys_xintegrity *)arg)->filename);

                if(myarg->filename==NULL){
                        kfree(myarg);
                        return -EINVAL;
                }
                if(myarg->ilen==0){
                        kfree(myarg);
                        printk("\nILEN=0 CHECK");
                        return -ENOMEM;
                }
                if(myarg->ibuf==NULL){
                        kfree(myarg);
                        printk("\nBUFF=NULL condition check");
                        return -ENOMEM;
                }
                if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->ibuf,myarg->ilen)){
                        putname(myarg->filename);
                        kfree(myarg);
                        printk("Access not ok for ibuf");
                        return -EACCES;
                }
                myarg->ibuf=kmalloc(myarg->ilen,GFP_KERNEL);
                if(myarg->ibuf == NULL){
                        putname(myarg->filename);
                        kfree(myarg);
                        return -ENOMEM;
                }
                if(copy_from_user((struct sys_xintegrity *)myarg->ibuf,((struct sys_xintegrity *)arg)->ibuf,myarg->ilen)){

                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        printk("error copying ibuf");
                        return -EPERM;
                }
                filp = filp_open(myarg->filename, O_RDONLY, 0);
                if (!filp || IS_ERR(filp)) {

                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);

                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
                        return -ENOENT;  /* or do something else */
                }
                //printk("\n\nIBUF=%d",myarg->ibuf);
                if (filp->f_op->read == NULL){

                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);

                        return -EACCES;  /* file(system) doesn't allow reads */
                }
                ret = vfs_getxattr(filp->f_path.dentry,"user.md5sum",myarg->ibuf,myarg->ilen);
                //printk("RET=%d \nMYARG->ILEN=%d",ret,myarg->ilen);
                if(ret<0){
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        printk("\n file exists but with no integrity");
                        return -ENODATA;
                }
                else
                        ret=0;

                //printk("RET=%d",ret);
                printk("\nRET VALUE=%d LENGTH=%d \n",ret,myarg->ilen);
                if(copy_to_user(((struct sys_xintegrity *)arg)->ibuf,myarg->ibuf,(myarg->ilen))){
                        kfree(myarg->ibuf);
                     putname(myarg->filename);
                        kfree(myarg);
                        return -EINVAL;

                }
                //printk("File name is %s",myarg->filename);
                kfree(myarg->ibuf);
                putname(myarg->filename);
                kfree(myarg);
                goto out;
                //return ret;
        }
        if(myarg->flag=='2'){

                /*if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->filename,20)){
                        kfree(myarg);
                        printk("Access not ok for filename");
                        return -EACCES;
                }*/
                struct file *filp;
                mm_segment_t oldfs;
                int bytes;
                 void *buffer=kmalloc(myarg->ilen,GFP_KERNEL);
                myarg->filename=getname(((struct sys_xintegrity *)arg)->filename);
                if(myarg->filename==NULL){
                        kfree(myarg);
                        return -EINVAL;
                }
                if(myarg->clen==0){
                        kfree(myarg);
                        printk("\nCLEN=0 CHECK");
                        return -ENOMEM;
                }
                 if(myarg->ilen==0){
                        kfree(myarg);
                        printk("\nILEN=0 CHECK");
                        return -ENOMEM;
                }
                if(myarg->ibuf==NULL){
                        kfree(myarg);
                        printk("\nBUFF=NULL condition check");
                        return -ENOMEM;


                }

                if(myarg->credbuf==NULL){
                        kfree(myarg);
                        printk("\nCREDBUF=NULL condition check");
                        return -ENOMEM;
                }
                if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->ibuf,myarg->ilen)){
                        putname(myarg->filename);
                        kfree(myarg);
                        printk("Access not ok for ibuf");
                        return -EACCES;
                }
                myarg->ibuf=kmalloc(myarg->ilen,GFP_KERNEL);

                if(myarg->ibuf==NULL){
                         putname(myarg->filename);
                         kfree(myarg);
                        return -ENOMEM;
                }
                if(copy_from_user((struct sys_xintegrity *)myarg->ibuf,((struct sys_xintegrity *)arg)->ibuf,myarg->ilen)){

                        putname(myarg->filename);
                        kfree(myarg->ibuf);
                        kfree(myarg);
                        printk("error copying ibuf");
                        return -EPERM;
                }

                if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->credbuf,myarg->clen)){
                        putname(myarg->filename);
                        kfree(myarg->ibuf);
                        kfree(myarg);

                        printk("Access not ok for credbuf");
                        return -EACCES;
                }
                myarg->credbuf=kmalloc(myarg->clen,GFP_KERNEL);

                //myarg->credbuf="password";
                if(myarg->credbuf == NULL){
                        putname(myarg->filename);
                                                                                                            
                   kfree(myarg->ibuf);
                        kfree(myarg);
                        return -ENOMEM;
                }
                if(copy_from_user((struct sys_xintegrity *)myarg->credbuf,((struct sys_xintegrity *)arg)->credbuf,myarg->clen)){
                        kfree(myarg->credbuf);
                        putname(myarg->filename);
                        kfree(myarg->ibuf);
                        kfree(myarg);
                        printk("error copying credbuf");
                        return -EPERM;
                }
                if(strcmp(myarg->credbuf,"password")){
                         kfree(myarg->credbuf);
                        putname(myarg->filename);
                        kfree(myarg->ibuf);
                        kfree(myarg);
                        printk("error copying credbuf");
                        return -EACCES;

                }
                //printk("\nCREDBUF-%s",myarg->credbuf);
                /*********************************************************
                 *
                 *********************************************************/


                filp = filp_open(myarg->filename, O_RDONLY, 0);
                if (!filp || IS_ERR(filp)) {
                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
                        return -ENOENT;  /* or do something else */
                }

                if (!filp->f_op->read)
                        return -2;  // file(system) doesn't allow reads

                /* now read len bytes from offset 0 */
                filp->f_pos = 0;                /* start offset */
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                desc.flags = 0;
                desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
                rc = crypto_hash_init(&desc);


      if (rc) {
                         printk(KERN_ERR
                                "%s: Error initializing crypto hash; rc = [%d]\n",
                                __func__, rc);
                        return ret;
                }
                //while((bytes = wrapfs_read_file(myarg->filename,buffer,20))){
                //sg_init_one(&sg, (u8 *)buffer, myarg->ilen);}
                while((bytes = filp->f_op->read(filp, buffer,myarg->ilen, &filp->f_pos))){
                        sg_init_one(&sg, (u8 *)buffer, myarg->ilen);
                        rc = crypto_hash_update(&desc, &sg, bytes);
                        printk("DATA: %s  BYTES: %d\n", (char *)buffer, bytes);
                        //ret= ecryptfs_calculate_md5(myarg->ibuf,buffer,20);
                }
                rc = crypto_hash_final(&desc, buffer);
                set_fs(oldfs);

                    // close the file
                    filp_close(filp, NULL);
                printk("\nMD5\n");
                for(i=0;i<16;i++){
                        printk("%02x",((char *)buffer)[i] & 0x0FF);
                }
                printk("\nDone\n");
                /*********************************************************
                 *
                 *********************************************************/
                filp=filp_open(myarg->filename, O_RDONLY, 0);

                if (!filp || IS_ERR(filp)) {

                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);

                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
                        return -ENOENT;  /* or do something else */
                }
                myarg->ibuf = (char *)buffer;
                rc = vfs_setxattr(filp->f_path.dentry,"user.md5sum",myarg->ibuf,myarg->ilen,0);

                if(rc){
                        kfree(myarg->ibuf);

                    putname(myarg->filename);
                        kfree(myarg);
                        return -EFAULT;
                }


                ret = vfs_getxattr(filp->f_path.dentry,"user.md5sum",myarg->ibuf,myarg->ilen);

                if(ret<0){
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        return -ENODATA;
                }
                else
                        ret=0;
                for(i=0;i<16;i++){
                        printk("%02x",myarg->ibuf[i] & 0xFF);
                }
                //printk("%d %s\n",ret,myarg->ibuf);
                if(copy_to_user(((struct sys_xintegrity *)arg)->ibuf,myarg->ibuf,myarg->ilen)){
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        return -EINVAL;

                }
                //printk("File name is %s",myarg->filename);

                kfree(myarg->ibuf);
                kfree(myarg->credbuf);
                putname(myarg->filename);
                kfree(myarg);
                goto out;
                //return ret;
                //return 0;
        }

        if(myarg->flag=='3'){

        /*if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->filename,32)){

                        printk("Access not ok for filename");
                                                                              

                     return -EINVAL;
          }*/
                struct file *filp;
                mm_segment_t oldfs;
                int bytes;
                void *buffer=kmalloc(myarg->ilen,GFP_KERNEL);
                myarg->filename=getname(((struct sys_xintegrity *)arg)->filename);

                if(myarg->filename==NULL){
                        kfree(myarg);
                        return -EINVAL;
                }

                if(!access_ok(VERIFY_READ,((struct sys_xintegrity *)arg)->ibuf,myarg->ilen)){
                        putname(myarg->filename);
                        kfree(myarg);
                        printk("Access not ok for ibuf");
                        return -EACCES;
                }
                myarg->ibuf=kmalloc(myarg->ilen,GFP_KERNEL);

                if(myarg->ibuf==NULL){
                         putname(myarg->filename);
                         kfree(myarg);
                        return -ENOMEM;
                }
                if(copy_from_user((struct sys_xintegrity *)myarg->ibuf,((struct sys_xintegrity *)arg)->ibuf,myarg->ilen)){

                        putname(myarg->filename);
                        kfree(myarg->ibuf);
                        kfree(myarg);
                        printk("error copying ibuf");
                        return -EPERM;
                }

                //struct hash_desc desc;
                //struct scatterlist sg;
                //struct file *filp;
                // mm_segment_t oldfs;
                //int bytes;
                // :Chroot? Maybe NULL isn't right here
                filp = filp_open(myarg->filename, O_RDONLY, 0);
                if (!filp || IS_ERR(filp)) {
                                                          
                 printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
                        return -ENOENT;  /* or do something else */
                }

                if (!filp->f_op->read)
                        return -2;  // file(system) doesn't allow reads

                /* now read len bytes from offset 0 */
                filp->f_pos = 0;                /* start offset */
                oldfs = get_fs();
                set_fs(KERNEL_DS);
                desc.flags = 0;
                desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
                rc = crypto_hash_init(&desc);
                if (rc) {
                         printk(KERN_ERR
                                "%s: Error initializing crypto hash; rc = [%d]\n",
                                __func__, rc);
                        return ret;
                }

                  while((bytes = filp->f_op->read(filp, buffer,myarg->ilen, &filp->f_pos))){
                        sg_init_one(&sg, (u8 *)buffer, myarg->ilen);
                        rc = crypto_hash_update(&desc, &sg, bytes);
                        printk("DATA: %s  BYTES: %d\n", (char *)buffer, bytes);
                        //ret= ecryptfs_calculate_md5(myarg->ibuf,buffer,20);
                }
                rc = crypto_hash_final(&desc, buffer);
                set_fs(oldfs);

                    // close the file
                    filp_close(filp, NULL);
                printk("\nMD5\n");
                for(i=0;i<16;i++){
                        printk("%02x",((char *)buffer)[i] & 0x0FF);
                }
                 printk("\nDone\n");
                /*********************************************************
                 *      Done
                 *********************************************************/
                 filp=filp_open(myarg->filename, O_RDONLY, 0);

                 if (!filp || IS_ERR(filp)) {

                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);

                        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
                        return -ENOENT;  /* or do something else */
                }

                 ret = vfs_getxattr(filp->f_path.dentry,"user.md5sum",myarg->ibuf,myarg->ilen);

                if(ret<0){
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        return -ENODATA;
                }
                else
                        ret=0;
                 if(copy_to_user(((struct sys_xintegrity *)arg)->ibuf,myarg->ibuf,myarg->ilen)){
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        return -EINVAL;

                }
                 filedesc = do_sys_open(AT_FDCWD,myarg->filename,myarg->oflag, myarg->mode);

                 printk("\nFILEDESC=%d\nMYARG->OFLAG=%d\nMYARG->MODE=%d\n",filedesc,myarg->oflag,myarg->mode);


                if(memcmp(buffer,myarg->ibuf,myarg->ilen)==0){
                        printk("hi\n");
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        return filedesc;
                 }
                else{
                        kfree(myarg->ibuf);
                        putname(myarg->filename);
                        kfree(myarg);
                        return -EPERM;
              }

        }
out:
return ret;
}

long do_sys_open(int dfd, const char *filename, int flags, int mode) {
         //struct open_flags* op;
        struct file *f;
         int fd=0;// = PTR_ERR(tmp);
 //      int lookup = build_open_flags(flags, mode, &op);
         char *tmp = getname(filename);
        printk("%s",(char *)filename);
        printk("\nFD=%d",fd);
        if (!IS_ERR(tmp)) {
                  fd = get_unused_fd();
                 if (fd >= 0) {
                        //fsnotify_open(f);
                         f = filp_open(tmp,flags,mode);
                        fd_install(fd,f);
                         //if (IS_ERR(f)) {
                        //f = filp_open(tmp,flags,mode);
                           //      put_unused_fd(fd);
                             //    fd = PTR_ERR(f);
                  }
                //else {
                //
                  //               fsnotify_open(f);
                    //             fd_install(fd, f);
                      //   }
                 //}
                putname(tmp);
         }
         return fd;
 }


int wrapfs_read_file(const char *filename, void *buf, int len)
{
    struct file *filp;
    mm_segment_t oldfs;
    int bytes;
        filp = filp_open(filename, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp));
        return -1;  /* or do something else */
    }

    if (!filp->f_op->read)
        return -2;  /* file(system) doesn't allow reads */

    /* now read len bytes from offset 0 */
    filp->f_pos = 0;            /* start offset */
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    bytes = filp->f_op->read(filp, buf, len, &filp->f_pos);
    set_fs(oldfs);

    /* close the file */
    filp_close(filp, NULL);

    return bytes;
}

static int __init init_sys_xintegrity(void)
{
        printk("installed new sys_xintegrity module\n");
        if (sysptr == NULL)
                sysptr = xintegrity;
        return 0;
}
static void  __exit exit_sys_xintegrity(void)
{
        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_xintegrity module\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");
                                          


