#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<string.h>
#include<fcntl.h>
//#include<file.h>
#define __NR_xintegrity 349     /* our private syscall number */
#include "sys_xintegrity.h"
int main(int argc, char *argv[])
{
        int rc,i;
        i=atoi(argv[1]);
        if(i==1){
                if(i==1 && argc==3){
                        //printf("\nARGC=%d\n",argc);
                        struct sys_xintegrity sys;
                        sys.flag='1';
                        char *temp=malloc(sizeof(char)* 256);
                        strcpy(temp, argv[2]);
                        sys.filename=temp;
                        sys.ilen=16;
                        char *buf=malloc(sizeof(char)*(sys.ilen));
                        sys.ibuf=(unsigned char *)buf;

                        //printf("%s",sys.filename);
                        rc=syscall(__NR_xintegrity,(void *) &sys);
                        for(i=0; i < 16; i++)
                        printf("%02x",sys.ibuf[i]& 0xFF);

                //printf("IBUF is %s",sys.ibuf);
                        if(rc == 0)
                                printf("\nsyscall returned %d\n",rc);
                        else
                                printf("\nsyscall returned %d (errno=%d)\n",rc,errno);
                        free(temp);
                        free(buf);
                        exit(rc);
                }
                else{
                        printf("\nInvalid number of arguments for mode1\n");
            }

        }

        if(i==2){
                if(i==2&& argc==4){
                        struct sys_xintegrity sys;
                        sys.flag='2';
                        char *temp=malloc(sizeof(char)*256);
                        strcpy(temp,argv[2]);
                        sys.filename=temp;
                        sys.ilen=16;
                        char *buf=malloc(sizeof(char)*(sys.ilen));
                        sys.ibuf=(unsigned char *)buf;
                        sys.clen=strlen(argv[3])+1;
                        //printf("\nCREDBUF STRING Length=%d\n",strlen(argv[3]));
                        char *temp1=malloc(sizeof(char)*(sys.clen));
                        strcpy(temp1,argv[3]);
                        //sys.credbuf=(unsigned char *)malloc(sizeof(char)*(sys.clen));
                        sys.credbuf=(unsigned char *)temp1;
                        rc = syscall(__NR_xintegrity, (void *) &sys);

                        for(i=0; i < 16; i++)
                                printf("%02x",sys.ibuf[i]& 0xFF);
                        if (rc >= 0){
                                   //for(i=0; i < 16; i++)
                                //      printf("%02x",sys.ibuf[i]& 0xFF);

                                printf("\nsyscall returned %d\n", rc);
                        }
                        else
                                printf("\nsyscall returned %d (errno=%d)\n", rc, errno);
                        //free(sys.ibuf);
                        //free(sys.credbuf);
                        //printf("\nCREDBUF=%s",sys.credbuf);
                        free(temp);
                        free(buf);
                        free(temp1);
                        exit(rc);
                }

                else
                                     printf("\nInvalid number of arguments\n");
        }
        if(i==3){
                if(i==3&& argc==3){
                        struct sys_xintegrity sys;
                        sys.flag='3';
                        char *temp=malloc(sizeof(char)*256);
                        strcpy(temp,argv[2]);
                        sys.filename=temp;
                        sys.oflag= O_CREAT;
                        sys.ilen=16;
                        char *buf=malloc(sizeof(char)*(sys.ilen));
                        sys.ibuf=(unsigned char *)buf;
                        sys.mode = S_IRWXU;
                        rc=syscall(__NR_xintegrity,(void *) &sys);
                        // for(i=0; i < 16; i++)
                //      printf("%02x",sys.ibuf[i]& 0xFF);

                        if(rc>=0)
                                printf("\nsyscall returned %d\n",rc);
                        else
                                printf("\nsyscall returned %d (errno=%d)\n",rc,errno);
                        free(temp);
                        free(buf);
                        exit(rc);
                }
        }
return 0;
}
