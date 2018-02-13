/*
 * overflow_wrapper.c -- wrap programs to prevent command line argument
 *                  buffer overrun vulnerabilities
 *
 *      This wrapper is designed to limit exploitation of programs which have 
 *      command line argument buffer overflow vulnerabilities.
 *	
 *	The vulnerable program is replaced by this wrapper.  The original
 *	vulnerable program being moved to another location and its
 *	permissions restricted.  This wrapper checks each argument's length
 *	to ensure it doesn't exceed a given length before executing
 *	the original program.
 *	
 *      The latest version of this wrapper is available from:
 *      
 *      ftp://ftp.auscert.org.au/pub/auscert/tools/overflow/overflow_wrapper.c
 *
 *
 *	The MD5 checksum for this file can be retrieved from:
 *
 *	ftp://ftp.auscert.org.au/pub/auscert/tools/overflow/CHECKSUM
 *
 *
 *      This program is designed to be an interim relief measure 
 *      until official vendor patches are made available.
 *
 *
 * Author:      AUSCERT
 *              Prentice Centre
 *              Qld.  4072.
 *              Australia.
 *
 *              auscert@auscert.org.au
 *
 * DISCLAIMER:  The use of this program is at your own risk.  It is
 *              designed to combat a particular vulnerability, and may
 *              not combat other vulnerabilities, either past or future.
 *              The decision to use this program is yours, as are the
 *              consequences of its use.
 *
 *              This program is designed to be an interim relief measure
 *              until appropriate patches can be obtained from your vendor.
 *
 * REVISION:
 *
 * V 1.1        13 May 1997 - Changed syslog option to log correctly under 
 *                            Solaris 2.x.
 *
 *
 * Installation instructions
 * ~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  1.  su to root
 *
 *  2.  Determine the location of the program you wish to protect.
 *
 *      For example purposes, we'll assume the program we wish to wrap is
 *      /usr/bin/vul_prog.
 *
 *  3.  Determine the permissions, owner, and group of vul_prog.  Note this
 *      information as it will be used later.  For example:
 *
 *          # ls -l /usr/bin/vul_prog
 *          -r-sr-xr-x  1 root  bin  20480 Jul 17 12:30 /usr/bin/vul_prog
 *
 *      In particular, note whether the program is setuid or setgid.
 *
 *  4.  Copy the vul_prog program to vul_prog.real, and then restrict
 *      its permissions.
 *
 *              # cd /usr/bin
 *              # cp vul_prog vul_prog.real
 *              # chmod 511 vul_prog.real
 *
 *  5.  Note the location of vul_prog.real.  This will be used 
 *      as the definition of REAL_PROG when compiling this wrapper.
 *      This should be an absolute pathname.  In this example,
 *	"/usr/bin/vul_prog.real"
 *
 *  6.  Compile this program in a non world writable directory other than 
 *      /usr/bin.
 *
 *      For example, to use /usr/local/src, first copy this file to
 *      /usr/local/src.  
 *
 *              # cd /usr/local/src
 *
 *      There are two defines required to compile this program:
 *
 *      REAL_PROG:  This is the location noted in step #5.
 *
 *      For this example, REAL_PROG is "/usr/bin/vul_prog.real"
 *
 *	MAXARGLEN:  This wrapper will exit without executing REAL_PROG
 *      when given any command line arguments which exceed MAXARGLEN in
 *      length.
 *
 *      This will need to be adjusted depending on the program being
 *      wrapped.  It should be made as small as possible while still
 *      allowing the program to function correctly.  If you are compiling
 *      this program as part of an AUSCERT advisory workaround, the
 *      advisory will list a suggested MAXARGLEN.
 *
 *      For this example, we'll set MAXARGLEN to 16.
 *
 *      Once you have the values of REAL_PROG and MAXARGLEN you can
 *      compile this program.
 *
 *              # cc -DREAL_PROG='"/usr/bin/vul_prog.real"' -DMAXARGLEN=16 \ 
 *                      -o vul_prog_wrapper overflow_wrapper-1.1.c
 *
 *      If you wish error messages to be logged by syslog when
 *      arguments that may exploit the buffer overrun vulnerability 
 *      are passed to vul_prog, add -DSYSLOG to the compile time options.
 *
 *              # cc -DREAL_PROG='"/usr/bin/vul_prog.real"' -DMAXARGLEN=16 \
 *                       -DSYSLOG -o vul_prog_wrapper overflow_wrapper-1.1.c
 *
 *      Note that when compiling the value of REAL_PROG needs to be enclosed 
 *      in single quotes (') as shown above.
 *
 *      If you get any messages about REAL_PROG or MAXARGLEN 
 *      being undefined ensure that the cc command you are using sets
 *      these values (similar to the example commands shown above).
 *
 *  7.  Copy this new wrapper program, vul_prog_wrapper,  into the directory 
 *      originally containing vul_prog.  This will replace the existing 
 *      vul_prog program.
 *
 *      Make sure this directory and its parent directories are protected so
 *      only root is able to make changes to files in the directory.
 *
 *      Use the information found in step #3 and set the same 
 *      owner, group, permissions and privileges on the new vul_prog program.  
 *
 *      For example:
 *
 *              # cp vul_prog_wrapper /usr/bin/vul_prog
 *              # cd /usr/bin
 *              # chown root vul_prog
 *              # chgrp bin vul_prog
 *              # chmod 4555 vul_prog
 *
 *      Check that the owner, group, permissions and privileges exactly
 *      match those noted in step #3.
 *
 *              # ls -l /usr/bin/vul_prog
 *
 *      Users will not be able to use the vul_prog program during the time 
 *      when the wrapper is copied into place until the chmod command 
 *      has been executed.
 *
 * 8.   Check that vul_prog still works!
 *
 */

static char     Version[] = "overflow_wrapper-1.1 V1.1 13-May-1997";


#include <stdio.h>
#include <syslog.h>

/*
 * This wrapper will exit without executing REAL_PROG when
 * given any command line arguments which exceed MAXARGLEN in length.  
 */

main(argc,argv,envp)
int     argc;
char    *argv[];
char    *envp[];
{
        int     i;
        
        for (i=0; i<argc; i++)
        {
                if (strlen(argv[i]) > MAXARGLEN)
                {
                        fprintf(stderr,"You have exceeded the argument length ...Exiting\n");
#ifdef SYSLOG
                        syslog(LOG_DAEMON|LOG_ERR,"%.32s: possible buffer overrun attack by uid %d\n", argv[0], getuid());
#endif

                        exit(1);
                }
        }
        execve(REAL_PROG, argv, envp);
        perror("execve failed");
        exit(1);
}

