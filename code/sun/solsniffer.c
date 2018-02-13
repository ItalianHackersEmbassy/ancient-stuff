/* solsniffer.c - v1.10 - Michael R. Widner (atreus, J.Galt)
 *
 * This is sunsniffer.c modified to run on dlpi systems, notably
 * solaris 2.x.  The additions are rather verbose, but I'm really
 * too damn lazy to bother cleaning it up.

 * 4/26/94 - initial code.  Had some serious hacks in the bufmod stuff.
 * 4/28/94 - v 1.0 fixed up the bufmod stuff a little, but still wrong.
 * 8/11/94 - v 1.1 ok, bufmod fixed.  No more packet dropping.
 *           Also fixed/added some command line options.
 *           -sflt to filter smtp, ftp, login and telnet respectively.
 *           -d x  to set data limit; good for catching mail and stuff
 *            going through firewalls.  Like luser on my subnet does
 *            telnet firewall.myorg.com, then from there does
 *            telnet someplace.outside.mynet
 *
 * Uploaded by: an112467@anon.penet.fi
 */

#include	<sys/stream.h>
#include	<sys/dlpi.h>
#include	<sys/bufmod.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
 
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stropts.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
 
#include <net/if.h>
#include <net/if_arp.h>
 
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
 
#include <netdb.h>
#include <arpa/inet.h>
 
/* #define		MAXDLBUF	8192  /* this is much too low -mrw */
#define		MAXDLBUF	32768 /* This is much bigger than any packet */
#define		MAXWAIT		15
#define		MAXDLADDR	1024

/* workaround for bcopy, etc. */
#define bcopy(s1, s2, len) memcpy(s2, s1, len)
#define index(s, c) strchr(s, c)
#define rindex(s, c) strrchr(s, c)
#define bzero(s, len) memset(s, 0, len)
#define bcmp(s1, s2, len) (memcmp(s1, s2, len)!=0)
/*
 * externs go here
 */
extern	void	sigalrm();
#define ERR stderr
 
char    *malloc();
char    *device,
        *ProgName,
        *LogName;
FILE    *LOG;
int     debug=0;
long	databuf[MAXDLBUF];
 
#define NIT_DEV     "/dev/le"
#define CHUNKSIZE   4096        /* device buffer size */
int     if_fd = -1;
int     Packet[CHUNKSIZE+32];

/* More ugly global stuff. */
int	promisc = 1;	/* promiscuous mode "on" by default */
int	bufmod = 0;		/* push buffer module, "off" by default */
int	filter_flags=0;	/* connections we'd like to fileter */
#define FILT_TELNET  1
#define FILT_FTP     2
#define FILT_LOGIN   4
#define FILT_SMTP    8
int	maxbuflen=128;	/* Define a new DATA LIMIT. Still max at MAXBUFLEN */
 
void Pexit(err,msg)
int err; char *msg;
{ perror(msg);
  exit(err); }
 
void Zexit(err,msg)
int err; char *msg;
{ fprintf(ERR,msg);
  exit(err); }
 
#define IP          ((struct ip *)Packet)
#define IP_OFFSET   (0x1FFF)
#define SZETH       (sizeof(struct ether_header))
#define IPLEN       (ntohs(ip->ip_len))
#define IPHLEN      (ip->ip_hl)
#define TCPOFF      (tcph->th_off)
#define IPS         (ip->ip_src)
#define IPD         (ip->ip_dst)
#define TCPS        (tcph->th_sport)
#define TCPD        (tcph->th_dport)
#define IPeq(s,t)   ((s).s_addr == (t).s_addr)
 
#define TCPFL(FLAGS) (tcph->th_flags & (FLAGS))

/* I cranked this up.  reduce it if you run out of mem. -mrw */ 
#define MAXBUFLEN  (8192)
time_t  LastTIME = 0;
 
struct CREC {
     struct CREC *Next,
                 *Last;
     time_t  Time;              /* start time */
     struct in_addr SRCip,
                    DSTip;
     u_int   SRCport,           /* src/dst ports */
             DSTport;
     u_char  Data[MAXBUFLEN+2]; /* important stuff :-) */
     u_int   Length;            /* current data length */
     u_int   PKcnt;             /* # pkts */
     u_long  LASTseq;
};
 
struct CREC *CLroot = NULL;
 
char *Symaddr(ip)
struct in_addr ip;
{ struct hostent *he =
      gethostbyaddr((char *)&ip.s_addr, sizeof(struct in_addr),AF_INET);
 
  return( (he)?(he->h_name):(inet_ntoa(ip)) );
}
 
char *TCPflags(flgs)
register u_char flgs;
{ static char iobuf[8];
#define SFL(P,THF,C) iobuf[P]=((flgs & THF)?C:'-')
 
  SFL(0,TH_FIN, 'F');
  SFL(1,TH_SYN, 'S');
  SFL(2,TH_RST, 'R');
  SFL(3,TH_PUSH,'P');
  SFL(4,TH_ACK, 'A');
  SFL(5,TH_URG, 'U');
  iobuf[6]=0;
  return(iobuf);
}
 
char *SERVp(port)
register u_int port;
{ static char buf[10];
  register char *p;
 
   switch(port) {
     case IPPORT_LOGINSERVER: p="rlogin"; break;
     case IPPORT_TELNET:      p="telnet"; break;
     case IPPORT_SMTP:        p="smtp"; break;
     case IPPORT_FTP:         p="ftp"; break;
     default: sprintf(buf,"%u",port); p=buf; break;
   }
   return(p);
}
 
char *Ptm(t)
register time_t *t;
{ register char *p = ctime(t);
  p[strlen(p)-6]=0; /* strip " YYYY\n" */
  return(p);
}
 
char *NOWtm()
{ time_t tm;
  time(&tm);
  return( Ptm(&tm) );
}
 
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
 
/* add an item */
#define ADD_NODE(SIP,DIP,SPORT,DPORT,DATA,LEN) { \
  register struct CREC *CLtmp = \
        (struct CREC *)malloc(sizeof(struct CREC)); \
  time( &(CLtmp->Time) ); \
  CLtmp->SRCip.s_addr = SIP.s_addr; \
  CLtmp->DSTip.s_addr = DIP.s_addr; \
  CLtmp->SRCport = SPORT; \
  CLtmp->DSTport = DPORT; \
  CLtmp->Length = MIN(LEN,MAXBUFLEN); \
  bcopy( (u_char *)DATA, (u_char *)CLtmp->Data, CLtmp->Length); \
  CLtmp->PKcnt = 1; \
  CLtmp->Next = CLroot; \
  CLtmp->Last = NULL; \
  CLroot = CLtmp; \
}
 
struct CREC *GET_NODE(Sip,SP,Dip,DP)
struct in_addr Sip,Dip;
register u_int SP,DP;
{ struct CREC *CLr = CLroot;
 
  while(CLr != NULL) {
    if( (CLr->SRCport == SP) && (CLr->DSTport == DP) &&
        IPeq(CLr->SRCip,Sip) && IPeq(CLr->DSTip,Dip) )
            break;
    CLr = CLr->Next;
  }
  return(CLr);
}
             
#define ADDDATA_NODE(CL,DATA,LEN) { \
 bcopy((u_char *)DATA, (u_char *)&CL->Data[CL->Length],LEN); \
 CL->Length += LEN; \
}
 
#define PR_DATA(dp,ln) {    \
  register u_char lastc=0; \
  while(ln-- >0) { \
     if(*dp < 32) {  \
        switch(*dp) { \
            case '\0': if((lastc=='\r') || (lastc=='\n') || lastc=='\0') \
                        break; \
            case '\r': \
            case '\n': fprintf(LOG,"\n     : "); \
                        break; \
            default  : fprintf(LOG,"^%c", (*dp + 64)); \
                        break; \
        } \
     } else { \
        if(isprint(*dp)) fputc(*dp,LOG); \
        else fprintf(LOG,"(%d)",*dp); \
     } \
     lastc = *dp++; \
  } \
  fflush(LOG); \
}
 
void END_NODE(CLe,d,dl,msg)
register struct CREC *CLe;
register u_char *d;
register int dl;
register char *msg;
{
   fprintf(LOG,"\n-- TCP/IP LOG -- TM: %s --\n", Ptm(&CLe->Time));
   fprintf(LOG," PATH: %s(%s) =>", Symaddr(CLe->SRCip),SERVp(CLe->SRCport));
   fprintf(LOG," %s(%s)\n", Symaddr(CLe->DSTip),SERVp(CLe->DSTport));
   fprintf(LOG," STAT: %s, %d pkts, %d bytes [%s]\n",
                        NOWtm(),CLe->PKcnt,(CLe->Length+dl),msg);
   fprintf(LOG," DATA: ");
    { register u_int i = CLe->Length;
      register u_char *p = CLe->Data;
      PR_DATA(p,i);
      PR_DATA(d,dl);
    }
 
   fprintf(LOG,"\n-- \n");
   fflush(LOG);
 
   if(CLe->Next != NULL)
    CLe->Next->Last = CLe->Last;
   if(CLe->Last != NULL)
    CLe->Last->Next = CLe->Next;
   else
    CLroot = CLe->Next;
   free(CLe);
}
 
/* 30 mins (x 60 seconds) */
#define IDLE_TIMEOUT 1800
#define IDLE_NODE() { \
  time_t tm; \
  time(&tm); \
  if(LastTIME<tm) { \
     register struct CREC *CLe,*CLt = CLroot; \
     LastTIME=(tm+IDLE_TIMEOUT); tm-=IDLE_TIMEOUT; \
     while(CLe=CLt) { \
       CLt=CLe->Next; \
       if(CLe->Time <tm) \
           END_NODE(CLe,(u_char *)NULL,0,"IDLE TIMEOUT"); \
     } \
  } \
}
 
void filter(cp, pktlen)
register char *cp;
register u_int pktlen;
{
 register struct ip     *ip;
 register struct tcphdr *tcph;
 
 { register u_short EtherType=ntohs(((struct ether_header *)cp)->ether_type);
 
   if(EtherType < 0x600) {
     EtherType = *(u_short *)(cp + SZETH + 6);
     cp+=8; pktlen-=8;
   }
 
   if(EtherType != ETHERTYPE_IP) /* chuk it if its not IP */
      return;
 }
 
    /* ugh, gotta do an alignment :-( */
 bcopy(cp + SZETH, (char *)Packet,(int)(pktlen - SZETH));
 
 ip = (struct ip *)Packet;
 if( ip->ip_p != IPPROTO_TCP) /* chuk non tcp pkts */
    return;
 tcph = (struct tcphdr *)(Packet + IPHLEN);
 
if(!( ((TCPD == IPPORT_TELNET) && !(filter_flags & FILT_TELNET)) ||
       ((TCPD == IPPORT_LOGINSERVER) && !(filter_flags & FILT_LOGIN)) ||
       ((TCPD == IPPORT_FTP) && !(filter_flags & FILT_FTP)) ||
       ((TCPD == IPPORT_SMTP) && !(filter_flags & FILT_SMTP))
   )) return;
 
 { register struct CREC *CLm;
   register int length = ((IPLEN - (IPHLEN * 4)) - (TCPOFF * 4));
   register u_char *p = (u_char *)Packet;
 
   p += ((IPHLEN * 4) + (TCPOFF * 4));
 
 if(debug) {
  fprintf(LOG,"PKT: (%s %04X) ", TCPflags(tcph->th_flags),length);
  fprintf(LOG,"%s[%s] => ", inet_ntoa(IPS),SERVp(TCPS));
  fprintf(LOG,"%s[%s]\n", inet_ntoa(IPD),SERVp(TCPD));
 }
 
   if( CLm = GET_NODE(IPS, TCPS, IPD, TCPD) ) {
 
      CLm->PKcnt++;
 
      if(length>0)
        if( (CLm->Length + length) < maxbuflen ) { /* was MAXBUFLEN */
          ADDDATA_NODE( CLm, p,length);
        } else {
          END_NODE( CLm, p,length, "DATA LIMIT");
        }
 
      if(TCPFL(TH_FIN|TH_RST)) {
          END_NODE( CLm, (u_char *)NULL,0,TCPFL(TH_FIN)?"TH_FIN":"TH_RST" );
      }
 
   } else {
 
      if(TCPFL(TH_SYN)) {
         ADD_NODE(IPS,IPD,TCPS,TCPD,p,length);
      }
 
   }
 
   IDLE_NODE();
 
 }
 
}
 
/* signal handler
 */
void death()
{ register struct CREC *CLe;
 
    while(CLe=CLroot)
        END_NODE( CLe, (u_char *)NULL,0, "SIGNAL");
 
    fprintf(LOG,"\nLog ended at => %s\n",NOWtm());
    fflush(LOG);
    if(LOG != stdout)
        fclose(LOG);
    exit(1);
}
 
/* opens network interface, performs ioctls and reads from it,
 * passing data to filter function
 */


err(fmt, a1, a2, a3, a4)
char	*fmt;
char	*a1, *a2, *a3, *a4;
{
	(void) fprintf(stderr, fmt, a1, a2, a3, a4);
	(void) fprintf(stderr, "\n");
	(void) exit(1);
}

static void
sigalrm()
{
	(void) err("sigalrm:  TIMEOUT");
}

strgetmsg(fd, ctlp, datap, flagsp, caller)
int	fd;
struct	strbuf	*ctlp, *datap;
int	*flagsp;
char	*caller;
{
	int	rc;
	static	char	errmsg[80];

	/*
	 * Start timer.
	 */
	(void) signal(SIGALRM, sigalrm);
	if (alarm(MAXWAIT) < 0) {
		(void) sprintf(errmsg, "%s:  alarm", caller);
		syserr(errmsg);
	}

	/*
	 * Set flags argument and issue getmsg().
	 */
	*flagsp = 0;
	if ((rc = getmsg(fd, ctlp, datap, flagsp)) < 0) {
		(void) sprintf(errmsg, "%s:  getmsg", caller);
		syserr(errmsg);
	}

	/*
	 * Stop timer.
	 */
	if (alarm(0) < 0) {
		(void) sprintf(errmsg, "%s:  alarm", caller);
		syserr(errmsg);
	}

	/*
	 * Check for MOREDATA and/or MORECTL.
	 */
	if ((rc & (MORECTL | MOREDATA)) == (MORECTL | MOREDATA))
		err("%s:  MORECTL|MOREDATA", caller);
	if (rc & MORECTL)
		err("%s:  MORECTL", caller);
	if (rc & MOREDATA)
		err("%s:  MOREDATA", caller);

	/*
	 * Check for at least sizeof (long) control data portion.
	 */
	if (ctlp->len < sizeof (long))
		err("getmsg:  control portion length < sizeof (long):  %d", ctlp->len);
}

expecting(prim, dlp)
int	prim;
union	DL_primitives	*dlp;
{
	if (dlp->dl_primitive != (u_long)prim) {
		err("unexpected dlprim error\n");
		exit(1);
	}
}
strioctl(fd, cmd, timout, len, dp)
int	fd;
int	cmd;
int	timout;
int	len;
char	*dp;
{
	struct	strioctl	sioc;
	int	rc;

	sioc.ic_cmd = cmd;
	sioc.ic_timout = timout;
	sioc.ic_len = len;
	sioc.ic_dp = dp;
	rc = ioctl(fd, I_STR, &sioc);

	if (rc < 0)
		return (rc);
	else
		return (sioc.ic_len);
}
dlattachreq(fd, ppa)
int	fd;
u_long	ppa;
{
	dl_attach_req_t	attach_req;
	struct	strbuf	ctl;
	int	flags;

	attach_req.dl_primitive = DL_ATTACH_REQ;
	attach_req.dl_ppa = ppa;

	ctl.maxlen = 0;
	ctl.len = sizeof (attach_req);
	ctl.buf = (char *) &attach_req;

	flags = 0;

	if (putmsg(fd, &ctl, (struct strbuf*) NULL, flags) < 0)
		syserr("dlattachreq:  putmsg");
}

dlokack(fd, bufp)
int	fd;
char	*bufp;
{
	union	DL_primitives	*dlp;
	struct	strbuf	ctl;
	int	flags;

	ctl.maxlen = MAXDLBUF;
	ctl.len = 0;
	ctl.buf = bufp;

	strgetmsg(fd, &ctl, (struct strbuf*)NULL, &flags, "dlokack");

	dlp = (union DL_primitives *) ctl.buf;

	expecting(DL_OK_ACK, dlp);

	if (ctl.len < sizeof (dl_ok_ack_t))
		err("dlokack:  response ctl.len too short:  %d", ctl.len);

	if (flags != RS_HIPRI)
		err("dlokack:  DL_OK_ACK was not M_PCPROTO");

	if (ctl.len < sizeof (dl_ok_ack_t))
		err("dlokack:  short response ctl.len:  %d", ctl.len);
}


dlbindreq(fd, sap, max_conind, service_mode, conn_mgmt, xidtest)
int	fd;
u_long	sap;
u_long	max_conind;
u_long	service_mode;
u_long	conn_mgmt;
u_long	xidtest;
{
	dl_bind_req_t	bind_req;
	struct	strbuf	ctl;
	int	flags;

	bind_req.dl_primitive = DL_BIND_REQ;
	bind_req.dl_sap = sap;
	bind_req.dl_max_conind = max_conind;
	bind_req.dl_service_mode = service_mode;
	bind_req.dl_conn_mgmt = conn_mgmt;
	bind_req.dl_xidtest_flg = xidtest;

	ctl.maxlen = 0;
	ctl.len = sizeof (bind_req);
	ctl.buf = (char *) &bind_req;

	flags = 0;

	if (putmsg(fd, &ctl, (struct strbuf*) NULL, flags) < 0)
		syserr("dlbindreq:  putmsg");
}

dlbindack(fd, bufp)
int	fd;
char	*bufp;
{
	union	DL_primitives	*dlp;
	struct	strbuf	ctl;
	int	flags;

	ctl.maxlen = MAXDLBUF;
	ctl.len = 0;
	ctl.buf = bufp;

	strgetmsg(fd, &ctl, (struct strbuf*)NULL, &flags, "dlbindack");

	dlp = (union DL_primitives *) ctl.buf;

	expecting(DL_BIND_ACK, dlp);

	if (flags != RS_HIPRI)
		err("dlbindack:  DL_OK_ACK was not M_PCPROTO");

	if (ctl.len < sizeof (dl_bind_ack_t))
		err("dlbindack:  short response ctl.len:  %d", ctl.len);
}

dlpromisconreq(fd, level)
int	fd;
u_long	level;
{
	dl_promiscon_req_t	promiscon_req;
	struct	strbuf	ctl;
	int	flags;

	promiscon_req.dl_primitive = DL_PROMISCON_REQ;
	promiscon_req.dl_level = level;

	ctl.maxlen = 0;
	ctl.len = sizeof (promiscon_req);
	ctl.buf = (char *) &promiscon_req;

	flags = 0;

	if (putmsg(fd, &ctl, (struct strbuf*) NULL, flags) < 0)
		syserr("dlpromiscon:  putmsg");

}

syserr(s)
char	*s;
{
	(void) perror(s);
	exit(1);
}


do_it()
{
	long	buf[MAXDLBUF];
	char	*device;
	int	ppa;
	int	fd;
	int	sap;
	struct	strbuf	data;
	int	flags;
	int	i;
	int	c;
	int	offset;
	int	len;
	struct	timeval	t;
	u_int	chunksize = 16 * 1024;
	struct	sb_hdr	*bp;
	char	*p, *limp;

	int mrwtmp; /* temporary debugging crap */

	device = "/dev/le";
	ppa = 0;
	sap= 0x800;

	/*
	 * Open the device.
	 */
	if ((fd = open(device, 2)) < 0)
		syserr(device);

	/*
	 * Attach.
	 */
	dlattachreq(fd, ppa);
	dlokack(fd, buf);

	/*
	 * Optionally enable promiscuous mode.
	 */
	if (promisc) {
		dlpromisconreq(fd, DL_PROMISC_PHYS);
		dlokack(fd, buf);
	}

	/*
	 * Bind.
	 */
	dlbindreq(fd, sap, 0, DL_CLDLS, 0, 0);
	dlbindack(fd, buf);

	/*
	 * Issue DLIOCRAW ioctl.
	 */
	if (strioctl(fd, DLIOCRAW, -1, 0, NULL) < 0)
		syserr("DLIOCRAW");

	/*
	 * Push and configure buffer module.
	 */
	if (bufmod) {
		if (ioctl(fd, I_PUSH, "bufmod") < 0)
			syserr("push bufmod");

		t.tv_sec = 0;
		t.tv_usec = 500000;	/* 0.5s */
		if (strioctl(fd, SBIOCSTIME, -1, sizeof (struct timeval),
			&t) < 0)
			syserr("SBIOCSTIME");
		if (strioctl(fd, SBIOCSCHUNK, -1, sizeof (u_int),
			&chunksize) < 0)
			syserr("SBIOCSCHUNK");
	}

	/*
	 * Flush the read side of the Stream.
	 */
	if (ioctl(fd, I_FLUSH, FLUSHR) < 0)
		syserr("I_FLUSH");

	/*
	 * Read packets.
	 */

	data.buf = (char *) databuf;
	data.maxlen = MAXDLBUF;
	data.len = 0;

	/* Here's the deal:  I had some problems with the bufmod code, but
	   I think it's working now.  I don't know a whole lot about the
	   whole DLPI interface, so I can't be sure there aren't any
	   oversights here.  It seems to be working now, but I have not had
	   the time to do extensive testing.
	   I know for certain that packets will be dropped on a busy network
	   if I don't use bufmod.  That problem should not occur when using
	   bufmod, but like I said, I may have overlooked something. */

	while (((mrwtmp=getmsg(fd, NULL, &data, &flags))==0) ||
		 (mrwtmp==MOREDATA) || (mrwtmp=MORECTL)) {
		p = data.buf;
		limp = p + data.len;

	/* This is the ugliest piece of commented out crap that I've ever
	   done.  Ignore it.  Someday it will go away. */
	/*	if (data.len && bufmod) {
			for (; p < limp; p += bp->sbh_totlen) {
				bp = (struct sb_hdr*) p; 
				/* Display hex data if we want * /
 				for (i = 0; i < bp->sbh_msglen; i++)
					printf("%02x ", *(p +
						sizeof (struct sb_hdr) + i)
						& 0xff);
				printf("\n"); 
				filter(p, bp->sbh_msglen);
			} 
		} else if (data.len) { */
			filter(data.buf, data.len); 
		/*	}  else if */
		data.len = 0;
	} /* while */
	printf("finished getmsg() = %i\n",mrwtmp);
}


/* Authorization, if you'd like it. */
#define AUTHPASSWD "c6Lqd3Dvn2l3s" 
 
void getauth()
{ char *buf,*getpass(),*crypt();
  char pwd[21],prmpt[81];
 
    strcpy(pwd,AUTHPASSWD);
    sprintf(prmpt,"(%s)UP? ",ProgName);
    buf=getpass(prmpt);
    if(strcmp(pwd,crypt(buf,pwd)))
        exit(1);
}
     
void main(argc, argv)
int argc;
char **argv;
{
    char   cbuf[BUFSIZ];
    struct ifconf ifc;
    int    s,
           ac=1,
           backg=0;
 
    ProgName=argv[0];
 
/*    getauth(); */
/* I put this here for a reason, but now I'm commenting it out. */
/*    if(!(LOG=fopen((LogName=".tfile"),"a")))
         Zexit(1,"Output file cant be opened\n"); */

/* Its still called NIT_DEV, even if it's no longer /dev/nit */
    device=NIT_DEV; 
    while((ac<argc) && (argv[ac][0] == '-')) {
       register char ch = argv[ac++][1];
       switch(toupper(ch)) {
            case 'I': device=argv[ac++];
                      break;
            case 'O': if(!(LOG=fopen((LogName=argv[ac++]),"a")))
                         Zexit(1,"Output file cant be opened\n");
                      break;
            case 'B': backg=1;
                      break;
            case 'S': filter_flags|=FILT_SMTP;
		      fprintf(ERR,"filtering out smtp connections.\n");
                      break;
            case 'T': filter_flags|=FILT_TELNET;
		      fprintf(ERR,"filtering out telnet connections.\n");
                      break;
            case 'L': filter_flags|=FILT_LOGIN;
		      fprintf(ERR,"filtering out rsh/rlogin connections.\n");
                      break;
            case 'F': filter_flags|=FILT_FTP;
		      fprintf(ERR,"filtering out ftp connections.\n");
                      break; 
            case 'D': maxbuflen=atoi(argv[ac++]);
		      if (maxbuflen > MAXBUFLEN) maxbuflen=MAXBUFLEN;
                      break;
            default : fprintf(ERR,
                        "Usage: %s [-d x] [-s] [-f] [-l] [-t] [-i interface] [-o file]\n",
                            ProgName);
		fprintf(ERR,"	-d int    set new data limit (128 default)\n");
		fprintf(ERR,"	-s        filter out smtp connections\n");
		fprintf(ERR,"	-f        filter out ftp connections\n");
		fprintf(ERR,"	-l        filter out rlogin/rsh connections\n");
		fprintf(ERR,"	-t        filter out telnet connections\n");
		fprintf(ERR,"	-o <file> output to <file>\n");
                      exit(1);
       }
    }

    fprintf(ERR,"Using logical device %s [%s]\n",device,NIT_DEV);
    fprintf(ERR,"Output to %s.%s%s",(LOG)?LogName:"stdout",
            (debug)?" (debug)":"",(backg)?" Backgrounding ":"\n");
 
    if(!LOG)
        LOG=stdout;
 
    signal(SIGINT, death);
    signal(SIGTERM,death);
    signal(SIGKILL,death);
    signal(SIGQUIT,death);
 
    if(backg && debug) {
         fprintf(ERR,"[Cannot bg with debug on]\n");
         backg=0;
    }

    fprintf(LOG,"\nLog started at => %s [pid %d]\n",NOWtm(),getpid());
    fflush(LOG);
 
    do_it();
}
 
