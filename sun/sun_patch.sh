#!/bin/sh
#
# Protect SPARC stack against unwanted exec access
# Side effect: growth in data segment also loses exec bit.
# This may break some programs.
#
# Install as:
#       /etc/init.d/protect_stack
#       ln /etc/init.d/protect_stack /etc/rc2.d/S07protect_stack
#
# And all programs except init are protected after the next reboot.
#
# After installing the scripts, first test with:
#
#       /etc/init.d/protect_stack start
#
#    Then start a new shell and test changes with /usr/proc/bin/pmap.
#
#       csh -fi
#       % pmap $$
#       ......
#       00047000   56K read/write               - instead of rwx
#       0004D000   32K     [ heap ]
#       ......
#       EFFFC000    8K read/write               - instead of rwx
#       EFFFC000   16K     [ stack ]
#       EFFFE000    8K read/write
#
#
# Seems to work on 2.4/2.5/2.5.1 but this may vary by patchlevel.
# Not all Sun MMUs support this, but it seems to haev effect on sun4m and
# sun4u, probably won't have an effect on sun4c.
#
# The assembly checking may need tweaking depending on OS level and
# patchlevel.
#
# Casper Dik (Casper.Dik@Holland.Sun.COM)
#
# The contents of this file  are intended to  be read as
# an example.  This  is not  a  supported product of Sun
# Microsystems  and  no hotline calls  will  be accepted
# which directly relate to this information.
#
# NO LIABILITY WILL BE  ACCEPTED BY SUN MICROSYSTEMS FOR
# ANY LOSS (DIRECT OR CONSEQUENTIAL) INCURRED IN ANY WAY
# BY ANY PARTY THROUGH THE USE OF THIS INFORMATION.
#
# NO WARRANTY  OF  ANY SORT  IS IMPLIED OR GIVEN FOR ANY
# CODE DERIVED FROM THIS INFORMATION.

PATH=/usr/bin:$PATH

#
#
# Set/get values using adb.
#
getvalue ()
{
    echo $1/$2 | adb -k /dev/ksyms /dev/mem | awk  "\"$1:\""' == $1 {print $2}'
}
setvalue ()
{
    echo $1/$2$3 | adb -wk /dev/ksyms /dev/mem >/dev/null 2>&1
}

#
# Check whether setting/unsetting is not dangerous.
#

check ()
{
    map=`getvalue $mapaddr X`
    zfod=`getvalue $zfodaddr x`
    if [ "$map" = "$oldmap" -a "$zfod" = "$oldzfod" ]
    then
        old=true;
    else
        old=false
    fi
    if [ "$map" = "$newmap" -a "$zfod" = "$newzfod" ]
    then
        new=true
    else
        new=false
    fi
}


p=`basename $0`
zfodaddr=zfod_segvn_crargs+0xd
case "`uname -p`" in
sparc)

        #
        # Instruction should at $mapaddr should be: mov 0xf,%reg or mov 0xb,%reg
        # this is a synthetic instruction that encodes as or %g0,0xf,$reg
        # 10rr rrr0 0001 0000 0010 0000 0000 1x11
        #
        # Try and find it at several locations.  Addresses must be specified
        # the way adb prints them.
        #
        for mapaddr in map_hunk+8 map_hunk+0xc
        do
            mapval=`getvalue $mapaddr X`
            case $mapval in
            [9ab][02468ace]10200[bf])
                reg=`expr $mapval : '\(..\)'`
                break;;
            esac
        done
        if [ -z "$reg" ]
        then
            echo "${p}: Instruction doesn't match" 1>&2
            exit 1
        fi

        echo "${p}: Instruction prefix set to $reg ($mapval@$mapaddr)"

        oldmap=${reg}10200f
        newmap=${reg}10200b
        oldzfod=f0f
        newzfod=b0f

;;
i386)
        # Try and find it at several locations.  Addresses must be specified
        # the way adb prints them.
        #
        for mapaddr in map_hunk+0x19
        do
            mapval=`getvalue $mapaddr X`
            case $mapval in
            [bf]f545c6)
                reg=true
                break;;
            esac
        done
        if [ -z "$reg" ]
        then
            echo "${p}: Instruction doesn't match" 1>&2
            exit
        fi
        oldmap=ff545c6
        newmap=bf545c6
        oldzfod=f0f
        newzfod=f0b

;;
*)
        echo "Unknown kernel arch"
        exit 1
;;
esac

case "$1" in
start)
    check
    if $new
    then
        echo "${p}: Stack already protected" 1>&2
        exit 0
    fi
    if $old
    then
        setvalue $mapaddr W $newmap
        setvalue $zfodaddr w $newzfod
        echo "${p}: Stack protected"
    else
        echo "${p}: Kernel value mismatch $map != $oldmap or $zfod != $oldzfod" 1>&2
        exit 1
    fi
    ;;
stop)
    check
    if $old
    then
        echo "${p}: Stack already unprotected" 1>&2
        exit 0
    fi
    if $new
    then
        setvalue $mapaddr W $oldmap
        setvalue $zfodaddr w $oldzfod
        echo "${p}: Stack no longer protected"
    else
        echo "${p}: Kernel value mismatch $map != $newmap or $zfod != $newzfod" 1>&2
        exit 1
    fi
    ;;
*)
    echo "Usage: ${p} [start|stop]" 1>&2
    exit 1;;
esac

