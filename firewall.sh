#!/bin/bash

IPT="/sbin/iptables"
# the interface which connect to the the internet, 
# it differs if you use wifi or other network device
ITF=eth0    
LIP="11.22.33.44"    # local IP, check yours IP to modify this

# shortcut of state, we build stateful-firewall
EED="-m state --state ESTABLISHED"
NEW="-m state --state NEW"
NED="-m state --state NEW,ESTABLISHED"
RED="-m state --state RELEATED,ESTABLISHED"

# allow dns 
DNS="8.8.8.8
8.8.4.4"

# bogus filter, it shouldn't appear in outside network
# and you can add yours blacklist here
BADIP="0.0.0.0/8
10.0.0.0/8
127.0.0.0/8
172.16.0.0/16
192.168.0.0/16
224.0.0.0/3"

# flush all current rules from iptables
$IPT -F

# allow local loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT ! -i lo -s 127.0.0.1/8 -j DROP
$IPT -A OUTPUT -o lo -j ACCEPT

# allow ping out, icmp echo-reply and fragment request, drop others to defend ICMP SMURF ATTACKS
$IPT -A INPUT -i $ITF -p icmp --icmp-type 0 -m limit --limit 2/s $RED -j ACCEPT
$IPT -A INPUT -i $ITF -p icmp --icmp-type fragmentation-needed $NEW -j ACCEPT
$IPT -A OUTPUT -o $ITF -p icmp $NED -j ACCEPT 

# drop bad ip
for ip in $BADIP
    do
        $IPT -A INPUT -i $ITF -s $ip -j DROP
        $IPT -A OUTPUT -o $ITF -d $ip -j DROP
    done

# check tcp syn to defend syn-flood attack
$IPT -A INPUT -i $ITF -p tcp ! --syn $NEW -j DROP

# check tcp fragments which are invalid, then drop them 
$IPT -A INPUT -i $ITF -p tcp -f -j DROP

# DROP ALL INVALID PACKETS
$IPT -A INPUT -i $ITF -m state --state INVALID -j DROP
$IPT -A FORWARD -i $ITF -m state --state INVALID -j DROP
$IPT -A OUTPUT -i $ITF -m state --state INVALID -j DROP

# portscan filter
$IPT -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,PSH,URG -j DROP

# string filter and log them
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/sh" -j LOG --log-prefix "bin/sh filterd" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/sh" -j DROP
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/bash" -j LOG --log-prefix "bin/bash filterd" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/bash" -j DROP
$IPT -A INPUT -i $ITF -m string --algo bm --string "tftp" -j LOG --log-prefix "tftp filterd" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "tftp" -j DROP

# allow dns
for ip in $DNS
    do
        $IPT -A INPUT -i $ITF -p udp -s $ip --sport 53 -d $LIP $EED -j ACCEPT
        $IPT -A OUTPUT -o $ITF -p udp -s $LIP -d $ip --dport 123 $NED -j ACCEPT
    done

# allow ntp
$IPT -A INPUT -i $ITF -p udp --sport 123 -d $LIP $EED -j ACCEPT
$IPT -A OUTPUT -o $ITF -p udp -s $LIP --dport 123 $NED -j ACCEPT

# if you need open others udp ports, add these above this line
# drop all else udp and log them
$IPT -A INPUT -i $ITF -p udp -j LOG --log-prefix "IN_UDP droped" --log-level 7
$IPT -A INPUT -i $ITF -p udp -j DROP
$IPT -A INPUT -i $ITF -p udp -j LOG --log-prefix "OUT_UDP droped" --log-level 7
$IPT -A OUTPUT -o $ITF -p udp -j DROP

# allow ssh, http and https
$IPT -A INPUT -i $ITF -p tcp --sport 22,80,443 -d $LIP $EED -j ACCEPT
$IPT -A OUTPUT -o $ITF -p tcp -s $LIP --dport 22,80,443 $NED -j ACCEPT

# if you need open others tcp ports, add these above this line
# drop all else and log them
$IPT -A INPUT -j LOG --log-prefix "IPT_droped" --log-level 7
$IPT -A FORWARD -j LOG --log-prefix "FWD_droped" --log-level 7
$IPT -A OUTPUT -j LOG --log-prefix "OUT_droped" --log-level 7
$IPT -A INPUT -j DROP
$IPT -A FORWARD -j DROP
$IPT -A OUTPUT -j DROP

