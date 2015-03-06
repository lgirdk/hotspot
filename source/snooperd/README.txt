# How to build
gcc dhcpsnooper.c -o dhcpsnooper -lnetfilter_queue

# Setting up iptables
# This setup will capture DHCP Release, Discover, Offer, Request, and ACK (client and server messages)

 iptables -I FORWARD -o br0 -p udp --dport=67 -j NFQUEUE --queue-num 0
 iptables -I FORWARD -o br0 -p udp --dport=68 -j NFQUEUE --queue-num 0

# This setup will capture DHCP Release, Discover, and Request (Just client messages)

iptables -I FORWARD -o br0 -p udp --dport=67 -j NFQUEUE --queue-num 0


# Wireshark capture filter
# This filters on a specific MAC address. The first value is where to start the seconds value
# is how many bytes which can be either 1, 2, or 4. 

(port 67 or port 68) and ((ether[8:4]==0xdb948895) or (ether[2:4]==0xdb948895))

# Remember when capturing packets if you want to see the GRE encapsulation then capture the
# tunnel interface (e.g. eth0). If you want to capture the inner packet then capture on the
# GRE device (e.g. gretap).
