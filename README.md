# TCPDUMP


## README

Tcpdump is one of the best network analysis-tools ever for information security professionals. 
Tcpdump is for everyone for hackers and people who have less of TCP/IP understanding. 

Many prefer to use higher-level analysis tools such Wireshark, _but I believe it is a mistake_. 

## OPTIONS

#### Below are some tcpdump options (with useful examples) that will help you working with the tool. They’re very easy to forget and/or confuse with other types of filters, i.e. ethereal, so hopefully this article can serve as a reference for you, as it does me:)

* The first of these is -n, which requests that names are not resolved, resulting in the IPs themselves.
* The second is -X, which displays both hex and ascii content within the packet.
* The final one is -S, which changes the display of sequence numbers to absolute rather than relative.

### Show the packet’s contents in both hex and ascii.   

    tcpdump -X ....         
      
### Same as -X, but also shows the ethernet header.
  
    tcpdump -XX

###  Show the list of available interfaces

    tcpdump -D

### Line-readable output (for viewing as you save, or sending to other commands)

    tcpdump -l

### Be less verbose (more quiet) with your output.

    tcpdump -q

### Give human-readable timestamp output.

    tcpdump -t :

### Give maximally human-readable timestamp output.

    tcpdump -tttt : 

### Listen on the eth0 interface.

    tcpdump -i eth0

### Verbose output (more v’s gives more output).

    tcpdump -vv 

### Only get x number of packets and then stop.
  
    tcpdump -c 

### Define the snaplength (size) of the capture in bytes. Use -s0 to get everything, unless you are intentionally capturing less.

    tcpdump -s 

### Print absolute sequence numbers.
  
    tcpdump -S 

### Get the ethernet header as well.
    
    tcpdump -e 

### Decrypt IPSEC traffic by providing an encryption key.
    
    tcpdump -E

### For more options, read manual:
* Find all options [here](https://www.cyberciti.biz/howto/question/man/tcpdump-man-page-with-examples.php)

# BASIC USAGE

###  Display Available Interfaces

    tcpdump -D
    tcpdump --list-interfaces

# Basic Commands
    
### Let’s start with a basic command that will get us HTTPS traffic:

    tcpdump -nnSX port 443

### Find Traffic by IP

    tcpdump host 1.1.1.1

### Filtering by Source and/or Destination

    tcpdump src 1.1.1.1 
    tcpdump dst 1.0.0.1

### Finding Packets by Network
    
    tcpdump net 1.2.3.0/24



### Basic communication (very verbose)

* Low - Good amount of traffic, with verbosity and no name help

    tcpdump -nnvvS

* Medium - -We add -X for payload but doesn’t grab any more of the packet

    tcpdump -nnvvXS

* Heavy - The final “s” increases the snaplength, grabbing the whole packet
    tcpdump -nnvvXSs 1514


# Getting Creative

Expressions are very nice, but the real magic of tcpdump comes from the ability to combine them in creative ways in order to isolate exactly what you’re looking for. 

## There are three ways to do combination:

### AND
    and or &&

### OR
    or or ||

### EXCEPT
    not or !

## Example: 

### Traffic that’s from 192.168.1.1 AND destined for ports 3389 or 22
    
    tcpdump 'src 192.168.1.1 and (dst port 3389 or 22)'


# Advanced

### Show me all URG packets:
    
    tcpdump 'tcp[13] & 32 != 0'

### Show me all ACK packets:

    tcpdump 'tcp[13] & 16 != 0'

### Show me all PSH packets:
    
    tcpdump 'tcp[13] & 8 != 0'

### Show me all RST packets:

    tcpdump 'tcp[13] & 4 != 0'

### Show me all SYN packets:

    tcpdump 'tcp[13] & 2 != 0'

### Show me all FIN packets:

    tcpdump 'tcp[13] & 1 != 0'

### Show me all SYN-ACK packets:
    
    tcpdump 'tcp[13] = 18'

### Show all traffic with both SYN and RST flags set: (that should never happen)

    tcpdump 'tcp[13] = 6'

### Show all traffic with the “evil bit” set:

    tcpdump 'ip[6] & 128 != 0'

### Display all IPv6 Traffic:

    tcpdump ip6

### Print Captured Packets in ASCII

    tcpdump -A -i eth0


### Display Captured Packets in HEX and ASCII
    
    tcpdump -XX -i eth0

### Capture and Save Packets in a File

    tcpdump -w 0001.pcap -i eth0

### Read Captured Packets File

    tcpdump -r 0001.pcap

### Capture IP address Packets

    tcpdump -n -i eth0

### Capture only TCP Packets.

    tcpdump -i eth0 tcp

### Capture Packet from Specific Port

    tcpdump -i eth0 port 22

### Capture Packets from source IP
    
    tcpdump -i eth0 src 192.168.0.2

### Capture Packets from destination IP

    tcpdump -i eth0 dst 50.116.66.139

### Capture any packed coming from x.x.x.x

    tcpdump -n src host x.x.x.x

### Capture any packet coming from or going to x.x.x.x
    
    tcpdump -n host x.x.x.x

### Capture any packet going to x.x.x.x

    tcpdump -n dst host x.x.x.x

### Capture any packed coming from x.x.x.x
    
    tcpdump -n src host x.x.x.x

### Capture any packet going to network x.x.x.0/24

    tcpdump -n dst net x.x.x.0/24

### Capture any packet coming from network x.x.x.0/24

    tcpdump -n src net x.x.x.0/24

### Capture any packet with destination port x

    tcpdump -n dst port x

### Capture any packet coming from port x
    
    tcpdump -n src port x

### Capture any packets from or to port range x to y

    tcpdump -n dst(or src) portrange x-y

### Capture any tcp or udp port range x to y

    tcpdump -n tcp(or udp) dst(or src) portrange x-y

### Capture any packets with dst ip x.x.x.x and port y
    
    tcpdump -n "dst host x.x.x.x and dst port y"

### Capture any packets with dst ip x.x.x.x and dst ports x, z

    tcpdump -n "dst host x.x.x.x and (dst port x or dst port z)"

### Capture ICMP , ARP

    tcpdump -v icmp(or arp)

### Capture packets on interface eth0 and dump to cap.txt file

    tcpdump -i eth0 -w cap.txt



### Get Packet Contents with Hex Output

    tcpdump -c 1 -X icmp

### Show Traffic Related to a Specific Port
    
    tcpdump port 3389 
    tcpdump src port 1025

### Show Traffic of One Protocol
    
    tcpdump icmp

### Find Traffic by IP
One of the most common queries, using host, you can see traffic that’s going to or from 1.1.1.1.

    tcpdump host 1.1.1.1

### Filtering by Source and/or Destination
* If you only want to see traffic in one direction or the other, you can use src and dst.

    tcpdump src 1.1.1.1 
    tcpdump dst 1.0.0.1

### Finding Packets by Network
* To find packets going to or from a particular network or subnet, use the net option.
    
    tcpdump net 1.2.3.0/24


### Get Packet Contents with Hex Output
* Hex output is useful when you want to see the content of the packets in question, and it’s often best used when you’re isolating a few candidates for closer scrutiny.
    
    tcpdump -c 1 -X icmp

### Show Traffic Related to a Specific Port
* You can find specific port traffic by using the port option followed by the port number.
    
    tcpdump port 3389 
    tcpdump src port 1025

### Show Traffic of One Protocol
* If you’re looking for one particular kind of traffic, you can use tcp, udp, icmp, and many others as well.

    tcpdump icmp

### Show only IP6 Traffic

    tcpdump ip6

### Find Traffic Using Port Ranges

    tcpdump portrange 21-23

### Find Traffic Based on Packet Size
* If you’re looking for packets of a particular size you can use these options. You can use less, greater, or their associated symbols that you would expect from mathematics.
    
    tcpdump less 32 
    tcpdump greater 64 
    tcpdump <= 128
    tcpdump => 128

### Reading / Writing Captures to a File (pcap)
* It’s often useful to save packet captures into a file for analysis in the future. 
    
    tcpdump port 80 -w capture_file

* You can read PCAP files by using the -r switch. Note that you can use all the regular commands within tcpdump while reading in a file; you’re only limited by the fact that you can’t capture and process what doesn’t exist in the file already.

    tcpdump -r capture_file


# It’s All About the Combinations

### Raw Output View
* Use this combination to see verbose output, with no resolution of hostnames or port numbers, using absolute sequence numbers, and showing human-readable timestamps.

    tcpdump -ttnnvvS

## Here are some examples of combined commands.

### From specific IP and destined for a specific Port
* Let’s find all traffic from 10.5.2.3 going to any host on port 3389.

    tcpdump -nnvvS src 10.5.2.3 and dst port 3389

### From One Network to Another
* Let’s look for all traffic coming from 192.168.x.x and going to the 10.x or 172.16.x.x networks

    tcpdump -nvX src net 192.168.0.0/16 and dst net 10.0.0.0/8 or 172.16.0.0/16

### Non ICMP Traffic Going to a Specific IP
* This will show us all traffic going to 192.168.0.2 that is not ICMP.
    
    tcpdump dst 192.168.0.2 and src net and not icmp

### Traffic From a Host That Isn’t on a Specific Port
* This will show us all traffic from a host that isn’t SSH traffic (assuming default port usage).
    
    tcpdump -vv src mars and not dst port 22

### Isolate TCP Flags
* You can also use filters to isolate packets with specific TCP flags set.

### Isolate TCP RST flags.

    tcpdump 'tcp[13] & 4!=0'
    tcpdump 'tcp[tcpflags] == tcp-rst'

### Isolate TCP SYN flags.

    tcpdump 'tcp[13] & 2!=0'
    tcpdump 'tcp[tcpflags] == tcp-syn'

### Isolate packets that have both the SYN and ACK flags set.

    tcpdump 'tcp[13]=18'

### Isolate TCP URG flags.

    tcpdump 'tcp[13] & 32!=0'
    tcpdump 'tcp[tcpflags] == tcp-urg'

### Isolate TCP ACK flags.

    tcpdump 'tcp[13] & 16!=0'
    tcpdump 'tcp[tcpflags] == tcp-ack'

### Isolate TCP PSH flags.

    tcpdump 'tcp[13] & 8!=0'
    tcpdump 'tcp[tcpflags] == tcp-psh'

### Isolate TCP FIN flags.

    tcpdump 'tcp[13] & 1!=0'
    tcpdump 'tcp[tcpflags] == tcp-fin'

# Commands that I using almost daily

### Both SYN and RST Set

    tcpdump 'tcp[13] = 6'

### Find HTTP User Agents

    tcpdump -vvAls0 | grep 'User-Agent:'
    tcpdump -nn -A -s1500 -l | grep "User-Agent:"

### By using egrep and multiple matches we can get the User Agent and the Host (or any other header) from the request.
    
    tcpdump -nn -A -s1500 -l | egrep -i 'User-Agent:|Host:'

### Capture only HTTP GET and POST packets
* Going deep on the filter we can specify only packets that match GET.
    
    tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

* Alternatively we can select only on POST requests. Note that the POST data may not be included in the packet captured with this filter. It is likely that a POST request will be split across multiple TCP data packets.
    
    tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'

### Extract HTTP Request URL's
    
    tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:"

### Extract HTTP Passwords in POST Requests
    
    tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"

### Capture Cookies from Server and from Client
    
    tcpdump -nn -A -s0 -l | egrep -i 'Set-Cookie|Host:|Cookie:'

### Capture all ICMP packets
* See all ICMP packets on the wire.
    
    tcpdump -n icmp

### Show ICMP Packets that are not ECHO/REPLY (standard ping)
    
    tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'

### Capture SMTP / POP3 Email
* It is possible to extract email body and other data, in this example we are only parsing the email recipients.
    
    tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'

### Troubleshooting NTP Query and Response
* In this example we see the NTP query and response.
    
    tcpdump dst port 123

### Capture FTP Credentials and Commands
    
    tcpdump -nn -v port ftp or ftp-data

### Rotate Capture Files
    
    tcpdump  -w /tmp/capture-%H.pcap -G 3600 -C 200

### Capture IPv6 Traffic
    
    tcpdump -nn ip6 proto 6

### IPv6 with UDP and reading from a previously saved capture file.
    
    tcpdump -nr ipv6-test.pcap ip6 proto 17

### Detect Port Scan in Network Traffic
    
    tcpdump -nn

# USAGE EXAMPLE

### Example Filter Showing Nmap NSE Script Testing
  
* On Target: 

        nmap -p 80 --script=http-enum.nse targetip

* On Server:  

        tcpdump -nn port 80 | grep "GET /"
        
           GET /w3perl/ HTTP/1.1
           GET /w-agora/ HTTP/1.1
           GET /way-board/ HTTP/1.1
           GET /web800fo/ HTTP/1.1
           GET /webaccess/ HTTP/1.1
           GET /webadmin/ HTTP/1.1
           GET /webAdmin/ HTTP/1.1

### Capture Start and End Packets of every non-local host
    
    tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'

### Capture DNS Request and Response
* Outbound DNS request to Google public DNS and the A record (ip address) response can be seen in this capture.
    
    tcpdump -i wlp58s0 -s0 port 53

### Capture HTTP data packets
* Only capture on HTTP data packets on port 80. Avoid capturing the TCP session setup (SYN / FIN / ACK).
    
    tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

### Capture with tcpdump and view in Wireshark
    
    ssh wuseman@localhost 'tcpdump -s0 -c 1000 -nn -w - not port 22' | wireshark -k -i -


Top Hosts by Packets
    
    tcpdump -nnn -t -c 200 | cut -f 1,2,3,4 -d '.' | sort | uniq -c | sort -nr | head -n 20

### Capture all the plaintext passwords
    
    tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '

    tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -lA | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd= |password=|pass:|user:|username:|password:|login:|pass |user '

### DHCP Example

    tcpdump -v -n port 67 or 68

### Cleartext GET Requests

    tcpdump -vvAls0 | grep 'GET'

### Find HTTP Host Headers

    tcpdump -vvAls0 | grep 'Host:'

### Find HTTP Cookies

    tcpdump -vvAls0 | grep 'Set-Cookie|Host:|Cookie:'

### Find SSH Connections
* This one works regardless of what port the connection comes in on, because it’s getting the banner response.
    
    tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D'

### Find DNS Traffic
    
    tcpdump -vvAs0 port 53

### Find FTP Traffic
    
    tcpdump -vvAs0 port ftp or ftp-data

### Find NTP Traffic
    
    tcpdump -vvAs0 port 123

### Capture SMTP / POP3 Email
    tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'

### Line Buffered Mode

    tcpdump -i eth0 -s0 -l port 80 | grep 'Server:'

### Find traffic with evil bit

    tcpdump 'ip[6] & 128 != 0'

### Filter on protocol (ICMP) and protocol-specific fields (ICMP type)
* Capture all ICMP with some exceptions. 
* For example, if a host runs lots of pings (SmokePing for example), it is useful to suppress ICMP echo requests and replies from dumped packets:

    tcpdump -n icmp and 'icmp[0] != 8 and icmp[0] != 0'

### Same command can be used with predefined header field offset (icmptype) and ICMP type field values (icmp-echo and icmp-echoreply):

    tcpdump -n icmp and icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply

### Filter on TOS field
* Capture all IP packets with a non-zero TOS field (one byte TOS field is at offset 1 in IP header):

    tcpdump -v -n ip and ip[1]!=0

### Filter on TTL field
* Capture all IP packets with TTL less than some value (on byte TTL field is at offset 8 in IP header):

    tcpdump -v ip and 'ip[8]<2'

Filter on TCP flags (SYN/ACK)

    tcpdump -n tcp and port 80 and 'tcp[tcpflags] & tcp-syn == tcp-syn'

### In the example above, all packets with TCP SYN flag set are captured. Other flags (ACK, for example) might be set also. Packets which have only TCP SYN flags set, can be captured 

* like this:

    tcpdump tcp and port 80 and 'tcp[tcpflags] == tcp-syn'

### Catch TCP SYN/ACK packets (typically, responses from servers):

    tcpdump -n tcp and 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

* Same thing:

    tcpdump -n tcp and 'tcp[tcpflags] & tcp-syn == tcp-syn' and 'tcp[tcpflags] & tcp-ack == tcp-ack'

### Catch ARP packets

    tcpdump -vv -e -nn ether proto 0x0806

### Filter on IP packet length
* Catch packets of a specified length (IP packet length (16 bits) is located at offset 2 in IP header):

    tcpdump -l icmp and '(ip[2:2]>50)' -w - |tcpdump -r - -v ip and '(ip[2:2]<60)'

### Remark: due to some bug in tcpdump, the following command doesn't catch packets as expected:

    tcpdump -v -n icmp and '(ip[2:2]>50)' and '(ip[2:2]<60)'

F### ilter on encapsulated content (ICMP within PPPoE)

    tcpdump -v -n icmp

### Queiter
* Using -q supresses some protocol information, -t supresses timestamps.
    tcpdump -q -i eth0
    tcpdump -t -i eth0
    tcpdump -A -n -q -i eth0 'port 80'
    tcpdump -A -n -q -t -i eth0 'port 80'

#Advanced Filtering

### Print only useful packets from the HTTP traffic
    tcpdump -A -s 0 -q -t -i eth0 'port 80 and ( ((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12:2]&0xf0)>>2)) != 0)'

### Dump SIP Traffic
* This is useful for debugging Asterisk or FreeSWITCH.

    tcpdump -nq -s 0 -A -vvv port 5060 and host 1.2.3.4

### Checking packet content

    tcpdump -i any -c10 -nn -A port 80


### Checking packet content

    sudo tcpdump -i any -c10 -nn -A port 80

# References & Awesome wikis

* https://hackertarget.com/tcpdump-examples/

* https://wiki.geant.org/display/public/EK/TcpdumpExamples

* http://edoceo.com/cli/tcpdump

* https://www.thegeekstuff.com/2010/08/tcpdump-command-examples/

* https://opensource.com/article/18/10/introduction-tcpdump

#### CONTACT 

If you have problems, questions, ideas or suggestions please contact
us by posting to wuseman@nr1.nu

#### WEB SITE

Visit our homepage for the latest info and updated tools

https://nr1.nu & https://github.com/wuseman/

#### END!

