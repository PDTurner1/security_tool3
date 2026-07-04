# security_tool3

Patrick Turner

CSC 842 – Tool #3 - Analyze malicious activity on DNS Port 53 traffic

Repository files:

README.md - this text

Sniff53_Documentation.pdf - full Sniff53 documentation

claude interaction.txt - original conversation with Claude AI

sentinel.py - Claude's origianl py file it produced

sniff53.py - Sniff53 DNS sniffer

test.pcap - Pcap file used in testing

testlog.txt - Log file used in testing



Sniff53

Sniff53 is a lightweight packet sniffer that parses Domain Name System (DNS) packets on port 53 (UDP) to detect malicious activity.  These DNS tunneling attacks can create a communication channel that bypasses many firewalls because they don’t inspect traffic that traverses port 53.  Corporate sized Next-Generation Firewalls (NGFWs) are now performing deep packet inspection.  Attackers can communicate with a Command and Control Server (C2) to send remote execution instructions to compromised computers.  If a firewall is not watching what is being sent back and forth on port 53 this can happen very easily.  This attack can also be used for data exfiltration, possibly sending small pieces of files or stealing credentials from a network.  Data exfiltration prevention hardware and software may miss DNS packets if they are only looking at traditional ways of exfiltrating data.  Another attack is used to bypass paid Wi-Fi.  Iodine and Your-Freedom are tools that can tunnel normal web traffic through port 53 which is usually open on paid Wi-Fi networks.  

How to run the tool:

The tool requires no external dependencies; it runs using the Python standard libraries.  The tool has the following options:

Python3 sniff53.py capture.pcap

Python3 sniff53.py queries.log

Python3 sniff53.py capture.pcap --min-score 0.5

Python3 sniff53.py capture.pcap --features

Python3 sniff53.py capture.pcap –summary


See Sniff53_Documentation.pdf for full documentation.
