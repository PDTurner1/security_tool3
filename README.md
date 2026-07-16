
(Please see Tool3 Updates.pdf which includes screenshots)

Tool 3 – Updates – Sniff53

The feedback that I received from the reviews included the following:
1.	Clearer reporting when malformed text log input is skipped or ignored.
2.	Capture real DNS traffic to test the tool.
3.	Save the output from the tool to a file that can be saved.
The tool has now been updated to parse the input file and catches four types of issues.  They include:
	Skipped lines
	Too few fields (missing query type column)
Invalid source IPs (octet out of range)
	Invalid domain names (those lacking a dot)
 

Capture live DNS traffic:
I took three captures (pcap1, pcap2, and pcap3 which I have included in the repository.  The tool hit on a few items and it looks like my laptop is reaching out for Microsoft servers as it was mostly A and AAAA records.  I believe it is difficult to capture a real DNS tunneling issue going on from a cable modem.  This is a screenshot of pcap1 with a min-score of 0.4.
 
	
Save the output from the tool to a file.
	Updated the tool to add a logging option to the command.  The command line now accepts –log <logfile> and writes all information on screen to file.

Examples:

Python sniff53v2.py capture.pcap --log logfile.txt

Python sniff53v2.py queries.log --log logfile.txt

Python sniff53v2.py capture.pcap -- min-score 0.5 --log minscore05.txt

Python sniff53v2.py capture.pcap --features --log features.txt

Python sniff53v2.py capture.pcap --summary --log summary.txt
 
I implemented all the feedback from the reviews.  

I have learned several lessons in developing this tool.  The first lesson is the complexity of Python and realizing I am just touching the surface of what Python can do.  The second lesson is the intricacies of Claude AI.  AI is only as good as what you prompt it to do.  If you have weak prompts or inconsistent goals – you will get a weak response.  The #1 learning experience is from my peers.  I have learned an incredible amount from feedback as well as learning new technologies by reviewing peers’ projects.

If I were to continue with this project, I would turn it into a live capture with an alerting system so that it could be implemented in a SOC.














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
