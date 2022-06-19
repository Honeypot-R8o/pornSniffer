from threading import Thread
from scapy.all import *
from netaddr import *
import datetime
from time import sleep
import netifaces as ni
import optparse
import smtplib
import sys

dnslist=[]
iplist=[]

dhcpname={}

def startscreen():
	print('\033c')
	print("****************************************")
	print("* Porn Sniffer V.7.0 by Reto Schaedler *")
	print("****************************************")
	print()


def packetSniffer(pkt):
	global dnslist
	global iplist
	ip46 = IPv6 if IPv6 in pkt else IP
	if pkt.haslayer(DNSQR):
		dnslist.append(str(pkt[DNS].qd.qname)[2:-2])
		iplist.append(str(pkt[ip46].dst))


def dnsSniffer():
	global intf
	ni.ifaddresses(intf)
	localIP = ni.ifaddresses(intf)[ni.AF_INET][0]['addr']
	#filterstr="udp and src port 53 and (host not " + localIP + ") and (host not " + "208.67.222.123" + ")"
	filterstr="udp and src port 53 and (host not " + "208.67.222.123" + ")"
	sniff(filter=filterstr, iface=intf, store=0, prn=packetSniffer)


def opendns(dns):
	schmuddel=False
	try:
		answer=sr1(IP(dst="208.67.222.123")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=dns)),verbose=0,timeout=1)
		for x in range(answer[DNS].ancount):
			if valid_ipv4(answer[DNSRR][x].rdata):					
				if IPAddress(answer[DNSRR][x].rdata) in IPNetwork("146.112.0.0/16"):
					schmuddel=True
	except:
		pass
	return(schmuddel)

def send_email(mail_user, mail_password, mail_recipient, subject, body):
	FROM = mail_user
	TO = mail_recipient
	SUBJECT = subject
	TEXT = body
	message = "From: "+FROM + "\nTo: " + TO + "\nSubject: " + SUBJECT + "\n\n" + TEXT + "\n\n"
	try:
		server = smtplib.SMTP_SSL("ms1smtp.webland.ch", 465)
		server.ehlo()
		#server.starttls()
		server.login(mail_user, mail_password)
		server.sendmail(FROM, TO, message)
		server.close()
		return 'successfully sent the mail'
	except Exception as e:
		return "failed to send mail" 

def openDnsChecker():
	global dnslist
	global iplist
	global dhcpname
	while True:
		if(len(dnslist)):
			try:
				if opendns(dnslist[0]):
					#print("****************************************")
					print(dnslist[0])
					print(iplist[0], end='')
					if iplist[0] in dhcpname:
						clientname=dhcpname[iplist[0]]					
					else:
						clientname="Unknown-Host-Name"
					print(" " + clientname)
					print ("Time:",datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
					print("****************************************")
					sys.stdout.flush()
					#send_email('email@test.com','myPassword','destination@test.com','Porn-Alert',dnslist[0] + "\r" + iplist[0] + "\r" + clientname)
				del(dnslist[0])
				del(iplist[0])
			except (KeyboardInterrupt, SystemExit):
				raise
			except:
				if len(dnslist)>0:
					del(dnslist[0])
				if len(iplist)>0:
					del(iplist[0])

		else:
				sleep(0.1)


def get_option(dhcp_options, key):

	must_decode = ['hostname', 'domain', 'vendor_class_id']
	try:
		for i in dhcp_options:
			if i[0] == key:
				# If DHCP Server Returned multiple name servers 
				# return all as comma seperated string.
				if key == 'name_server' and len(i) > 2:
					return ",".join(i[1:])
				# domain and hostname are binary strings,
				# decode to unicode string before returning
				elif key in must_decode:
					return i[1].decode()
				else: 
					return i[1]        
	except:
		pass


def handle_dhcp_packet(packet):
	global dhcpname
	# Match DHCP request
	if DHCP in packet and packet[DHCP].options[0][1] == 3:
		requested_addr = get_option(packet[DHCP].options, 'requested_addr')
		hostname = get_option(packet[DHCP].options, 'hostname')
		if packet[IP].src == "0.0.0.0":		
			dhcpname[requested_addr]=hostname
		else:
			dhcpname[str(packet[IP].src)]=hostname
	return

def dhcpListener():
	global intf
	sniff(filter="udp and (port 67 or 68)", iface=intf,prn=handle_dhcp_packet)


if __name__ == '__main__':

	parser = optparse.OptionParser()
	parser.add_option('-i', '--interface',
	    action="store", dest="interface",
	    help="query string", default="enp60s0")
	options, args = parser.parse_args()

	intf=options.interface

	startscreen()


	th = Thread(target=dnsSniffer)
	th.start()

	th1 = Thread(target=openDnsChecker)
	th1.start()
	
	th2 = Thread(target=dhcpListener)
	th2.start()
