import os
os.system("clear")

from scapy.all import *

intr = "eth0"               #select the network adapter
protocolFilter = "tcp"      #select the protocol (tcp, udp icmp)

output_file = "capturedPackets.pcap"    #name of file
captured_packets = []

print(f"sniffing in {protocolFilter} . . .")


#Funzione di callback per elaborare i pacchetti catturati
def packet_callback(packet):
    print("-" * 80)
    print (packet.summary())
    print("-" * 80)

    captured_packets.append(packet)

#sniffing dei paccehtti
sniff(prn=packet_callback, store=0, count=0, filter=(protocolFilter), iface=intr)
#store=0        non salva i pacchetti
#count=0        prende pacchetti infiniti

#Dopo aver terminato lo sniffing, salva i pacchetti in un file .pcap
wrpcap(output_file, captured_packets, append=False)
#append=False sofvrascrive il file all'esecuzione
#append=True aggiunge dati senza sovrascrivere
