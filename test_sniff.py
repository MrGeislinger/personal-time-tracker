from scapy.all import sniff, ARP

# Function that takes in packets and prints out MAC address if ARP Probe
def arp_display(pkt):
  if (pkt[ARP].op == 1): #who-has (request)
    if (pkt[ARP].psrc == '0.0.0.0'): # ARP Probe
      print(f'ARP Probe from: {pkt[ARP].hwsrc}')

# Sniffs packets and runs function if ARP found
print(sniff(prn=arp_display, filter="arp", store=0, count=10))
