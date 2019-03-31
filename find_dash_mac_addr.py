from scapy.all import sniff, ARP

# Takes in packets and prints out MAC address if ARP Probe
def arp_display(packet):
    if (packet[ARP].op == 1): #who-has (request)
    # This might actually have a different IP (when setup via Amazon)
    # if (packet[ARP].psrc == '0.0.0.0'): # ARP Probe
        print(f'ARP Probe from: {packet[ARP].hwsrc}')

# Sniffs packets and runs function if ARP found (looks for only 10 events)
print(sniff(prn=arp_display, filter="arp", store=0, count=10))
