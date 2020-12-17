from scapy.all import *
import time

# Fixup function to extract dhcp_options by key
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

    logs = []
    # Print the DHCP REQUEST
    print('---')
    print('DHCP Request')
    print(packet.summary())
    print(ls(packet))

    requested_addr = get_option(packet[DHCP].options, 'requested_addr')
    hostname = get_option(packet[DHCP].options, 'hostname')
    print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")

    

if __name__ == "__main__":
    sniff(filter="port 67 or 68", prn=handle_dhcp_packet)
