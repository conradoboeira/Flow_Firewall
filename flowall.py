# Author: Conrado Boeira
# About: Code to capture packets and exhibit data on the flows monitored
# During execution, the user can provide rules to block specific flows

import socket
import struct
import sys
import binascii
import select
from os import system, name
from time import sleep
from prettytable import PrettyTable

ETH_P_ALL = 0x0003
# numero maximo de flows para exibir na tela ao mesmo tempo
show_limit = 30

# From https://www.geeksforgeeks.org/clear-screen-python/
# define our clear function
def clear():

    # for windows
    if name == 'nt':
        _ = system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

# Convert bytes to a readable MAC
def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

# Print the flows in a nice table
def pretty_print(flows):
    # Get flows ordered by total size
    ordered_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)
    tabela = PrettyTable()
    tabela.field_names = ["Source IP", "Source Port","Destination IP", "Destination Port", "Protocol", "Allowed Packets", "Denied Packets", "Total Size (bytes)"]
    index = 1
    for flow in ordered_flows:
        if(index > show_limit): break
        flow_id, count = flow
        a_packets,d_packets,size = count
        # Check if the flow has ports or not
        if(len(flow_id) == 3):
            tabela.add_row([flow_id[0], "-", flow_id[1], "-", flow_id[2],a_packets,d_packets, size ])
        else:
            tabela.add_row([flow_id[0], flow_id[1], flow_id[2], flow_id[3], flow_id[4], a_packets, d_packets, size ])
        index += 1

    clear()
    print(61*"*" + " PACKET FLOWS" + 61*"*")
    print(tabela)

# Look at the defined rules and decide wheather a packet should be forwarded or not
def allow_packet(src, src_port, dst, dst_port, rules):
    for rule in rules:
        b_src, b_s_port, b_dst, b_d_port = rule
        if(b_src == "*" or b_src == src):
            if(b_s_port == "*" or int(b_s_port) == src_port):
                if(b_dst == "*" or b_dst == dst):
                    if(b_d_port == "*" or int(b_d_port) == dst_port):
                        return False
    return True

def main(router_mac, monitored_list):

    # Try to create socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)
    s.bind(('wlp2s0',0))

    # Saves data from all packet flows
    # For protocols without ports: (source,destination,protcol) -> (number of packets allowed, number of packets denied, total size)
    # For protocols with ports: (source,source port,destination,destination port,protcol) -> (number of packets allowed, number of packets denied, total size)
    flows = {}

    # Saves the rules to deny flows
    # (source, source port, destination, destination port)
    rules = []

    # Inputs from which we expect to read
    inputs = [ s, sys.stdin ]
    outputs = []

    running = 1

    while running:

        inputready, outputready, exceptready = select.select(
            inputs, outputs, [], 0.0001)

        for i in inputready:

            if i == s : # Input from socket
                (packet,addr) = s.recvfrom(65536)
                original_size = len(packet)

                # Unpack Ethernet header
                eth_length = 14
                eth_header = packet[:14]

                eth = struct.unpack("!6s6sH",eth_header)
                dst_mac = bytes_to_mac(eth[0])
                src_mac = bytes_to_mac(eth[1])

                # Check if the source should be monitored or not
                if(src_mac not in monitored_list): continue

                # Check if IP packet
                if(eth[2] == 0x0800):
                    # Unpack IP header
                    ip_header = packet[eth_length:20+eth_length]
                    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF
                    iph_length = ihl*4
                    ttl = iph[5]
                    protocol_num = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    # Set source and destination ports to default values for later checking
                    src_port = -1
                    dst_port = -1
                    flow_id = ()

                    # CHECK PACKET INFO

                    # Check if it is an ICMP or IGMP packet
                    if(protocol_num == 1 or protocol_num == 2):
                        if(protocol_num == 1): flow_id = (s_addr,d_addr, "ICMP")
                        else: flow_id = (s_addr,d_addr, "IGMP")

                    # Check if it is an TCP or UDP packet
                    if(protocol_num == 6 or protocol_num == 17):
                        # Get values for source and destionation ports from the packet
                        len_prev_head = eth_length + iph_length
                        ports = packet[len_prev_head:4+len_prev_head]
                        ports_h = struct.unpack("!HH",ports)
                        src_port = ports_h[0]
                        dst_port = ports_h[1]

                        if(protocol_num == 6): flow_id = (s_addr,src_port,d_addr,dst_port, "TCP")
                        else: flow_id = (s_addr,src_port,d_addr,dst_port,  "UDP")

                    # Check if packet is not blocked by the rules set
                    if(allow_packet(s_addr, src_port, d_addr, dst_port, rules)):
                        # Add packet values to the flows dictionary and incresse the allowed packets counter
                        if(flow_id in flows):
                            current_val = flows[flow_id]
                            flows[flow_id] = (current_val[0]+1, current_val[1], current_val[2] + len(packet))
                        else:
                            flows[flow_id] = (1, 0, len(packet))

                        # Forwarding packet
                        dest_mac = binascii.unhexlify(router_mac.replace(':',''))
                        source_mac = s.getsockname()[4]
                        eth_hdr = struct.pack("!6s6sH", dest_mac, source_mac, eth[2])
                        packet_wo_eth = packet[eth_length:]

                        # Error check in case packet is too big, for unknown reasons
                        try:
                            s.send(eth_hdr+packet_wo_eth)
                        except OSError as msg:
                            continue

                    # Packet was blocked
                    else:
                        # Add packet values to the flows dictionary and incresse the blocket packets counter
                        if(flow_id in flows):
                            current_val = flows[flow_id]
                            flows[flow_id] = (current_val[0], current_val[1]+1, current_val[2] + len(packet))
                        else:
                            flows[flow_id] = (0, 1, len(packet))

                    pretty_print(flows)


            elif i == sys.stdin: # Input from stdin
                line = sys.stdin.readline()
                if line == "Q\n" or line == "q\n":   # Quit
                    running = 0
                    break
                else: # Get additional commands - blocked operation
                    print(":", end='')
                    command = input().strip()
                    values = command.split(" ")

                    if(command == "show rules"):
                        for r in rules: print(r)

                    elif(len(values) == 5):
                        op, src, src_port, dst, dst_port = values
                        if(op == "deny"):
                            rules.append((src,src_port,dst,dst_port))
                        elif(op == "allow"):
                            if((src,src_port,dst,dst_port) in rules):
                                rules.remove((src,src_port,dst,dst_port))
                        else:
                            print("Command not recognized")
                    else:
                        print("Command not recognized")

                sleep(0.1)


if __name__ == '__main__':
    router_mac = sys.argv[1]
    monitored = sys.argv[2].strip().split(",")
    main(router_mac, monitored)
