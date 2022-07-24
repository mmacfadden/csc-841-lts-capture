#!/usr/bin/env python3

###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

import argparse
from rtsp_capture import RtspStreamer

##
## Process the arguments
##
parser = argparse.ArgumentParser(description='Capture a video stream from an LTS IP Camera using RTSP/RTP/HVEC.')
parser.add_argument('--host', '-s', metavar='host', type=str, required=True,
                    help='The hostname or address of the LTS camera')
parser.add_argument('--port', metavar='port', type=int, required=True,
                    help='The the RTSP port of the LTS camera')
parser.add_argument('--token', '-t', metavar='token', type=str, required=True,
                    help='The basic authorization token')
parser.add_argument('--frames', metavar='frames', type=int, required=True,
                    help='The number frames to capture from the RTP stream')
parser.add_argument('--output', '-o', metavar='out', type=str, required=True,
                    help='The file to output to')
parser.add_argument('--verbose', '-v', action='store_true',
                    help="Print verbose output")

args = parser.parse_args()

##
## Execute the capture
##
c = RtspStreamer(args.host, args.port, args.token)
c.capture(args.frames, args.output, args.verbose)
