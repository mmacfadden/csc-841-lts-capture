###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

from __future__ import annotations
from .rtsp_client import RtspClient
from .rtsp_request import RtspRequest

class RtspStreamer:

    def __init__(self: RtspStreamer, host: str, port: int, token: str) -> RtspStreamer:
        self.host = host
        self.port = port
        self.token = token

    def capture(self, max_frames: int, out_file: str, verbose: bool) -> None:
        client = RtspClient(self.host, self.port, "BBVC", verbose)
        client.connect()

        options = RtspRequest("OPTIONS", f"rtsp://{self.host}/media/video1")
        client.send_rtp_request(options)

        describe = RtspRequest("DESCRIBE", f"rtsp://{self.host}/media/video1") \
            .header("Accept", "application/sdp") \
            .header("Authorization", f"Basic {self.token}")
        client.send_rtp_request(describe)

        setup = RtspRequest("SETUP", "rtsp://{args.host}/media/video1/video") \
            .header("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1") \
            .header("Authorization", f"Basic {self.token}")
        
        setup_reply = client.send_rtp_request(setup)
        session_header = setup_reply.get_header("Session")
        session_id = session_header[0:session_header.index(";")].strip()

        play = RtspRequest("PLAY", f"rtsp://{self.host}/media/video1") \
            .header("Range", "npt=0.000000-") \
            .header("Session", session_id) \
            .header("Authorization", f"Basic {self.token}")
        client.send_rtp_request(play)

        client.capture_interleaved_rtp_stream(max_frames, out_file)