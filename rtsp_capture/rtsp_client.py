###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

from __future__ import annotations

from .rtsp_request import RtspRequest
from .rtsp_header import RtspHeader
from .rtsp_response import RtspResponse

import socket
import bitstring


class RtspClient:
    def __init__(self: RtspClient, host: str, port: int, ua: str, verbose: bool) -> RtspClient:
       self.host = host
       self.port = port
       self.ua = ua
       self.seqNo = 1
       self.sock = None
       self.verbose = verbose

    def connect(self: RtspClient) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))    

    def send_rtp_request(self: RtspClient, request: RtspRequest) -> RtspResponse:
        self.__print_banner(f"REQUEST: {self.seqNo}")
        
        request.headers.insert(0, RtspHeader("CSeq", str(self.seqNo)))
        request.headers.insert(0, RtspHeader("User-Agent", self.ua))
        
        print(request)
      
        self.sock.send(request.to_bytes())

        response = self.sock.recv(8000)
        # response = self.recvall(s)
        rtsp_response = RtspResponse.parse(response)

        print(rtsp_response)

        self.seqNo = self.seqNo + 1

        return rtsp_response


    def capture_interleaved_rtp_stream(self: RtspClient, max_frames: int, out_file: str) -> None:
        self.__print_banner("Capturing RTP Stream")
        
        print("...")

        video_file = open(out_file,'wb')

        frames = 0
        while frames < max_frames:
            packet = self.__read_rtp_packet()
            if (packet != None):
                video_file.write(packet)
                frames += 1

        video_file.close()
        
        
        self.__print_banner("RTP Capture Complete")
    
    def __read_rtp_packet(self: RtspClient) -> None:
        """Attempts to identify and return a processed RTP Embedded Data packet.

        From https://datatracker.ietf.org/doc/html/rfc2326#section-10.12

            Stream data such as RTP packets is encapsulated by an ASCII dollar
            sign (24 hexadecimal), followed by a one-byte channel identifier,
            followed by the length of the encapsulated binary data as a binary,
            two-byte integer in network byte order.
        
         0             1                 2               3
         0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |        $       |    Channel   |       Embedded Data Length    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        This method will return null if the data does not start with the magic
        number.
        """
        magic = self.sock.recv(1)
        if magic != b'$':
            return

        channel = int.from_bytes(self.sock.recv(1), "big")
        if (channel != 0):
            return
            
        length = int.from_bytes(self.sock.recv(2), "big")
        rtp_payload = self.sock.recv(length)
        
        frame = self.__process_rtp_embedded_data(rtp_payload)
        return frame

    def __process_rtp_embedded_data(self: RtspClient, rtp_payload: bytes):
        """ This method process an RTP packet that was embedded in the RTSP protocol.
        It assumes HVEC Encoding.  Relevant RFCs are:
            RTP - https://datatracker.ietf.org/doc/html/rfc3550
            HVEC over RTP - https://datatracker.ietf.org/doc/html/rfc7798
        """
        # The mandatory starting bytes for an NAL frame
        nal_start_bytes = ("\x00\x00\x00\x01").encode()
        
        # We convert the whole rtp payload to a bit string. We could probably shorten this
        # a bit for performance, but this is just a proof of concept.
        bit_str = bitstring.BitArray(bytes = rtp_payload)
    
        ##
        ## Process the RTP Header
        ##

        """
        The below is the RTP Header Format. Per:
            https://datatracker.ietf.org/doc/html/rfc3550#section-5.1

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |V=2|P|X|  CC   |M|     PT      |       sequence number         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           timestamp                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           synchronization source (SSRC) identifier            |
        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
        |            contributing source (CSRC) identifiers             |
        |                             ....                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """

        version = bit_str[0:2].uint
        p = bit_str[3]
        x = bit_str[4]
        cc = bit_str[4:8].uint
        m = bit_str[9]
        pt = bit_str[9:16].uint
        seq_no = bit_str[16:32].uint
        timestamp = bit_str[32:64].uint
        ssrc = bit_str[64:96].uint
        
        self.__debug(f"RTP Header: version({version}), p({p}), x({x}), cc({cc}), m({m}), pt({pt}), seq_no ({seq_no}), timestamp({timestamp}), SSRC({ssrc})")
        
         # We have processed 12 bytes of the RTP header, excluding the CSRCs.
        byte_count = 12 
        bit_count = byte_count * 8

        # process the number of CSRC ids specified by the CC field.
        csrc_ids = []
        for _ in range(cc):
            csrc_ids.append(bit_str[bit_count:bit_count + 32].uint)
            byte_count += 4
            bit_count = byte_count * 8
        
        self.__debug(f"NAL csrc_ids: {csrc_ids}")

        # We have an extension header as defined by:
        #   https://datatracker.ietf.org/doc/html/rfc3550#section-5.3.1
        if x:
            # The first two bytes are the header id.
            header_id = bit_str[bit_count:bit_count + 16].uint
            bit_count += 16
            byte_count += 2
            
            # The nest two bytes is a 16 bit lentgh that counts the number of 32-bit 
            # (4-byte) words in the extension excluding the 4-octet header.
            header_length = bit_str[bit_count:bit_count + 16].uint
            byte_count += 2
            
            self.__debug("Header Extension: id: {header_id}, length: {header_length}")

            # Update the byte count by 4 bytes times the length of the header.
            byte_count += 4 * header_length

            # adjust the bit count
            bit_count = byte_count * 8
            

        ##
        ## Next comes the NAL Header
        ##   https://datatracker.ietf.org/doc/html/rfc7798#section-1.1.4
        ##

        """
        HEVC maintains the NAL unit concept of H.264 with modifications.
        HEVC uses a two-byte NAL unit header, as shown in Figure 1.  The
        payload of a NAL unit refers to the NAL unit excluding the NAL unit
        header.

                    +---------------+---------------+
                    |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |F|   Type    |  LayerId  | TID |
                    +-------------+-----------------+

        Figure 1: The Structure of the HEVC NAL Unit Header
        """
        nal_f = bit_str[bit_count]
        nal_type = bit_str[bit_count + 1:bit_count + 7].uint 
        nal_layer_id = bit_str[bit_count + 7:bit_count + 13].uint 
        nal_tid = bit_str[bit_count + 13:bit_count + 16].uint 
        
        self.__debug(f"NAL Header: F({nal_f}), Type({nal_type}), LayerId({nal_layer_id}), TID({nal_tid})")

        # we've now processed two more bytes for the NAL Header.
        byte_count += 2
        bit_count = byte_count * 8
        
        if nal_type == 32:
            self.__debug("VPS_NUT")
        
        elif nal_type == 33:
            self.__debug("SPS_NUT")
        
        elif nal_type == 34:
            self.__debug("PPS_NUT")

        elif nal_type == 49:
            """
            This is what the Fragment Unit header looks like.
            +---------------+
            |0|1|2|3|4|5|6|7|
            +-+-+-+-+-+-+-+-+
            |S|E|  FuType   |
            +---------------+
            """

            fu_header = bit_str[bit_count:bit_count + 8]
            fu_start = fu_header[0]
            fu_end = fu_header[1]

            # we've now processed one more byte for the FU Header.
            byte_count += 1
            bit_count = byte_count * 8
            
            if (fu_start):
                self.__debug("FU (Start)")
               
                h = fu_header[1:].copy()
                h.append(bitstring.BitArray(length=1))
               
                head = (
                    nal_start_bytes +
                    h.bytes +
                    ("\x01").encode()
                )

                return head + rtp_payload[byte_count:]
            elif not fu_end:
                self.__debug("FU (Intermediate)")
                return rtp_payload[byte_count:]
            else:
                data = rtp_payload[byte_count:]
                self.__debug("FU (Final)")
                return data
        else:
            raise(Exception(f"Unexpected NAL Type: {nal_type}"))


    def __debug(self: RtspClient, msg: str) -> None:
        if self.verbose:
            print(msg)

    def __print_banner(self, message: str) -> None:
        print("--------------------------")
        print(message)
        print("--------------------------")