# DSU CSC-844 Final Project (LTS IP Camera Capture Utilities)
This repository contains utilities I created for Dakota State University CSC-844 Advanced Reverse Engineering. The project contains two utilities.

1. **[rstp-passwd.py](#rtsp-passwd-utility)**:  Extracts a Basic Authentication token from an RTSP exchange.
2. **[lts-capture.py](#lts-capture-utility)**:  Captures a video stream from an LTS IP Camera using the RTSP protocol once you have intercepted the BASIC Authentication Token.

## Background
The LTS camera uses the Real Time Streaming Protocol (RTSP), defined in [RFC 2326](https://datatracker.ietf.org/doc/html/rfc2326) to negotiate the streaming of video data from the camera to a client.  RTSP is a request / response protocol similar in structure as HTTP, but is a completely different in content. RTSP is about "control". It has commands to describe available streams, setup a stream, play them, stop them, etc.  The video is generally streamed over the Real-time Transport Protocol (RTP) defined in [RFC 3550 ](https://datatracker.ietf.org/doc/html/rfc3550). RTP often is sent over UDP.

Interestingly, RTSP has the ability to "interleave", or embed the RTP data in the same socket connection as the RTSP in cases where a firewall might block the UDP data on a non-standard port.

### RTSP Stream Set Up

#### DESCRIBE
This exchange will describe an available stream. It will tell the client what type of video, codec, etc. can be used.

##### Request
```
DESCRIBE rtsp://192.168.1.232/media/video1 RTSP/1.0
User-Agent: BBVC
Accept: application/sdp
CSeq: 3
Authorization: Basic YWRtaW46VURIeVkkSzcmS0FrclQzKlghS3g=
```

##### Response
```
RTSP/1.0 200 OK
CSeq: 3
Content-Base: rtsp://192.168.1.232/media/video1
Content-Length: 506
Content-Type: application/sdp

v=0
o=- 1001 1 IN IP4 192.168.1.232
s=VCP IPC Realtime stream
m=video 0 RTP/AVP 108
c=IN IP4 192.168.1.232
a=control:rtsp://192.168.1.232/media/video1/video
a=rtpmap:108 H265/90000
a=fmtp:108 sprop-sps=QgEBAUAAAAMAAAMAAAMAAAMAmaAB4CACIHxOWu5Gwa5VE3AQEBBAAAADAEAAAAUC; sprop-pps=RAHAc8BMkA==
a=recvonly
m=application 0 RTP/AVP 107
c=IN IP4 192.168.1.232
a=control:rtsp://192.168.1.232/media/video1/metadata
a=rtpmap:107 vnd.onvif.metadata/90000
a=fmtp:107 DecoderTag=h3c-v3 RTCP=0
a=recvonly
```

#### SETUP
The setup command sets up a specific stream.  Two notes:

* The Transport line lets the client know that the stream will be embedded in RTSP using RTP.  This is indicated by the "interleaved" line.
* The server returns the session id of this stream.  This will be used in the PLAY command.

##### Request
```
SETUP rtsp://192.168.1.232/media/video1/video RTSP/1.0
User-Agent: BBVC
CSeq: 4
Transport: RTP/AVP/TCP;unicast;interleaved=0-1
Authorization: Basic YWRtaW46VURIeVkkSzcmS0FrclQzKlghS3g=
```

##### Response
```
RTSP/1.0 200 OK
CSeq: 4
Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7fd7d2e;mode="PLAY"
Session: b9b53d2a5db53d2aecb53d2a99b53d2;timeout=60
```

#### PLAY
This tells the server to start streaming the data via RTP embedded in the existing RTSP connection. Notice, the session id matches what was returned by the server in the set up.  The binary data will then be streamed on the same TCP connection as the RTSP exchange.

##### Request
```
PLAY rtsp://192.168.1.232/media/video1 RTSP/1.0
User-Agent: BBVC
Range: npt=0.000000-
CSeq: 5
Session: b9b53d2a5db53d2aecb53d2a99b53d2
Authorization: Basic YWRtaW46VURIeVkkSzcmS0FrclQzKlghS3g=
```

##### Response
```
RTSP/1.0 200 OK
CSeq: 5
Range: npt=0Z-
Session: b9b53d2a5db53d2aecb53d2a99b53d2
```


### Extracting the Password
Two important notes:
  * Similar to HTTP, RTSP uses "headers" to pass meta-data about requests. One such header is the Authorization header.
  * The PLAY command is used to tell the camera to play a video stream (that has already been set up). If required, this command will contain the Authorization header.

A play command might look as follows:
```
PLAY rtsp://192.168.1.232/media/video1 RTSP/1.0
User-Agent: BBVC
Range: npt=0.000000-
CSeq: 5
Session: b9b53d2a5db53d2aecb53d2a99b53d2
Authorization: Basic YWRtaW46VURIeVkkSzcmS0FrclQzKlghS3g=


```

From this data, we can extract the Authorization header as well as the stream URI.

## rtsp-passwd Utility
This utility uses [scapy](https://scapy.net/) to sniff network traffic in promiscuous mode and looks for an RTSP PLAY command that contains an authorization header.  When found, it will extract the stream URI as well as the authorization header. It will then extract the auth token and decode it to find the username and password.

### Usage
```sh
./rtsp-passwd.py -h
usage: rtsp-passwd.py [-h] host port

Extracts authentication credentials from an unprotected RTSP stream.

positional arguments:
  host        The hostname or address of the LTS camera
  port        The the RTSP port of the LTS camera

optional arguments:
  -h, --help  show this help message and exit
```

### Example Usage
```sh
./rtsp-passwd.py 192.168.1.232 8554                                                                                                           127 ⨯

Extracting RTSP Stream Authentication...

-----------------------------------
RTSP Stream Authentication Detected
-----------------------------------
RTSP Stream:    rtsp://192.168.1.232/media/video1
Auth Token:     YWRtaW46UGFzc3dvcmQxIQ==
Username:       admin
Password:       Password1!

```

## lts-capture Utility

### Usage
```sh
usage: lts-capture.py [-h] --host host --port port --token token --frames frames --output out [--verbose]

Capture a video stream from an LTS IP Camera using RTSP/RTP/HVEC.

optional arguments:
  -h, --help            show this help message and exit
  --host host, -s host  The hostname or address of the LTS camera
  --port port           The the RTSP port of the LTS camera
  --token token, -t token
                        The basic authorization token
  --frames frames       The number frames to capture from the RTP stream
  --output out, -o out  The file to output to
  --verbose, -v         Print verbose output
```

### Example Usage
```sh
./lts-capture.py \
  --host 192.168.1.232 \
  --port 8554 \
  --token YWRtaW46VURIeVkkSzcmS0FrclQzKlghS3g= \
  --frames 500 \
  --output stream.h265
```

## License
The code is licensed under the MIT License. The text of the license can be found in the [License](License) file.