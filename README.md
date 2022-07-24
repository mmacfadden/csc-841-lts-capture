# DSU CSC-844 Final Project (LTS IP Camera Capture Utility)
This repository contains a utility I created for Dakota State University CSC-844 Advanced Reverse Engineering. The utility will capture a video stream from an LTS IP Camera using the RTSP protocol once you have intercepted the BASIC Authentication Token.

## Usage
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

## Example Usage
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