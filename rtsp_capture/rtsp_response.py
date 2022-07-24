###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

from __future__ import annotations

class RtspResponse:

    @staticmethod
    def parse(response: bytes) -> RtspResponse:
        data = str(response, "UTF8")
        lines = data.split("\r\n")
        status_line = lines[0]
        last_header_idx = lines.index("")

        headers = {}
        
        for header_line in lines[1:last_header_idx]:
            colon = header_line.index(":")
            name = header_line[0:colon]
            value = header_line[colon + 1:len(header_line)]
            headers[name] = value
        
        body = "\r\n".join(lines[last_header_idx:len(lines)])
        return RtspResponse(status_line, headers, body)

    
    def __init__(self, status: str, headers: dict[str, str], body: str) -> RtspResponse:
        self.status = status
        self.headers = headers
        self.body = body

    def __str__(self) -> str:
       lines =  [self.status] + [f'{key}: {value}' for key, value in self.headers.items()] + [self.body]
       return "\r\n".join(lines) + "\r\n"
    
    def get_header(self, name: str) -> str:
        return self.headers[name]