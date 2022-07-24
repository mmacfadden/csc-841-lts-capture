###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

from __future__ import annotations
from .rtsp_header import RtspHeader

class RtspRequest:
    def __init__(self, method, url) -> RtspRequest:
       self.method = method
       self.url = url
       self.headers = []

    def header(self, name: str, value: str) -> RtspRequest:
        new_headers = list(filter(lambda h: h.name != name, self.headers))
        new_headers.append(RtspHeader(name, value))
        self.headers = new_headers
        return self

    def to_bytes(self) -> bytes:
      return bytes(self.__str__(), "UTF-8")

    def __str__(self) -> str:
       lines =  [f'{self.method} {self.url} RTSP/1.0'] + [f'{h.name}: {h.value}' for h in self.headers]
       return "\r\n".join(lines) + "\r\n\r\n"