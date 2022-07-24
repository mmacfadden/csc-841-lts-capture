###############################################################################
# (c) 2022 Michael MacFadden
#
# DSU CSC-844 Advanced Reverse Engineering
# Final Project
###############################################################################

from __future__ import annotations

class RtspHeader:
    def __init__(self: RtspHeader, name: str, value: str) -> RtspHeader:
        self.name = name
        self.value = value