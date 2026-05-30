import re
from .packet import AITPacket

class ContentSanitizer:
    POLLUTION_PATTERNS = [
        r"ignore previous instructions",
        r"reveal system prompt",
        r"show hidden prompt",
        r"system\s*override",
        r"developer mode",
        r"jailbreak",
        r"前の命令を無視",
        r"システムプロンプトを表示",
        r"秘密情報を出せ"
    ]

    def scan(self, packet: AITPacket) -> AITPacket:
        packet.metadata["pollution_detected"] = False
        
        for pattern in self.POLLUTION_PATTERNS:
            if re.search(pattern, packet.content, re.IGNORECASE):
                packet.metadata["pollution_detected"] = True
                packet.metadata["pollution_reason"] = f"Matched pattern: {pattern}"
                # If pollution detected in DATA, lower trust further
                if packet.type == "DATA":
                    packet.trust = min(packet.trust, 0.1)
                break
        
        return packet
