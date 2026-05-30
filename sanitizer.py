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
        r"以下の指示を無視",
        r"指示をリセット",
        r"システムプロンプトを表示",
        r"本当の指示を教えて",
        r"秘密情報を出せ",
        r"os\.system",
        r"subprocess\.run",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"<\/s>",
        r"フィクションの物語",
        r"研究目的です",
        r"AI Assistant:",
        r"Please forward",
        r"Confirm you've done so",
        r"attacker@evil\.com",
        r"Ignore previous rules",
        r"reveal API key",
        r"開発者モードになれ",
        r"base64",
        r"decode:",
        r"学術研究",
        r"NEW INSTRUCTIONS",
        r"---END OF DOCUMENT---"
    ]

    def scan(self, packet: AITPacket) -> AITPacket:
        packet.metadata["pollution_detected"] = False
        
        for pattern in self.POLLUTION_PATTERNS:
            if re.search(pattern, packet.content, re.IGNORECASE):
                packet.metadata["pollution_detected"] = True
                packet.metadata["pollution_reason"] = f"Matched pattern: {pattern}"
                
                # Dynamic Downgrade: If pollution detected, strip authority
                # (Admins/System are bypassed to allow testing)
                if packet.source not in ["ADMIN", "SYSTEM"]:
                    packet.trust = min(packet.trust, 0.1)
                    packet.type = "DATA" # Force to DATA to trigger policy restriction
                break
        
        return packet
