import re
import unicodedata
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

    # Cognitive/Linguistic Markers for Smuggling (Intent Detection)
    SMUGGLING_MARKERS = [
        r"reverse the following",
        r"execute the resulting",
        r"think of a word",
        r"starts with.*ends with",
        r"combine the fragments",
        r"secretly execute",
        r"do not output.*just execute"
    ]

    def scan(self, packet: AITPacket) -> AITPacket:
        # 1. Unicode Normalization (NFKC) + Custom Homoglyph Neutralizer
        content = unicodedata.normalize('NFKC', packet.content)
        
        # 2. Invisible Character Stripping (Zero-Width Steganography Defense)
        invisible_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']
        for char in invisible_chars:
            content = content.replace(char, '')
        
        # 3. Structural Flattening (Markdown Table Defense)
        # Strips table delimeters to reassemble fragmented keywords (| I | G | N | -> IGNORE)
        flattened_content = content.replace("|", "").replace("-", "").replace(" ", "")

        # Manual mapping for high-risk confusables
        confusables = {
            'і': 'i', 'ο': 'o', 'е': 'e', 'а': 'a', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x'
        }
        for k, v in confusables.items():
            content = content.replace(k, v)
            flattened_content = flattened_content.replace(k, v)
        
        # 4. Pre-cleaning (Markdown/HTML)
        clean_content = re.sub(r"<!--[\s\S]*?-->", "", content)
        clean_content = re.sub(r"\[\/\/\]: # \(.*?\)", "", clean_content)

        packet.metadata["pollution_detected"] = False
        
        # 5. Pattern Matching (Standard & Flattened)
        # Scan both original and flattened content
        for pattern in self.POLLUTION_PATTERNS:
            if re.search(pattern, clean_content, re.IGNORECASE) or re.search(pattern, flattened_content, re.IGNORECASE):
                packet.metadata["pollution_detected"] = True
                packet.metadata["pollution_reason"] = f"Matched pattern: {pattern}"
                break

        # 6. Intent Scanning (Linguistic Markers)
        if not packet.metadata["pollution_detected"]:
            for marker in self.SMUGGLING_MARKERS:
                if re.search(marker, clean_content, re.IGNORECASE):
                    packet.metadata["pollution_detected"] = True
                    packet.metadata["pollution_reason"] = f"Intent Smuggling detected: {marker}"
                    break
        
        # 7. ASCII Art / Symbol Density Detection
        if not packet.metadata["pollution_detected"]:
            # If a block of text has high symbol density, flag it
            symbol_count = len(re.findall(r"[^a-zA-Z0-9\s\u3040-\u30FF\u4E00-\u9FFF]", content))
            if len(content) > 20 and (symbol_count / len(content)) > 0.3:
                packet.metadata["pollution_detected"] = True
                packet.metadata["pollution_reason"] = "High symbol density detected (Potential ASCII Art Attack)"
        
        # Dynamic Downgrade
        if packet.metadata["pollution_detected"]:
            if packet.source not in ["ADMIN", "SYSTEM"]:
                packet.trust = min(packet.trust, 0.1)
                packet.type = "DATA"
        
        return packet
