"""
Forensic Watermark Extractor
Recovers embedded forensic watermark identifiers from leaked or suspect PDF files.
Operates across content stream, zero-width steganographic, and structural layers.
"""

import io
import re
from typing import Optional, Dict, Any
from pypdf import PdfReader

from backend.watermark.embedder import decode_zero_width

# Patterns for watermark and forensic fingerprint identifier extraction
WM_ID_PATTERN = re.compile(r"^(?:FP|WM)-[A-Z0-9]{2,8}(?:-[A-Z0-9]{2,8})?$")
TAG_PATTERN = re.compile(r"TRACESEAL(?:_FORENSIC_TAG)?[:\s]+((?:FP|WM)-[A-Z0-9\-]+)")
RAW_BYTES_TAG_PATTERN = re.compile(rb"TRACESEAL(?:_FORENSIC_TAG)?[:\s]+((?:FP|WM)-[A-Z0-9\-]+)")
RAW_META_PATTERN = re.compile(rb"/TraceSealWatermark\s*\(((?:FP|WM)-[A-Z0-9\-]+)\)")


class WatermarkExtractor:
    """
    Forensic Watermark Recovery Engine.
    Tested transformations:
    - Copying PDF file (Fully resilient)
    - Renaming PDF file (Fully resilient)
    - Normal PDF rendering in browsers and desktop readers (Fully resilient)
    - Re-opening and saving in PDF viewers preserving vector objects (Resilient)
    - Moderate document handling (Resilient)

    Limitations (Documented for technical honesty):
    - Optical rasterization (printing to paper and re-scanning at low DPI) destroys digital streams.
    - Aggressive adversarial PDF sanitizers stripping invisible text objects (Mode 3) can remove content markers.
    """

    @classmethod
    def extract_from_bytes(cls, pdf_bytes: bytes) -> Dict[str, Any]:
        """
        Extract forensic watermark from document bytes (PDF, Image, Text, or Binary).
        Returns dictionary with extraction status, watermark_id, layer, and confidence.
        """
        if not pdf_bytes:
            return {
                "extracted": False,
                "watermark_id": None,
                "extraction_layer": None,
                "confidence": 0.0,
                "message": "Uploaded file is empty.",
            }

        file_bytes = pdf_bytes

        # Layer 1: PDF Document Stream Inspection
        if file_bytes.startswith(b"%PDF"):
            try:
                reader = PdfReader(io.BytesIO(file_bytes))
                # 1a. Check Zero-Width Steganography in page text
                for page_idx, page in enumerate(reader.pages):
                    try:
                        text = page.extract_text() or ""
                        decoded_zw = decode_zero_width(text)
                        if decoded_zw and WM_ID_PATTERN.match(decoded_zw):
                            return {
                                "extracted": True,
                                "watermark_id": decoded_zw,
                                "extraction_layer": f"Zero-Width Steganographic Stream (Page {page_idx + 1})",
                                "confidence": 1.0,
                                "message": "Watermark recovered from zero-width unicode steganography.",
                            }
                    except Exception:
                        pass

                # 1b. Check Imperceptible Content Stream (Mode 3 invisible text)
                for page_idx, page in enumerate(reader.pages):
                    try:
                        text = page.extract_text() or ""
                        match = TAG_PATTERN.search(text)
                        if match:
                            wm_id = match.group(1)
                            return {
                                "extracted": True,
                                "watermark_id": wm_id,
                                "extraction_layer": f"Imperceptible Content Stream (Page {page_idx + 1}, Mode 3)",
                                "confidence": 1.0,
                                "message": "Watermark recovered from imperceptible content stream.",
                            }
                    except Exception:
                        pass

                # 1c. Check PDF Structural Metadata
                try:
                    metadata = reader.metadata or {}
                    for key, val in metadata.items():
                        if val:
                            val_str = str(val)
                            if "TRACESEAL:" in val_str:
                                match = TAG_PATTERN.search(val_str)
                                if match:
                                    return {
                                        "extracted": True,
                                        "watermark_id": match.group(1),
                                        "extraction_layer": f"Structural Metadata ({key})",
                                        "confidence": 0.95,
                                        "message": f"Watermark recovered from PDF structural metadata {key}.",
                                    }
                            if key.endswith("TraceSealWatermark") and WM_ID_PATTERN.match(val_str):
                                return {
                                    "extracted": True,
                                    "watermark_id": val_str,
                                    "extraction_layer": "Document Catalog Dictionary (/TraceSealWatermark)",
                                    "confidence": 0.95,
                                    "message": "Watermark recovered from catalog dictionary.",
                                }
                except Exception:
                    pass
            except Exception:
                pass

        # Layer 2: Image Metadata and Steganography (PNG / JPEG / WebP)
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(file_bytes))
            # Check PNG text chunks
            text_dict = getattr(img, "text", {}) or {}
            for k, v in text_dict.items():
                v_str = str(v)
                if k == "TraceSealWatermark" and WM_ID_PATTERN.match(v_str):
                    return {
                        "extracted": True,
                        "watermark_id": v_str,
                        "extraction_layer": "Image Structural Metadata (PNG tEXt chunk)",
                        "confidence": 1.0,
                        "message": "Watermark recovered from image metadata chunk.",
                    }
                zw = decode_zero_width(v_str)
                if zw and WM_ID_PATTERN.match(zw):
                    return {
                        "extracted": True,
                        "watermark_id": zw,
                        "extraction_layer": "Image Steganographic Stream (Zero-Width)",
                        "confidence": 1.0,
                        "message": "Watermark recovered from image zero-width steganography.",
                    }
                m = TAG_PATTERN.search(v_str)
                if m:
                    return {
                        "extracted": True,
                        "watermark_id": m.group(1),
                        "extraction_layer": "Image Metadata Tag",
                        "confidence": 0.95,
                        "message": "Watermark recovered from image metadata tag.",
                    }

            # Check img.info (comments, exif, parameters)
            for k, v in getattr(img, "info", {}).items():
                v_str = str(v)
                zw = decode_zero_width(v_str)
                if zw and WM_ID_PATTERN.match(zw):
                    return {
                        "extracted": True,
                        "watermark_id": zw,
                        "extraction_layer": "Image Comment Steganography",
                        "confidence": 1.0,
                        "message": "Watermark recovered from image comment stream.",
                    }
                m = TAG_PATTERN.search(v_str)
                if m:
                    return {
                        "extracted": True,
                        "watermark_id": m.group(1),
                        "extraction_layer": "Image Comment Header",
                        "confidence": 0.95,
                        "message": "Watermark recovered from image comment header.",
                    }
        except Exception:
            pass

        # Layer 3: Text Stream and Zero-Width Steganography (TXT, Markdown, or text documents)
        try:
            text_str = file_bytes.decode("utf-8")
            decoded_zw = decode_zero_width(text_str)
            if decoded_zw and WM_ID_PATTERN.match(decoded_zw):
                return {
                    "extracted": True,
                    "watermark_id": decoded_zw,
                    "extraction_layer": "Zero-Width Steganographic Text Stream",
                    "confidence": 1.0,
                    "message": "Watermark recovered from text zero-width unicode steganography.",
                }
            match = TAG_PATTERN.search(text_str)
            if match:
                return {
                    "extracted": True,
                    "watermark_id": match.group(1),
                    "extraction_layer": "Text Stream Forensic Header",
                    "confidence": 0.95,
                    "message": "Watermark recovered from text stream forensic tag.",
                }
        except Exception:
            pass

        # Layer 4: Deep Raw Byte Stream Inspection across ALL file formats
        raw_match = RAW_BYTES_TAG_PATTERN.search(file_bytes)
        if raw_match:
            wm_id = raw_match.group(1).decode("ascii", errors="ignore")
            return {
                "extracted": True,
                "watermark_id": wm_id,
                "extraction_layer": "Raw Object Stream Parser",
                "confidence": 0.90,
                "message": "Watermark recovered from raw object stream scan.",
            }

        raw_meta = RAW_META_PATTERN.search(file_bytes)
        if raw_meta:
            wm_id = raw_meta.group(1).decode("ascii", errors="ignore")
            return {
                "extracted": True,
                "watermark_id": wm_id,
                "extraction_layer": "Raw Metadata Stream Scan",
                "confidence": 0.90,
                "message": "Watermark recovered from raw metadata trailer scan.",
            }

        return {
            "extracted": False,
            "watermark_id": None,
            "extraction_layer": None,
            "confidence": 0.0,
            "message": "No forensic watermark detected in document layers.",
        }

    @classmethod
    def extract_from_file(cls, filepath: str) -> Dict[str, Any]:
        """Extract watermark from a file path."""
        with open(filepath, "rb") as f:
            return cls.extract_from_bytes(f.read())
