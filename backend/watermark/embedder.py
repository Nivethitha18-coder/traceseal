"""
Multi-Layer Imperceptible Forensic Watermark Embedder
Embeds forensic watermark ID into PDF documents without modifying visible appearance.
Utilizes PDF Rendering Mode 3 (invisible text), zero-width character steganography,
and structural document dictionary metadata.
"""

import io
import re
from typing import Tuple
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

from backend.watermark.generator import generate_watermark_id

# Zero-Width Unicode Steganography Alphabet
ZW_ZERO = "\u200B"  # Zero-width space represents bit 0
ZW_ONE = "\u200C"   # Zero-width non-joiner represents bit 1
ZW_START = "\u200D" # Zero-width joiner represents start delimiter
ZW_END = "\uFEFF"   # Zero-width non-breaking space represents end delimiter


def encode_zero_width(text: str) -> str:
    """Encode an ASCII text string into invisible zero-width unicode characters."""
    binary_str = "".join(f"{ord(c):08b}" for c in text)
    encoded = "".join(ZW_ONE if bit == "1" else ZW_ZERO for bit in binary_str)
    return f"{ZW_START}{encoded}{ZW_END}"


def decode_zero_width(text: str) -> str:
    """Decode invisible zero-width unicode characters back into ASCII text string."""
    pattern = re.compile(f"{ZW_START}([{ZW_ZERO}{ZW_ONE}]+){ZW_END}")
    match = pattern.search(text)
    if not match:
        return ""
    bits = match.group(1).replace(ZW_ZERO, "0").replace(ZW_ONE, "1")
    chars = [chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8) if i + 8 <= len(bits)]
    return "".join(chars)


class WatermarkEmbedder:
    """
    Forensic Watermark Embedder.
    Embeds forensic fingerprint across three complementary layers:
    1. Imperceptible Content Stream: Text Render Mode 3 (Neither fill nor stroke)
    2. Zero-Width Unicode Steganography embedded within stream text
    3. Structural Document Metadata & Catalog Dictionary
    """

    @classmethod
    def embed_watermark(
        cls,
        pdf_bytes: bytes,
        watermark_id: str,
    ) -> bytes:
        """
        Embed the unique forensic watermark_id into the PDF document.
        Returns the fingerprinted PDF bytes.
        """
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()

        num_pages = len(reader.pages)
        if num_pages == 0:
            raise ValueError("Input PDF contains no pages")

        # Encode zero-width steganographic payload
        zw_payload = encode_zero_width(watermark_id)
        tag_text = f"TRACESEAL_FORENSIC_TAG:{watermark_id}{zw_payload}"

        # Create invisible overlay page matching document dimensions
        first_page = reader.pages[0]
        page_width = float(first_page.mediabox.width)
        page_height = float(first_page.mediabox.height)

        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=(page_width, page_height))
        # Text Render Mode 3 = Neither fill nor stroke (Invisible text mode per PDF 1.7 Spec §9.3.5)
        text_obj = can.beginText(10, 10)
        text_obj.setTextRenderMode(3)
        text_obj.setFont("Helvetica", 4)
        text_obj.textLine(tag_text)
        can.drawText(text_obj)
        can.save()
        packet.seek(0)

        overlay_reader = PdfReader(packet)
        overlay_page = overlay_reader.pages[0]

        # Merge invisible overlay into pages
        for idx, page in enumerate(reader.pages):
            new_page = writer.add_page(page)
            if idx == 0:
                new_page.merge_page(overlay_page)

        # Layer 3: Structural Metadata Dictionary
        existing_meta = reader.metadata or {}
        new_meta = {
            "/Producer": "TraceSeal Provenance Engine v1.0",
            "/Keywords": f"Confidential TRACESEAL:{watermark_id}",
            "/TraceSealWatermark": watermark_id,
        }
        for k, v in existing_meta.items():
            if str(k) not in new_meta:
                new_meta[str(k)] = str(v)

        writer.add_metadata(new_meta)

        out_buffer = io.BytesIO()
        writer.write(out_buffer)
        return out_buffer.getvalue()

    @classmethod
    def embed_watermark_image(
        cls,
        image_bytes: bytes,
        watermark_id: str,
        format_hint: str = "PNG",
    ) -> bytes:
        """Embed forensic watermark metadata into an image (PNG/JPEG) without altering visible appearance."""
        try:
            from PIL import Image, PngImagePlugin
            img = Image.open(io.BytesIO(image_bytes))
            img_format = (img.format or format_hint or "PNG").upper()
            zw_payload = encode_zero_width(watermark_id)
            tag_text = f"TRACESEAL_FORENSIC_TAG:{watermark_id}{zw_payload}"

            out_buf = io.BytesIO()
            if img_format == "PNG":
                png_info = PngImagePlugin.PngInfo()
                existing_text = getattr(img, "text", {}) or {}
                for k, v in existing_text.items():
                    try:
                        png_info.add_text(str(k), str(v))
                    except Exception:
                        pass
                png_info.add_text("TraceSealWatermark", watermark_id)
                png_info.add_text("TRACESEAL_FORENSIC_TAG", tag_text)
                img.save(out_buf, format="PNG", pnginfo=png_info)
                return out_buf.getvalue()
            elif img_format in ("JPEG", "JPG"):
                comment_bytes = tag_text.encode("utf-8")
                img.save(out_buf, format="JPEG", comment=comment_bytes, quality=95)
                return out_buf.getvalue()
            else:
                # Fallback: save preserving format with appended tag
                img.save(out_buf, format=img_format)
                return out_buf.getvalue() + f"\n<!-- TRACESEAL_FORENSIC_TAG:{watermark_id}{zw_payload} -->".encode("utf-8")
        except Exception:
            # Safe fallback: append forensic bytes comment marker
            zw_payload = encode_zero_width(watermark_id)
            return image_bytes + f"\n/* TRACESEAL_FORENSIC_TAG:{watermark_id}{zw_payload} */".encode("utf-8")

    @classmethod
    def embed_watermark_text(
        cls,
        text_bytes: bytes,
        watermark_id: str,
    ) -> bytes:
        """Embed invisible zero-width unicode steganography and tag into plain text / document content."""
        try:
            decoded = text_bytes.decode("utf-8")
            zw_payload = encode_zero_width(watermark_id)
            tag = f"\n/* TRACESEAL_FORENSIC_TAG:{watermark_id}{zw_payload} */\n"
            return (decoded + tag).encode("utf-8")
        except Exception:
            zw_payload = encode_zero_width(watermark_id)
            return text_bytes + f"\nTRACESEAL_FORENSIC_TAG:{watermark_id}{zw_payload}\n".encode("utf-8", errors="ignore")

    @classmethod
    def embed_watermark_auto(
        cls,
        content_bytes: bytes,
        watermark_id: str,
        filename: str = "",
    ) -> bytes:
        """
        Auto-detect format and embed imperceptible forensic watermark.
        Supports PDF, PNG, JPG/JPEG, Text, and arbitrary documents.
        """
        fname_lower = filename.lower()
        if content_bytes.startswith(b"%PDF") or fname_lower.endswith(".pdf"):
            return cls.embed_watermark(content_bytes, watermark_id)
        elif content_bytes.startswith(b"\x89PNG\r\n\x1a\n") or fname_lower.endswith(".png"):
            return cls.embed_watermark_image(content_bytes, watermark_id, format_hint="PNG")
        elif content_bytes.startswith(b"\xff\xd8\xff") or fname_lower.endswith((".jpg", ".jpeg")):
            return cls.embed_watermark_image(content_bytes, watermark_id, format_hint="JPEG")
        elif fname_lower.endswith(".txt"):
            return cls.embed_watermark_text(content_bytes, watermark_id)
        else:
            # Check if valid image
            try:
                from PIL import Image
                Image.open(io.BytesIO(content_bytes))
                return cls.embed_watermark_image(content_bytes, watermark_id)
            except Exception:
                pass
            # Try text embedding if utf-8
            try:
                content_bytes.decode("utf-8")
                return cls.embed_watermark_text(content_bytes, watermark_id)
            except Exception:
                pass
            return content_bytes

