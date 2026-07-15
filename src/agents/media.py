"""Shared media intake for El Guardián and the Goalie.

Turns an uploaded photo, PDF, or video into a Gemini content part so the same
analysis flow can "see" the file. Nothing is persisted — bytes live only for the
length of the request, and any file pushed to the Gemini Files API (video) is
deleted right after the model reads it.
"""

import os
import tempfile
import time

from google.genai import types

MB = 1024 * 1024

# Client-facing caps. Images and PDFs go inline (Gemini's inline request budget
# is ~20MB); video is routed through the Files API so it can be larger.
MAX_IMAGE_BYTES = 15 * MB
MAX_PDF_BYTES = 18 * MB
MAX_VIDEO_BYTES = 50 * MB

ALLOWED_IMAGE = {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/heic", "image/heif"}
ALLOWED_VIDEO = {"video/mp4", "video/quicktime", "video/webm", "video/x-msvideo", "video/mpeg", "video/3gpp"}
ALLOWED_PDF = {"application/pdf"}

# Phone file pickers routinely hand us "" or "application/octet-stream" instead of
# a real type — especially for PDFs. Fall back to the filename extension so a
# perfectly good upload isn't rejected, and so Gemini gets a usable mime_type.
EXT_MIME = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".mov": "video/quicktime",
    ".webm": "video/webm",
    ".3gp": "video/3gpp",
    ".mpeg": "video/mpeg",
    ".mpg": "video/mpeg",
    ".avi": "video/x-msvideo",
}


class MediaError(Exception):
    """Raised when an upload is rejected (bad type or too large)."""


def kind_for(mime: str) -> str | None:
    mime = (mime or "").lower().split(";")[0].strip()
    if mime in ALLOWED_IMAGE:
        return "image"
    if mime in ALLOWED_PDF:
        return "pdf"
    if mime in ALLOWED_VIDEO:
        return "video"
    return None


def resolve_mime(mime: str, filename: str = "") -> str:
    """Best-effort real mime type: trust a known one, else read the extension."""
    m = (mime or "").lower().split(";")[0].strip()
    if kind_for(m):
        return m
    ext = os.path.splitext(filename or "")[1].lower()
    return EXT_MIME.get(ext, m)


def validate(mime: str, size: int, filename: str = "") -> tuple[str, str]:
    """Return (kind, resolved_mime), or raise MediaError with a human message."""
    resolved = resolve_mime(mime, filename)
    kind = kind_for(resolved)
    if not kind:
        raise MediaError(
            "Unsupported file type. Send a photo (JPG/PNG/WebP/HEIC), a PDF, or a video (MP4/MOV/WebM)."
        )
    cap = {"image": MAX_IMAGE_BYTES, "pdf": MAX_PDF_BYTES, "video": MAX_VIDEO_BYTES}[kind]
    if size > cap:
        raise MediaError(f"That {kind} is too large — keep it under {cap // MB}MB.")
    if size <= 0:
        raise MediaError("The file appears to be empty.")
    return kind, resolved


class MediaAttachment:
    """A validated upload ready to hand to Gemini.

    Use as a context manager so any remote Files API upload is cleaned up::

        with MediaAttachment(client, raw, mime) as parts:
            client.models.generate_content(..., contents=[text, *parts])
    """

    def __init__(self, client, raw: bytes, mime: str, filename: str = ""):
        self.client = client
        self.raw = raw
        # Resolve first so Gemini always receives a real mime_type, even when the
        # phone sent "" or application/octet-stream.
        self.kind, self.mime = validate(mime, len(raw), filename)
        self._remote_name: str | None = None

    def __enter__(self) -> list:
        if self.kind == "video":
            return [self._upload_video()]
        return [types.Part.from_bytes(data=self.raw, mime_type=self.mime)]

    def _upload_video(self):
        """Push video through the Files API and wait for it to become ACTIVE."""
        suffix = {"video/mp4": ".mp4", "video/quicktime": ".mov", "video/webm": ".webm"}.get(self.mime, ".mp4")
        tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        try:
            tmp.write(self.raw)
            tmp.close()
            uploaded = self.client.files.upload(
                file=tmp.name,
                config=types.UploadFileConfig(mime_type=self.mime),
            )
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        self._remote_name = uploaded.name
        deadline = time.time() + 90  # free-tier safety valve
        while getattr(uploaded.state, "name", str(uploaded.state)) == "PROCESSING":
            if time.time() > deadline:
                raise MediaError("The video took too long to process — try a shorter clip.")
            time.sleep(1.5)
            uploaded = self.client.files.get(name=self._remote_name)
        if getattr(uploaded.state, "name", str(uploaded.state)) == "FAILED":
            raise MediaError("The video could not be processed — try re-exporting it as MP4.")
        # Return a Part (not the raw File) so it works both at the top level of
        # `contents` and nested inside a Content(parts=[...]) — the Goalie uses the
        # latter, which only accepts Part objects.
        return types.Part.from_uri(file_uri=uploaded.uri, mime_type=uploaded.mime_type or self.mime)

    def __exit__(self, *exc):
        if self._remote_name:
            try:
                self.client.files.delete(name=self._remote_name)
            except Exception:
                pass  # best-effort cleanup; the file expires on its own anyway
        return False
