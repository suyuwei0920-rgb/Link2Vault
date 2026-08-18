from __future__ import annotations

import io
import wave

import pytest
from link2vault.media.probe import MediaRejected, probe_media
from link2vault.media.uploads import stream_upload


class FakeUpload:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        filename: str = "meeting.wav",
        content_type: str = "audio/wav",
    ) -> None:
        self._chunks = iter(chunks)
        self.filename = filename
        self.content_type = content_type
        self.read_sizes: list[int] = []

    async def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return next(self._chunks, b"")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_streams_chunks_to_server_generated_partial_file(tmp_path) -> None:
    upload = FakeUpload([b"first", b"second"])

    receipt = await stream_upload(upload, tmp_path, max_bytes=1024)

    assert receipt.path.parent == tmp_path
    assert receipt.path.suffixes == [".wav", ".partial"]
    assert receipt.path.name != "meeting.wav.partial"
    assert receipt.path.read_bytes() == b"firstsecond"
    assert receipt.size_bytes == 11
    assert all(size == 1024 * 1024 for size in upload.read_sizes)


@pytest.mark.anyio
async def test_rejects_extension_mime_mismatch_without_orphan(tmp_path) -> None:
    upload = FakeUpload(
        [b"not-a-recording"],
        filename="meeting.exe",
        content_type="audio/wav",
    )

    with pytest.raises(MediaRejected, match="type"):
        await stream_upload(upload, tmp_path, max_bytes=1024)

    assert list(tmp_path.iterdir()) == []


@pytest.mark.anyio
async def test_enforces_stream_limit_without_allocating_the_declared_limit(tmp_path) -> None:
    chunk = b"x" * (1024 * 1024)
    upload = FakeUpload([chunk, chunk, b"overflow"])

    with pytest.raises(MediaRejected, match="large"):
        await stream_upload(upload, tmp_path, max_bytes=2 * 1024 * 1024)

    assert list(tmp_path.iterdir()) == []


def test_probe_rejects_truncated_or_invalid_media(tmp_path) -> None:
    invalid = tmp_path / "invalid.wav"
    invalid.write_bytes(b"RIFF-truncated")

    with pytest.raises(MediaRejected, match="valid audio"):
        probe_media(invalid)


def test_probe_returns_duration_for_supported_audio(tmp_path) -> None:
    audio = tmp_path / "valid.wav"
    with wave.open(str(audio), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16_000)
        output.writeframes(io.BytesIO(b"\x00\x00" * 16_000).getvalue())

    info = probe_media(audio)

    assert info.duration_seconds == pytest.approx(1.0, abs=0.02)
    assert info.codec_name == "pcm_s16le"
