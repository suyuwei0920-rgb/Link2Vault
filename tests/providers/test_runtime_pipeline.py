from __future__ import annotations

import wave

import pytest
from link2vault.config import Settings
from link2vault.domain.tasks import CaptureSource, TaskStatus
from link2vault.ingest.douyin_resolver import ResolvedTarget
from link2vault.providers.runtime import build_runtime_pipeline
from link2vault.storage.task_repository import TaskRepository


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _write_silent_wav(path, seconds: int = 1) -> None:
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(b"\0\0" * 8000 * seconds)


@pytest.mark.anyio
async def test_runtime_fetches_douyin_media_and_persists_probed_duration(tmp_path) -> None:
    media = tmp_path / "downloaded.wav"
    _write_silent_wav(media)

    class Resolver:
        async def resolve(self, _share_text: str) -> ResolvedTarget:
            return ResolvedTarget(
                kind="video",
                canonical_url="https://" + "www." + "douyin.com/video/1234567890",
                media_candidates=(
                    "https://" + "v3." + "douyinvod.com/synthetic.mp4",
                ),
                title="Synthetic title",
            )

    class Downloader:
        async def download(self, _candidates, _task_id):
            return media

    settings = Settings(
        data_dir=tmp_path / "data",
        media_tmp_dir=tmp_path,
        vault_root=tmp_path / "vault",
    )
    repository = TaskRepository(settings.data_dir)
    created = repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="synthetic-runtime",
        input_ref="https://" + "v." + "douyin.com/synthetic/",
    )
    repository.claim_next("worker-a")
    pipeline = build_runtime_pipeline(
        settings,
        repository,
        douyin_resolver=Resolver(),
        media_downloader=Downloader(),
    )

    completed = await pipeline.run(created.id)

    assert completed.status is TaskStatus.COMPLETED
    assert completed.media_seconds == pytest.approx(1.0, abs=0.05)
    assert completed.artifacts["fetching"] == str(media)
