"""Traffic analysis: PCAP upload and snapshot history (live capture runs in the sensor)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.api.schemas import Page, TrafficSnapshotDetail, TrafficSnapshotOut
from app.core.audit import record_event
from app.core.rbac import Perm
from app.database.models import TrafficSnapshot, User
from app.modules.traffic_monitor.capture import CaptureError
from app.services import operations

router = APIRouter(prefix="/traffic", tags=["traffic"])
Reader = Annotated[User, Depends(require(Perm.TRAFFIC_READ))]

#: pcap (both endiannesses, micro/nano-second) and pcapng magic numbers
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
CHUNK = 1024 * 1024


@router.post("/pcap", response_model=TrafficSnapshotDetail, summary="Upload and analyse a PCAP/PCAPNG file")
def upload_pcap(
    request: Request,
    file: UploadFile,
    user: Annotated[User, Depends(require(Perm.TRAFFIC_RUN))],
    db: DbDep,
    settings: SettingsDep,
) -> TrafficSnapshot:
    limit = settings.max_upload_mb * 1024 * 1024
    tmp_dir = settings.data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(suffix=".pcap", dir=tmp_dir)
    tmp_path = Path(tmp_name)
    try:
        size = 0
        with os.fdopen(fd, "wb") as handle:
            while chunk := file.file.read(CHUNK):
                if size == 0 and not chunk.startswith(PCAP_MAGICS):
                    raise HTTPException(status_code=415, detail="Not a PCAP/PCAPNG file")
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb} MB")
                handle.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="Empty file")
        try:
            snapshot = operations.analyze_traffic_file(db, settings, user.username, tmp_path)
        except CaptureError as exc:
            raise HTTPException(status_code=422, detail="Unreadable capture file") from exc
        snapshot.source = f"upload:{Path(file.filename or 'capture').name[:100]}"
        db.commit()
        record_event(
            db,
            actor=user.username,
            action="traffic.pcap",
            resource=snapshot.source,
            ip=client_ip(request),
            details={"snapshot_id": snapshot.id, "bytes": size},
        )
        return snapshot
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/snapshots", response_model=Page[TrafficSnapshotOut])
def list_snapshots(
    _: Reader,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[TrafficSnapshotOut]:
    total = db.scalar(select(func.count(TrafficSnapshot.id))) or 0
    rows = db.scalars(select(TrafficSnapshot).order_by(TrafficSnapshot.created_at.desc()).limit(limit).offset(offset))
    return Page[TrafficSnapshotOut](
        items=[TrafficSnapshotOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/latest", response_model=TrafficSnapshotDetail)
def latest(_: Reader, db: DbDep) -> TrafficSnapshot:
    snapshot = operations.latest_traffic(db)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="No traffic analysed yet")
    return snapshot


@router.get("/snapshots/{snapshot_id}", response_model=TrafficSnapshotDetail)
def get_snapshot(snapshot_id: int, _: Reader, db: DbDep) -> TrafficSnapshot:
    snapshot = db.get(TrafficSnapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot
