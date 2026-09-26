"""受控副本清单：批量签发、单份撤回、整批冻结与有效性校验。

在既有副本签发能力之上，为纸质与电子受控副本建立独立台账：
每次批量签发把来源档案锁定到签发时刻的版本快照，按接收方、用途和
有效期生成不可混淆的副本编号与水印元数据；撤回与冻结会立即阻断
后续借阅和披露登记，签发通过幂等键保证重复点击不会多发副本。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository, row_dict
from app.archives.validation import parse_timestamp
from app.services.audit import AuditService

COPY_FORMAT_SUFFIX = {"paper": "P", "electronic": "E"}

EFFECTIVE_STATUS_LABELS = {"active": "有效", "revoked": "已撤回", "frozen": "已冻结", "expired": "已过期"}

_BLOCKED_STATES = {"disposed", "pending_disposal", "quarantined"}


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def effective_status(copy: dict[str, Any], now: datetime) -> str:
    """汇总副本撤回、批次冻结与有效期，得出副本当前有效状态。"""
    if copy["status"] == "revoked":
        return "revoked"
    if copy.get("batch_status") == "frozen":
        return "frozen"
    valid_until = from_storage(copy["valid_until"])
    if valid_until is not None and now >= valid_until:
        return "expired"
    return "active"


def ensure_copy_usable(connection: sqlite3.Connection, copy_id: int, dossier_id: int, now: datetime) -> dict[str, Any]:
    """借阅或披露登记引用受控副本时，确认副本归属该档案且当前有效。"""
    row = connection.execute(
        """SELECT c.*,b.status AS batch_status FROM controlled_copies c
           JOIN controlled_copy_batches b ON b.id=c.batch_id WHERE c.id=?""",
        (copy_id,),
    ).fetchone()
    if not row:
        raise NotFoundError("受控副本不存在")
    copy = dict(row)
    if copy["dossier_id"] != dossier_id:
        raise ValidationError("受控副本不属于该档案")
    status = effective_status(copy, now)
    if status != "active":
        raise ConflictError(f"受控副本{EFFECTIVE_STATUS_LABELS[status]}，禁止继续借阅或披露登记")
    return copy


class ControlledCopyRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def next_sequence(self, dossier_id: int) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM controlled_copy_batches WHERE dossier_id=?", (dossier_id,)
        ).fetchone()
        return int(row[0]) + 1

    def create_batch(self, values: dict[str, Any]) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO controlled_copy_batches(
                   batch_code,dossier_id,source_version,source_snapshot_json,snapshot_digest,
                   idempotency_key,request_digest,status,operator_user_id,note,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,'active',?,?,?,?)""",
            (
                values["batch_code"], values["dossier_id"], values["source_version"],
                values["source_snapshot_json"], values["snapshot_digest"], values["idempotency_key"],
                values["request_digest"], values["operator_user_id"], values["note"],
                values["now"], values["now"],
            ),
        )
        return self.get_batch(cursor.lastrowid)

    def get_batch(self, batch_id: int) -> dict[str, Any]:
        return row_dict(
            self.connection.execute("SELECT * FROM controlled_copy_batches WHERE id=?", (batch_id,)).fetchone()
        )

    def batch_by_idempotency(self, dossier_id: int, idempotency_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM controlled_copy_batches WHERE dossier_id=? AND idempotency_key=?",
            (dossier_id, idempotency_key),
        ).fetchone()
        return dict(row) if row else None

    def create_copy(self, values: dict[str, Any]) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO controlled_copies(
                   copy_number,batch_id,dossier_id,recipient,purpose,copy_format,
                   watermark_json,watermark_digest,valid_from,valid_until,status,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,'active',?,?)""",
            (
                values["copy_number"], values["batch_id"], values["dossier_id"], values["recipient"],
                values["purpose"], values["copy_format"], values["watermark_json"], values["watermark_digest"],
                values["valid_from"], values["valid_until"], values["now"], values["now"],
            ),
        )
        return self.get_copy(cursor.lastrowid)

    def get_copy(self, copy_id: int) -> dict[str, Any]:
        return row_dict(
            self.connection.execute(
                """SELECT c.*,b.status AS batch_status,b.batch_code FROM controlled_copies c
                   JOIN controlled_copy_batches b ON b.id=c.batch_id WHERE c.id=?""",
                (copy_id,),
            ).fetchone()
        )

    def copies_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT c.*,b.status AS batch_status,b.batch_code FROM controlled_copies c
               JOIN controlled_copy_batches b ON b.id=c.batch_id WHERE c.batch_id=? ORDER BY c.id""",
            (batch_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def copies_for_dossier(self, dossier_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT c.*,b.status AS batch_status,b.batch_code FROM controlled_copies c
               JOIN controlled_copy_batches b ON b.id=c.batch_id WHERE c.dossier_id=? ORDER BY c.id""",
            (dossier_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def revoke_copy(self, copy_id: int, operator_user_id: int, reason: str, now: str) -> dict[str, Any]:
        updated = self.connection.execute(
            """UPDATE controlled_copies SET status='revoked',revoked_at=?,revoked_by=?,revoke_reason=?,
               version=version+1,updated_at=? WHERE id=? AND status='active'""",
            (now, operator_user_id, reason, now, copy_id),
        )
        if updated.rowcount != 1:
            raise ConflictError("受控副本已撤回，不能重复操作")
        return self.get_copy(copy_id)

    def freeze_batch(self, batch_id: int, operator_user_id: int, reason: str, now: str) -> dict[str, Any]:
        updated = self.connection.execute(
            """UPDATE controlled_copy_batches SET status='frozen',frozen_at=?,frozen_by=?,freeze_reason=?,
               version=version+1,updated_at=? WHERE id=? AND status='active'""",
            (now, operator_user_id, reason, now, batch_id),
        )
        if updated.rowcount != 1:
            raise ConflictError("签发批次已冻结，不能重复操作")
        return self.get_batch(batch_id)


class ControlledCopyService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.copies = ControlledCopyRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def issue_batch(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        dossier = self.dossiers.get(dossier_id)
        if dossier["lifecycle_state"] in _BLOCKED_STATES:
            raise ConflictError("当前状态禁止签发受控副本")
        request_digest = _digest({"copies": data["copies"], "note": data.get("note", "")})
        existing = self.copies.batch_by_idempotency(dossier_id, data["idempotency_key"])
        if existing:
            if existing["request_digest"] != request_digest:
                raise ConflictError("幂等键已被不同的签发请求占用")
            now = self.clock.now()
            return {
                "batch": self._present_batch(existing),
                "copies": [self._present_copy(row, now) for row in self.copies.copies_for_batch(existing["id"])],
                "replayed": True,
            }
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        normalized = []
        for item in data["copies"]:
            valid_from = parse_timestamp(item["valid_from"], "有效期起始") if item.get("valid_from") else now_dt
            valid_until = parse_timestamp(item["valid_until"], "有效期截止")
            if valid_until <= valid_from:
                raise ValidationError("有效期截止必须晚于有效期起始")
            normalized.append({**item, "valid_from": to_storage(valid_from), "valid_until": to_storage(valid_until)})
        sequence = self.copies.next_sequence(dossier_id)
        batch_code = f"CCB-{dossier['dossier_code']}-{sequence:03d}"
        snapshot = {
            "dossier_id": dossier["id"],
            "dossier_code": dossier["dossier_code"],
            "asset_type": dossier["asset_type"],
            "intake_id": dossier["intake_id"],
            "intake_code": dossier["intake_code"],
            "root_dossier_id": dossier["root_dossier_id"],
            "source_dossier_id": dossier["source_dossier_id"],
            "quantity": dossier["quantity"],
            "reserved_quantity": dossier["reserved_quantity"],
            "unit": dossier["unit"],
            "lifecycle_state": dossier["lifecycle_state"],
            "vault_id": dossier["vault_id"],
            "vault_code": dossier["vault_code"],
            "version": dossier["version"],
            "captured_at": now,
        }
        snapshot_digest = _digest(snapshot)
        batch = self.copies.create_batch(
            {
                "batch_code": batch_code,
                "dossier_id": dossier_id,
                "source_version": dossier["version"],
                "source_snapshot_json": _canonical(snapshot),
                "snapshot_digest": snapshot_digest,
                "idempotency_key": data["idempotency_key"],
                "request_digest": request_digest,
                "operator_user_id": principal.user_id,
                "note": data.get("note", ""),
                "now": now,
            }
        )
        copies = []
        for index, item in enumerate(normalized, start=1):
            copy_number = f"CC-{dossier['dossier_code']}-{sequence:03d}-{index:02d}{COPY_FORMAT_SUFFIX[item['copy_format']]}"
            watermark = {
                "copy_number": copy_number,
                "batch_code": batch_code,
                "dossier_id": dossier["id"],
                "dossier_code": dossier["dossier_code"],
                "source_version": dossier["version"],
                "snapshot_digest": snapshot_digest,
                "recipient": item["recipient"],
                "purpose": item["purpose"],
                "copy_format": item["copy_format"],
                "valid_from": item["valid_from"],
                "valid_until": item["valid_until"],
                "issued_at": now,
                "issued_by": principal.user_id,
            }
            copies.append(
                self.copies.create_copy(
                    {
                        "copy_number": copy_number,
                        "batch_id": batch["id"],
                        "dossier_id": dossier_id,
                        "recipient": item["recipient"],
                        "purpose": item["purpose"],
                        "copy_format": item["copy_format"],
                        "watermark_json": _canonical(watermark),
                        "watermark_digest": _digest(watermark),
                        "valid_from": item["valid_from"],
                        "valid_until": item["valid_until"],
                        "now": now,
                    }
                )
            )
        self.dossiers.append_event(
            dossier_id,
            "controlled_copy.issued",
            principal.user_id,
            now,
            details={
                "batch_code": batch_code,
                "source_version": dossier["version"],
                "copy_count": len(copies),
                "copy_numbers": [copy["copy_number"] for copy in copies],
            },
        )
        self.audit.record(
            principal,
            "controlled_copy.issue",
            "controlled_copy_batch",
            str(batch["id"]),
            after=self._present_batch(batch),
            metadata={"copy_count": len(copies), "idempotency_key": data["idempotency_key"]},
        )
        return {
            "batch": self._present_batch(batch),
            "copies": [self._present_copy(row, now_dt) for row in copies],
            "replayed": False,
        }

    def revoke_copy(self, principal: Principal, copy_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        before = self.copies.get_copy(copy_id)
        if before["status"] == "revoked":
            raise ConflictError("受控副本已撤回，不能重复操作")
        now = to_storage(self.clock.now())
        updated = self.copies.revoke_copy(copy_id, principal.user_id, data["reason"], now)
        self.dossiers.append_event(
            before["dossier_id"],
            "controlled_copy.revoked",
            principal.user_id,
            now,
            details={"copy_number": before["copy_number"], "batch_code": before["batch_code"], "reason": data["reason"]},
        )
        self.audit.record(
            principal,
            "controlled_copy.revoke",
            "controlled_copy",
            str(copy_id),
            before=before,
            after=updated,
            metadata={"reason": data["reason"]},
        )
        return self._present_copy(updated, self.clock.now())

    def freeze_batch(self, principal: Principal, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        before = self.copies.get_batch(batch_id)
        if before["status"] == "frozen":
            raise ConflictError("签发批次已冻结，不能重复操作")
        now = to_storage(self.clock.now())
        updated = self.copies.freeze_batch(batch_id, principal.user_id, data["reason"], now)
        affected = self.connection.execute(
            "SELECT COUNT(*) FROM controlled_copies WHERE batch_id=? AND status='active'", (batch_id,)
        ).fetchone()[0]
        self.dossiers.append_event(
            before["dossier_id"],
            "controlled_copy.frozen",
            principal.user_id,
            now,
            details={"batch_code": before["batch_code"], "reason": data["reason"], "affected_copies": affected},
        )
        self.audit.record(
            principal,
            "controlled_copy.freeze",
            "controlled_copy_batch",
            str(batch_id),
            before=self._present_batch(before),
            after=self._present_batch(updated),
            metadata={"reason": data["reason"], "affected_copies": affected},
        )
        return {"batch": self._present_batch(updated), "affected_copies": affected}

    def list_copies(self, principal: Principal, dossier_id: int, status_filter: str) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        self.dossiers.get(dossier_id)
        now = self.clock.now()
        copies = [self._present_copy(row, now) for row in self.copies.copies_for_dossier(dossier_id)]
        if status_filter != "all":
            copies = [copy for copy in copies if copy["effective_status"] == status_filter]
        return copies

    def get_batch(self, principal: Principal, batch_id: int) -> dict[str, Any]:
        principal.require("dossiers.read")
        batch = self.copies.get_batch(batch_id)
        now = self.clock.now()
        return {
            "batch": self._present_batch(batch),
            "copies": [self._present_copy(row, now) for row in self.copies.copies_for_batch(batch_id)],
        }

    def _present_batch(self, batch: dict[str, Any]) -> dict[str, Any]:
        result = dict(batch)
        result["source_snapshot"] = json.loads(result.pop("source_snapshot_json"))
        return result

    def _present_copy(self, copy: dict[str, Any], now: datetime) -> dict[str, Any]:
        result = dict(copy)
        result["watermark"] = json.loads(result.pop("watermark_json"))
        result["effective_status"] = effective_status(copy, now)
        result["effective_status_label"] = EFFECTIVE_STATUS_LABELS[result["effective_status"]]
        return result
