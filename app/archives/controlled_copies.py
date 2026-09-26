"""受控副本清单：批量签发、单份撤回、整批冻结与有效性校验。

受控副本是机密工艺文档对外发放的最小受控单位。每份副本在签发时
生成不可混淆的编号（介质码直接嵌入编号，纸质 P 与电子 E 不会混淆）
和水印元数据，并把来源档案的版本与关键字段快照锁定在批次上。
撤回或冻结后的副本禁止再用于查阅借阅和对外披露登记。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository
from app.archives.validation import parse_timestamp
from app.services.audit import AuditService

_MEDIUM_SUFFIX = {"paper": "P", "electronic": "E"}
_MEDIUM_LABEL = {"paper": "纸质", "electronic": "电子"}
_BLOCKED_STATES = {"disposed", "pending_disposal", "quarantined"}


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ControlledCopyService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------ 签发

    def issue_batch(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("controlled_copies.manage")
        dossier = self.dossiers.get(dossier_id)
        digest = hashlib.sha256(_canonical({"dossier_id": dossier_id, **data}).encode("utf-8")).hexdigest()
        existing = self._batch_by_key(dossier_id, data["idempotency_key"])
        if existing:
            if existing["request_digest"] != digest:
                raise ConflictError("同一幂等键不能用于不同的签发请求")
            return {**self._batch_payload(existing), "replayed": True}
        if dossier["lifecycle_state"] in _BLOCKED_STATES:
            raise ConflictError("当前状态禁止签发受控副本")
        if data.get("expected_source_version") and dossier["version"] != data["expected_source_version"]:
            raise ConflictError("档案版本已变化，请刷新后重试")
        now = to_storage(self.clock.now())
        windows = [self._valid_window(item, now) for item in data["copies"]]
        batch_code = self._new_batch_code(now)
        snapshot = {
            "dossier_id": dossier["id"],
            "dossier_code": dossier["dossier_code"],
            "asset_type": dossier["asset_type"],
            "quantity": dossier["quantity"],
            "unit": dossier["unit"],
            "lifecycle_state": dossier["lifecycle_state"],
            "vault_id": dossier["vault_id"],
            "version": dossier["version"],
            "snapshot_at": now,
        }
        cursor = self.connection.execute(
            """INSERT INTO controlled_copy_batches(
                   batch_code,source_dossier_id,source_version,source_snapshot_json,
                   idempotency_key,request_digest,state,operator_user_id,note,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,'active',?,?,?,?)""",
            (
                batch_code, dossier_id, dossier["version"], json.dumps(snapshot, ensure_ascii=False),
                data["idempotency_key"], digest, principal.user_id, data.get("note", ""), now, now,
            ),
        )
        batch_id = cursor.lastrowid
        copies = []
        for sequence, (item, (valid_from, valid_until)) in enumerate(zip(data["copies"], windows), start=1):
            copy_code = self._copy_code(batch_code, sequence, item["medium"])
            watermark = self._watermark(
                copy_code=copy_code,
                batch_code=batch_code,
                item=item,
                valid_from=valid_from,
                valid_until=valid_until,
                dossier=dossier,
                principal=principal,
                now=now,
            )
            cursor = self.connection.execute(
                """INSERT INTO controlled_copies(
                       copy_code,batch_id,dossier_id,recipient_code,purpose,medium,
                       valid_from,valid_until,watermark_json,state,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?)""",
                (
                    copy_code, batch_id, dossier_id, item["recipient_code"], item["purpose"],
                    item["medium"], valid_from, valid_until,
                    json.dumps(watermark, ensure_ascii=False), now, now,
                ),
            )
            copies.append(self._get_copy(cursor.lastrowid))
        self.dossiers.append_event(
            dossier_id,
            "controlled_copy_batch.issued",
            principal.user_id,
            now,
            details={
                "batch_code": batch_code,
                "copy_ids": [copy["id"] for copy in copies],
                "source_version": dossier["version"],
            },
        )
        batch = self._get_batch(batch_id)
        self.audit.record(
            principal,
            "controlled_copy_batch.issue",
            "controlled_copy_batch",
            str(batch_id),
            after={**batch, "copies": copies},
            metadata={"batch_code": batch_code, "source_version": dossier["version"]},
        )
        return {"batch": batch, "copies": copies, "replayed": False}

    # ------------------------------------------------------------------ 撤回与冻结

    def withdraw(self, principal: Principal, copy_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("controlled_copies.manage")
        before = self._get_copy(copy_id)
        if before["state"] == "withdrawn":
            return {"copy": before, "replayed": True}
        if before["state"] == "frozen":
            raise ConflictError("副本所在批次已冻结，不能再单独撤回")
        now = to_storage(self.clock.now())
        updated = self.connection.execute(
            """UPDATE controlled_copies SET state='withdrawn',state_reason=?,state_changed_at=?,updated_at=?
               WHERE id=? AND state='active'""",
            (data["reason"], now, now, copy_id),
        )
        if updated.rowcount != 1:
            raise ConflictError("副本状态已变化，请刷新后重试")
        copy = self._get_copy(copy_id)
        self.dossiers.append_event(
            copy["dossier_id"],
            "controlled_copy.withdrawn",
            principal.user_id,
            now,
            details={"copy_code": copy["copy_code"], "batch_code": copy["batch_code"], "reason": data["reason"]},
        )
        self.audit.record(principal, "controlled_copy.withdraw", "controlled_copy", str(copy_id), before=before, after=copy)
        return {"copy": copy, "replayed": False}

    def freeze_batch(self, principal: Principal, batch_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("controlled_copies.manage")
        before = self._get_batch(batch_id)
        if before["state"] == "frozen":
            return {"batch": before, "copies": self._batch_copies(batch_id), "replayed": True}
        now = to_storage(self.clock.now())
        updated = self.connection.execute(
            """UPDATE controlled_copy_batches SET state='frozen',frozen_at=?,frozen_reason=?,version=version+1,updated_at=?
               WHERE id=? AND state='active'""",
            (now, data["reason"], now, batch_id),
        )
        if updated.rowcount != 1:
            raise ConflictError("批次状态已变化，请刷新后重试")
        self.connection.execute(
            """UPDATE controlled_copies SET state='frozen',state_reason=?,state_changed_at=?,updated_at=?
               WHERE batch_id=? AND state='active'""",
            (f"批次冻结：{data['reason']}", now, now, batch_id),
        )
        batch = self._get_batch(batch_id)
        copies = self._batch_copies(batch_id)
        self.dossiers.append_event(
            batch["source_dossier_id"],
            "controlled_copy_batch.frozen",
            principal.user_id,
            now,
            details={
                "batch_code": batch["batch_code"],
                "reason": data["reason"],
                "frozen_copy_ids": [copy["id"] for copy in copies if copy["state"] == "frozen"],
            },
        )
        self.audit.record(principal, "controlled_copy_batch.freeze", "controlled_copy_batch", str(batch_id), before=before, after=batch)
        return {"batch": batch, "copies": copies, "replayed": False}

    # ------------------------------------------------------------------ 查询

    def list_copies(
        self,
        principal: Principal,
        *,
        dossier_id: int | None = None,
        batch_id: int | None = None,
        state: str | None = None,
    ) -> dict[str, Any]:
        principal.require("dossiers.read")
        if state and state not in {"active", "withdrawn", "frozen"}:
            raise ValidationError("副本状态过滤只支持 active、withdrawn、frozen")
        clauses: list[str] = []
        params: list[Any] = []
        if dossier_id:
            clauses.append("c.dossier_id=?")
            params.append(dossier_id)
        if batch_id:
            clauses.append("c.batch_id=?")
            params.append(batch_id)
        if state:
            clauses.append("c.state=?")
            params.append(state)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            """SELECT c.*,b.batch_code,b.state AS batch_state,b.source_version
               FROM controlled_copies c JOIN controlled_copy_batches b ON b.id=c.batch_id"""
            + where
            + " ORDER BY c.id",
            tuple(params),
        ).fetchall()
        now = to_storage(self.clock.now())
        copies = [self._present(dict(row), now) for row in rows]
        summary = {"active": 0, "withdrawn": 0, "frozen": 0, "expired": 0}
        for copy in copies:
            summary[copy["state"]] += 1
            if copy["expired"]:
                summary["expired"] += 1
        return {"copies": copies, "summary": summary}

    def get_batch(self, principal: Principal, batch_id: int) -> dict[str, Any]:
        principal.require("dossiers.read")
        return self._batch_payload(self._get_batch(batch_id))

    # ---------------------------------------------------------- 借阅/披露校验

    def assert_copy_usable(self, dossier_id: int, copy_id: int) -> dict[str, Any]:
        """借阅或披露登记前确认副本仍有效，撤回、冻结、过期一律拒绝。"""
        row = self.connection.execute(
            """SELECT c.*,b.batch_code,b.state AS batch_state
               FROM controlled_copies c JOIN controlled_copy_batches b ON b.id=c.batch_id
               WHERE c.id=?""",
            (copy_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("受控副本不存在")
        copy = dict(row)
        if copy["dossier_id"] != dossier_id:
            raise ValidationError("受控副本不属于该档案")
        if copy["batch_state"] == "frozen" or copy["state"] == "frozen":
            raise ConflictError("受控副本所在批次已冻结，禁止借阅和披露登记")
        if copy["state"] == "withdrawn":
            raise ConflictError("受控副本已撤回，禁止借阅和披露登记")
        if copy["valid_until"] < to_storage(self.clock.now()):
            raise ConflictError("受控副本已过有效期，禁止借阅和披露登记")
        return copy

    # ------------------------------------------------------------------ 内部

    def _valid_window(self, item: dict[str, Any], now: str) -> tuple[str, str]:
        valid_from = to_storage(parse_timestamp(item["valid_from"], "有效期开始")) if item.get("valid_from") else now
        valid_until = to_storage(parse_timestamp(item["valid_until"], "有效期截止"))
        if valid_until <= valid_from:
            raise ValidationError("有效期截止必须晚于有效期开始")
        return valid_from, valid_until

    def _new_batch_code(self, now: str) -> str:
        return f"CCB-{now[:10].replace('-', '')}-{uuid.uuid4().hex[:8].upper()}"

    def _copy_code(self, batch_code: str, sequence: int, medium: str) -> str:
        token = batch_code.rsplit("-", 1)[-1]
        return f"CC-{token}-{sequence:03d}-{_MEDIUM_SUFFIX[medium]}"

    def _watermark(
        self,
        *,
        copy_code: str,
        batch_code: str,
        item: dict[str, Any],
        valid_from: str,
        valid_until: str,
        dossier: dict[str, Any],
        principal: Principal,
        now: str,
    ) -> dict[str, Any]:
        payload = {
            "copy_code": copy_code,
            "batch_code": batch_code,
            "recipient_code": item["recipient_code"],
            "purpose": item["purpose"],
            "medium": item["medium"],
            "medium_label": _MEDIUM_LABEL[item["medium"]],
            "valid_from": valid_from,
            "valid_until": valid_until,
            "source_dossier_code": dossier["dossier_code"],
            "source_version": dossier["version"],
            "issued_by": principal.username,
            "issued_at": now,
        }
        return {**payload, "digest": hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()}

    def _batch_by_key(self, dossier_id: int, idempotency_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM controlled_copy_batches WHERE source_dossier_id=? AND idempotency_key=?",
            (dossier_id, idempotency_key),
        ).fetchone()
        return dict(row) if row else None

    def _get_batch(self, batch_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM controlled_copy_batches WHERE id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFoundError("受控副本批次不存在")
        batch = dict(row)
        batch["source_snapshot"] = json.loads(batch.pop("source_snapshot_json"))
        return batch

    def _get_copy(self, copy_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            """SELECT c.*,b.batch_code,b.state AS batch_state,b.source_version
               FROM controlled_copies c JOIN controlled_copy_batches b ON b.id=c.batch_id
               WHERE c.id=?""",
            (copy_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("受控副本不存在")
        return self._present(dict(row), to_storage(self.clock.now()))

    def _batch_copies(self, batch_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT c.*,b.batch_code,b.state AS batch_state,b.source_version
               FROM controlled_copies c JOIN controlled_copy_batches b ON b.id=c.batch_id
               WHERE c.batch_id=? ORDER BY c.id""",
            (batch_id,),
        ).fetchall()
        now = to_storage(self.clock.now())
        return [self._present(dict(row), now) for row in rows]

    def _batch_payload(self, batch: dict[str, Any]) -> dict[str, Any]:
        return {"batch": batch, "copies": self._batch_copies(batch["id"])}

    def _present(self, copy: dict[str, Any], now: str) -> dict[str, Any]:
        copy["watermark"] = json.loads(copy.pop("watermark_json"))
        copy["expired"] = copy["state"] == "active" and copy["valid_until"] < now
        if copy["state"] != "active":
            copy["effective_state"] = copy["state"]
        elif copy["batch_state"] == "frozen":
            copy["effective_state"] = "frozen"
        elif copy["expired"]:
            copy["effective_state"] = "expired"
        else:
            copy["effective_state"] = "active"
        return copy
