from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


def _create_dossier(client, admin, code="PROC-DOC-001"):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": f"V-{code}",
            "building": "科研楼",
            "room": "保密室",
            "cabinet": "柜一",
            "shelf": "一层",
            "sensitivity": "critical",
            "capacity_units": 20,
        },
    )
    assert vault.status_code == 201, vault.text
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"IN-{code}", "project_code": "P-OMEGA", "expected_count": 1},
    )
    assert batch.status_code == 201, batch.text
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": code,
            "intake_id": batch.json()["id"],
            "asset_type": "工艺技术文档",
            "quantity": 1,
            "unit": "份",
            "vault_id": vault.json()["id"],
        },
    )
    assert dossier.status_code == 201, dossier.text
    return dossier.json()


def _issue_payload(key="issue-0001"):
    return {
        "idempotency_key": key,
        "copies": [
            {"recipient": "华科材料有限公司", "purpose": "联合开发评审", "copy_format": "paper", "valid_until": "2027-03-31T00:00:00+00:00"},
            {"recipient": "华科材料有限公司", "purpose": "联合开发评审", "copy_format": "electronic", "valid_until": "2027-03-31T00:00:00+00:00"},
            {"recipient": "北方精密制造厂", "purpose": "委托加工试产", "copy_format": "paper", "valid_until": "2026-12-31T00:00:00+00:00"},
        ],
        "note": "三家合作单位受控分发",
    }


def _issue(client, admin, dossier_id, key="issue-0001"):
    response = client.post(
        f"/api/dossiers/{dossier_id}/controlled-copies",
        headers=admin["headers"],
        json=_issue_payload(key),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_batch_issue_generates_distinct_numbers_and_watermarks(client, admin):
    dossier = _create_dossier(client, admin)
    result = _issue(client, admin, dossier["id"])
    assert result["replayed"] is False
    batch = result["batch"]
    assert batch["batch_code"] == "CCB-PROC-DOC-001-001"
    assert batch["source_version"] == dossier["version"]
    assert batch["source_snapshot"]["dossier_code"] == "PROC-DOC-001"
    assert batch["source_snapshot"]["version"] == dossier["version"]
    assert len(batch["snapshot_digest"]) == 64
    copies = result["copies"]
    numbers = [copy["copy_number"] for copy in copies]
    assert len(set(numbers)) == 3
    assert numbers[0] == "CC-PROC-DOC-001-001-01P"
    assert numbers[1] == "CC-PROC-DOC-001-001-02E"
    assert numbers[2] == "CC-PROC-DOC-001-001-03P"
    assert [copy["copy_format"] for copy in copies] == ["paper", "electronic", "paper"]
    first = copies[0]["watermark"]
    assert first["copy_number"] == numbers[0]
    assert first["recipient"] == "华科材料有限公司"
    assert first["purpose"] == "联合开发评审"
    assert first["valid_until"] == "2027-03-31T00:00:00+00:00"
    assert first["source_version"] == dossier["version"]
    assert first["snapshot_digest"] == batch["snapshot_digest"]
    assert all(len(copy["watermark_digest"]) == 64 for copy in copies)
    assert all(copy["effective_status"] == "active" for copy in copies)


def test_issue_is_idempotent_and_rejects_conflicting_replay(client, admin):
    dossier = _create_dossier(client, admin)
    first = _issue(client, admin, dossier["id"])
    second = _issue(client, admin, dossier["id"])
    assert second["replayed"] is True
    assert second["batch"]["id"] == first["batch"]["id"]
    assert [copy["id"] for copy in second["copies"]] == [copy["id"] for copy in first["copies"]]
    listing = client.get(f"/api/dossiers/{dossier['id']}/controlled-copies", headers=admin["headers"])
    assert len(listing.json()) == 3
    changed = _issue_payload("issue-0001")
    changed["copies"][0]["purpose"] = "变更后的用途"
    conflict = client.post(
        f"/api/dossiers/{dossier['id']}/controlled-copies",
        headers=admin["headers"],
        json=changed,
    )
    assert conflict.status_code == 409


def test_issue_rejects_past_valid_until(client, admin):
    dossier = _create_dossier(client, admin)
    payload = _issue_payload("issue-past")
    payload["copies"] = [
        {"recipient": "华科材料有限公司", "purpose": "联合开发评审", "copy_format": "paper", "valid_until": "2020-01-01T00:00:00+00:00"}
    ]
    response = client.post(f"/api/dossiers/{dossier['id']}/controlled-copies", headers=admin["headers"], json=payload)
    assert response.status_code == 422


def test_revoke_single_copy_blocks_loan_and_disclosure(client, admin):
    dossier = _create_dossier(client, admin)
    issued = _issue(client, admin, dossier["id"])
    target = issued["copies"][0]
    revoked = client.post(
        f"/api/dossiers/controlled-copies/{target['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "合作终止，收回纸质副本"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["effective_status"] == "revoked"
    assert revoked.json()["revoke_reason"] == "合作终止，收回纸质副本"
    again = client.post(
        f"/api/dossiers/controlled-copies/{target['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "重复撤回"},
    )
    assert again.status_code == 409
    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={
            "dossier_id": dossier["id"],
            "requester_user_id": admin["body"]["user"]["id"],
            "quantity": 1,
            "due_at": "2026-12-01T00:00:00+00:00",
            "controlled_copy_id": target["id"],
        },
    )
    assert loan.status_code == 409
    disclosure = client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={"recipient_code": "EXT-01", "quantity": 1, "idempotency_key": "disc-revoked", "controlled_copy_id": target["id"]},
    )
    assert disclosure.status_code == 409
    active_copy = issued["copies"][1]
    ok_loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={
            "dossier_id": dossier["id"],
            "requester_user_id": admin["body"]["user"]["id"],
            "quantity": 1,
            "due_at": "2026-12-01T00:00:00+00:00",
            "controlled_copy_id": active_copy["id"],
        },
    )
    assert ok_loan.status_code == 201, ok_loan.text
    assert ok_loan.json()["controlled_copy_id"] == active_copy["id"]


def test_freeze_batch_blocks_every_copy(client, admin):
    dossier = _create_dossier(client, admin)
    issued = _issue(client, admin, dossier["id"])
    batch_id = issued["batch"]["id"]
    frozen = client.post(
        f"/api/dossiers/controlled-copy-batches/{batch_id}/freeze",
        headers=admin["headers"],
        json={"reason": "发现版本外发错误，整批冻结"},
    )
    assert frozen.status_code == 200, frozen.text
    assert frozen.json()["batch"]["status"] == "frozen"
    assert frozen.json()["batch"]["freeze_reason"] == "发现版本外发错误，整批冻结"
    assert frozen.json()["affected_copies"] == 3
    again = client.post(
        f"/api/dossiers/controlled-copy-batches/{batch_id}/freeze",
        headers=admin["headers"],
        json={"reason": "重复冻结"},
    )
    assert again.status_code == 409
    for copy in issued["copies"]:
        loan = client.post(
            "/api/dossiers/access_loans",
            headers=admin["headers"],
            json={
                "dossier_id": dossier["id"],
                "requester_user_id": admin["body"]["user"]["id"],
                "quantity": 1,
                "due_at": "2026-12-01T00:00:00+00:00",
                "controlled_copy_id": copy["id"],
            },
        )
        assert loan.status_code == 409
        disclosure = client.post(
            f"/api/dossiers/{dossier['id']}/disclosures",
            headers=admin["headers"],
            json={
                "recipient_code": "EXT-02",
                "quantity": 1,
                "idempotency_key": f"disc-frozen-{copy['id']}",
                "controlled_copy_id": copy["id"],
            },
        )
        assert disclosure.status_code == 409
    listing = client.get(
        f"/api/dossiers/{dossier['id']}/controlled-copies",
        headers=admin["headers"],
        params={"status": "frozen"},
    )
    assert len(listing.json()) == 3


def test_query_lists_active_and_revoked_with_reasons(client, admin):
    dossier = _create_dossier(client, admin)
    issued = _issue(client, admin, dossier["id"])
    revoked_copy = issued["copies"][2]
    client.post(
        f"/api/dossiers/controlled-copies/{revoked_copy['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "接收方资质到期"},
    )
    all_copies = client.get(f"/api/dossiers/{dossier['id']}/controlled-copies", headers=admin["headers"])
    assert all_copies.status_code == 200
    assert len(all_copies.json()) == 3
    active = client.get(
        f"/api/dossiers/{dossier['id']}/controlled-copies", headers=admin["headers"], params={"status": "active"}
    )
    assert {copy["copy_number"] for copy in active.json()} == {
        issued["copies"][0]["copy_number"],
        issued["copies"][1]["copy_number"],
    }
    revoked = client.get(
        f"/api/dossiers/{dossier['id']}/controlled-copies", headers=admin["headers"], params={"status": "revoked"}
    )
    assert len(revoked.json()) == 1
    assert revoked.json()[0]["revoke_reason"] == "接收方资质到期"
    assert revoked.json()[0]["revoked_at"] is not None
    batch = client.get(f"/api/dossiers/controlled-copy-batches/{issued['batch']['id']}", headers=admin["headers"])
    assert batch.status_code == 200
    assert batch.json()["batch"]["source_snapshot"]["dossier_code"] == "PROC-DOC-001"
    assert len(batch.json()["copies"]) == 3


def test_copy_from_other_dossier_is_rejected(client, admin):
    first = _create_dossier(client, admin, "PROC-DOC-001")
    second = _create_dossier(client, admin, "PROC-DOC-002")
    issued = _issue(client, admin, first["id"])
    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={
            "dossier_id": second["id"],
            "requester_user_id": admin["body"]["user"]["id"],
            "quantity": 1,
            "due_at": "2026-12-01T00:00:00+00:00",
            "controlled_copy_id": issued["copies"][0]["id"],
        },
    )
    assert loan.status_code == 422


def test_disclosure_with_active_copy_records_reference(client, admin):
    dossier = _create_dossier(client, admin, "PROC-DOC-009")
    client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={
            "requested_quantity": 1,
            "children": [{"dossier_code": "PROC-DOC-009-A", "quantity": 1}],
        },
    )
    parent = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    child_id = parent["children"][0]["id"]
    issued = _issue(client, admin, child_id)
    copy_id = issued["copies"][0]["id"]
    disclosure = client.post(
        f"/api/dossiers/{child_id}/disclosures",
        headers=admin["headers"],
        json={"recipient_code": "EXT-09", "quantity": 1, "idempotency_key": "disc-active", "controlled_copy_id": copy_id},
    )
    assert disclosure.status_code == 201, disclosure.text
    assert disclosure.json()["record"]["controlled_copy_id"] == copy_id


def test_expired_copy_cannot_be_used(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCHIVE_DATABASE_PATH", str(tmp_path / "expiry.db"))
    from app.database import close_connection, get_connection, init_db
    from app.core.clock import FrozenClock, to_storage
    from app.core.errors import ConflictError
    from app.core.security import Principal
    from app.archives.controlled_copies import ControlledCopyService, ensure_copy_usable
    from app.archives.service import DossierLifecycleService

    close_connection()
    init_db()
    connection = get_connection()
    clock = FrozenClock(datetime(2026, 9, 26, 8, 0, 0, tzinfo=UTC))
    now = to_storage(clock.now())
    connection.execute(
        "INSERT INTO users(username,password_hash,display_name,status,password_changed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        ("manager", "x", "研发负责人", "active", now, now, now),
    )
    principal = Principal(user_id=1, username="manager", display_name="研发负责人", department_id=None, permissions=frozenset({"*"}), session_id=1)
    lifecycle = DossierLifecycleService(connection, clock)
    batch = lifecycle.create_batch(principal, {"intake_code": "IN-EXP", "project_code": "P-EXP", "expected_count": 1})
    dossier = lifecycle.register_dossier(
        principal,
        {"dossier_code": "EXP-DOC", "intake_id": batch["id"], "asset_type": "工艺技术文档", "quantity": 1, "unit": "份", "vault_id": None},
    )
    service = ControlledCopyService(connection, clock)
    issued = service.issue_batch(
        principal,
        dossier["id"],
        {
            "idempotency_key": "exp-key",
            "copies": [
                {
                    "recipient": "华科材料有限公司",
                    "purpose": "联合开发评审",
                    "copy_format": "electronic",
                    "valid_from": None,
                    "valid_until": to_storage(clock.now() + timedelta(hours=1)),
                }
            ],
            "note": "",
        },
    )
    copy_id = issued["copies"][0]["id"]
    ensure_copy_usable(connection, copy_id, dossier["id"], clock.now())
    clock.advance(hours=2)
    with pytest.raises(ConflictError):
        ensure_copy_usable(connection, copy_id, dossier["id"], clock.now())
    expired = service.list_copies(principal, dossier["id"], "expired")
    assert len(expired) == 1
    assert expired[0]["effective_status_label"] == "已过期"
    assert service.list_copies(principal, dossier["id"], "active") == []
    close_connection()
