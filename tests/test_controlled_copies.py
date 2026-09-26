from __future__ import annotations


def _bootstrap_dossier(client, admin):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": "CC-VAULT-01",
            "building": "档案楼",
            "room": "机密库",
            "cabinet": "一号柜",
            "shelf": "三层",
            "sensitivity": "restricted",
            "capacity_units": 50,
        },
    ).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "CC-BATCH-001", "project_code": "P-SECRET", "expected_count": 1},
    ).json()
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": "CC-DOC-001",
            "intake_id": batch["id"],
            "asset_type": "工艺技术文档",
            "quantity": 10,
            "unit": "份",
            "vault_id": vault["id"],
        },
    ).json()
    return dossier


def _issue_payload(**overrides):
    payload = {
        "idempotency_key": "issue-partners-001",
        "copies": [
            {
                "recipient_code": "PARTNER-A",
                "purpose": "联合研发评审",
                "medium": "paper",
                "valid_until": "2027-03-31T00:00:00+00:00",
            },
            {
                "recipient_code": "PARTNER-B",
                "purpose": "工艺验证",
                "medium": "electronic",
                "valid_until": "2027-03-31T00:00:00+00:00",
            },
            {
                "recipient_code": "PARTNER-C",
                "purpose": "质量审计",
                "medium": "paper",
                "valid_until": "2027-06-30T00:00:00+00:00",
            },
        ],
        "note": "三家合作单位受控发放",
    }
    payload.update(overrides)
    return payload


def _issue(client, admin, dossier, **overrides):
    return client.post(
        f"/api/dossiers/{dossier['id']}/controlled-copy-batches",
        headers=admin["headers"],
        json=_issue_payload(**overrides),
    )


def test_issue_batch_generates_distinct_codes_watermarks_and_snapshot(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    response = _issue(client, admin, dossier)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["replayed"] is False
    assert body["batch"]["batch_code"].startswith("CCB-")
    assert body["batch"]["state"] == "active"
    # 来源版本与快照锁定在签发时刻
    assert body["batch"]["source_version"] == dossier["version"]
    snapshot = body["batch"]["source_snapshot"]
    assert snapshot["dossier_code"] == "CC-DOC-001"
    assert snapshot["version"] == dossier["version"]
    assert snapshot["quantity"] == 10
    # 副本编号不可混淆：介质码嵌入编号，纸质 P 与电子 E 可区分
    codes = [copy["copy_code"] for copy in body["copies"]]
    assert len(set(codes)) == 3
    assert codes[0].endswith("-001-P")
    assert codes[1].endswith("-002-E")
    assert codes[2].endswith("-003-P")
    # 水印元数据携带接收方、用途、介质与完整性摘要
    watermark = body["copies"][0]["watermark"]
    assert watermark["recipient_code"] == "PARTNER-A"
    assert watermark["purpose"] == "联合研发评审"
    assert watermark["medium"] == "paper"
    assert watermark["medium_label"] == "纸质"
    assert watermark["source_version"] == dossier["version"]
    assert len(watermark["digest"]) == 64
    assert body["copies"][1]["watermark"]["medium_label"] == "电子"
    # 档案事件留痕
    detail = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert detail["events"][-1]["event_type"] == "controlled_copy_batch.issued"


def test_issue_batch_is_idempotent_and_rejects_conflicting_replay(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    first = _issue(client, admin, dossier)
    second = _issue(client, admin, dossier)
    assert first.status_code == second.status_code == 201
    assert second.json()["replayed"] is True
    assert second.json()["batch"]["id"] == first.json()["batch"]["id"]
    # 重复点击不会多发副本
    listing = client.get(
        "/api/dossiers/controlled-copies/list",
        headers=admin["headers"],
        params={"dossier_id": dossier["id"]},
    ).json()
    assert listing["summary"] == {"active": 3, "withdrawn": 0, "frozen": 0, "expired": 0}
    # 同一幂等键不能用于不同请求
    conflict = _issue(client, admin, dossier, note="改动后的请求")
    assert conflict.status_code == 409


def test_issue_batch_locks_expected_source_version(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    stale = _issue(client, admin, dossier, idempotency_key="issue-stale", expected_source_version=99)
    assert stale.status_code == 409
    matched = _issue(
        client,
        admin,
        dossier,
        idempotency_key="issue-matched",
        expected_source_version=dossier["version"],
    )
    assert matched.status_code == 201, matched.text


def test_withdraw_single_copy_blocks_loan_and_disclosure(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    copies = _issue(client, admin, dossier).json()["copies"]
    target = copies[0]
    withdrawn = client.post(
        f"/api/dossiers/controlled-copies/{target['id']}/withdraw",
        headers=admin["headers"],
        json={"reason": "合作单位 A 退出项目"},
    )
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["copy"]["state"] == "withdrawn"
    assert withdrawn.json()["copy"]["state_reason"] == "合作单位 A 退出项目"
    # 重复撤回幂等返回
    again = client.post(
        f"/api/dossiers/controlled-copies/{target['id']}/withdraw",
        headers=admin["headers"],
        json={"reason": "合作单位 A 退出项目"},
    )
    assert again.json()["replayed"] is True
    # 已撤回副本禁止借阅登记
    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={
            "dossier_id": dossier["id"],
            "requester_user_id": admin["body"]["user"]["id"],
            "quantity": 1,
            "due_at": "2026-12-31T00:00:00+00:00",
            "controlled_copy_id": target["id"],
        },
    )
    assert loan.status_code == 409
    # 已撤回副本禁止披露登记
    disclosure = client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-A",
            "quantity": 1,
            "idempotency_key": "disclose-withdrawn",
            "controlled_copy_id": target["id"],
        },
    )
    assert disclosure.status_code == 409
    # 其余有效副本不受影响
    active_loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={
            "dossier_id": dossier["id"],
            "requester_user_id": admin["body"]["user"]["id"],
            "quantity": 1,
            "due_at": "2026-12-31T00:00:00+00:00",
            "controlled_copy_id": copies[1]["id"],
        },
    )
    assert active_loan.status_code == 201, active_loan.text
    assert active_loan.json()["controlled_copy_id"] == copies[1]["id"]


def test_freeze_batch_invalidates_all_active_copies(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    copies = _issue(client, admin, dossier).json()["copies"]
    # 先撤回一份，冻结不应覆盖其撤回原因
    client.post(
        f"/api/dossiers/controlled-copies/{copies[0]['id']}/withdraw",
        headers=admin["headers"],
        json={"reason": "单方撤回"},
    )
    batch_id = copies[0]["batch_id"]
    frozen = client.post(
        f"/api/dossiers/controlled-copy-batches/{batch_id}/freeze",
        headers=admin["headers"],
        json={"reason": "发现泄密风险，整批冻结"},
    )
    assert frozen.status_code == 200, frozen.text
    body = frozen.json()
    assert body["batch"]["state"] == "frozen"
    assert body["batch"]["frozen_reason"] == "发现泄密风险，整批冻结"
    states = {copy["copy_code"]: (copy["state"], copy["state_reason"]) for copy in body["copies"]}
    assert states[copies[0]["copy_code"]] == ("withdrawn", "单方撤回")
    assert states[copies[1]["copy_code"]][0] == "frozen"
    assert "批次冻结" in states[copies[1]["copy_code"]][1]
    # 重复冻结幂等返回
    again = client.post(
        f"/api/dossiers/controlled-copy-batches/{batch_id}/freeze",
        headers=admin["headers"],
        json={"reason": "发现泄密风险，整批冻结"},
    )
    assert again.json()["replayed"] is True
    # 冻结副本禁止借阅与披露登记
    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={
            "dossier_id": dossier["id"],
            "requester_user_id": admin["body"]["user"]["id"],
            "quantity": 1,
            "due_at": "2026-12-31T00:00:00+00:00",
            "controlled_copy_id": copies[1]["id"],
        },
    )
    assert loan.status_code == 409
    disclosure = client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-B",
            "quantity": 1,
            "idempotency_key": "disclose-frozen",
            "controlled_copy_id": copies[1]["id"],
        },
    )
    assert disclosure.status_code == 409
    # 冻结批次中的副本不能再单独撤回
    withdraw = client.post(
        f"/api/dossiers/controlled-copies/{copies[1]['id']}/withdraw",
        headers=admin["headers"],
        json={"reason": "冻结后尝试撤回"},
    )
    assert withdraw.status_code == 409


def test_list_copies_filters_by_state_and_shows_reasons(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    copies = _issue(client, admin, dossier).json()["copies"]
    client.post(
        f"/api/dossiers/controlled-copies/{copies[0]['id']}/withdraw",
        headers=admin["headers"],
        json={"reason": "用途变更"},
    )
    client.post(
        f"/api/dossiers/controlled-copy-batches/{copies[1]['batch_id']}/freeze",
        headers=admin["headers"],
        json={"reason": "保密办要求冻结"},
    )
    listing = client.get(
        "/api/dossiers/controlled-copies/list",
        headers=admin["headers"],
        params={"dossier_id": dossier["id"]},
    )
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["summary"] == {"active": 0, "withdrawn": 1, "frozen": 2, "expired": 0}
    withdrawn = client.get(
        "/api/dossiers/controlled-copies/list",
        headers=admin["headers"],
        params={"dossier_id": dossier["id"], "state": "withdrawn"},
    ).json()
    assert len(withdrawn["copies"]) == 1
    assert withdrawn["copies"][0]["state_reason"] == "用途变更"
    assert withdrawn["copies"][0]["effective_state"] == "withdrawn"
    frozen = client.get(
        "/api/dossiers/controlled-copies/list",
        headers=admin["headers"],
        params={"dossier_id": dossier["id"], "state": "frozen"},
    ).json()
    assert len(frozen["copies"]) == 2
    assert all("批次冻结" in copy["state_reason"] for copy in frozen["copies"])
    invalid = client.get(
        "/api/dossiers/controlled-copies/list",
        headers=admin["headers"],
        params={"state": "unknown"},
    )
    assert invalid.status_code == 422


def test_expired_copy_cannot_be_registered(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    issued = _issue(
        client,
        admin,
        dossier,
        copies=[
            {
                "recipient_code": "PARTNER-X",
                "purpose": "历史评审",
                "medium": "paper",
                "valid_from": "2025-01-01T00:00:00+00:00",
                "valid_until": "2025-12-31T00:00:00+00:00",
            }
        ],
    )
    assert issued.status_code == 201, issued.text
    copy = issued.json()["copies"][0]
    assert copy["expired"] is True
    assert copy["effective_state"] == "expired"
    disclosure = client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-X",
            "quantity": 1,
            "idempotency_key": "disclose-expired",
            "controlled_copy_id": copy["id"],
        },
    )
    assert disclosure.status_code == 409


def test_copy_belongs_to_another_dossier_is_rejected(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    other = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": "CC-DOC-002",
            "intake_id": dossier["intake_id"],
            "asset_type": "工艺技术文档",
            "quantity": 5,
            "unit": "份",
        },
    ).json()
    copy = _issue(client, admin, dossier).json()["copies"][0]
    disclosure = client.post(
        f"/api/dossiers/{other['id']}/disclosures",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-A",
            "quantity": 1,
            "idempotency_key": "disclose-wrong-dossier",
            "controlled_copy_id": copy["id"],
        },
    )
    assert disclosure.status_code == 422


def test_batch_detail_returns_snapshot_and_copies(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    issued = _issue(client, admin, dossier).json()
    batch_id = issued["batch"]["id"]
    detail = client.get(f"/api/dossiers/controlled-copy-batches/{batch_id}", headers=admin["headers"])
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["batch"]["batch_code"] == issued["batch"]["batch_code"]
    assert body["batch"]["source_snapshot"]["dossier_code"] == "CC-DOC-001"
    assert len(body["copies"]) == 3
    # 档案后续变更不影响批次锁定的来源版本
    client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={"recipient_code": "LAB-01", "quantity": 2, "idempotency_key": "disclose-after-issue"},
    )
    after = client.get(f"/api/dossiers/controlled-copy-batches/{batch_id}", headers=admin["headers"]).json()
    assert after["batch"]["source_version"] == dossier["version"]
    assert after["batch"]["source_snapshot"]["quantity"] == 10
