from vuln_agent.core.progress import initial_agents_progress, set_agent_status


def test_initial_progress_pending():
    rows = initial_agents_progress(["recon", "js_audit", "reporter"])
    assert [r["agent"] for r in rows] == ["recon", "js_audit", "reporter"]
    assert all(r["status"] == "pending" for r in rows)
    assert rows[0]["label"] == "Recon & fingerprint"


def test_set_agent_status_transitions():
    rows = initial_agents_progress(["recon", "adapt"])
    rows = set_agent_status(rows, "recon", "running")
    assert rows[0]["status"] == "running"
    assert rows[0]["started_at"]
    assert rows[1]["status"] == "pending"
    rows = set_agent_status(rows, "recon", "done")
    assert rows[0]["status"] == "done"
    assert rows[0]["finished_at"]
    rows = set_agent_status(rows, "adapt", "skipped")
    assert rows[1]["status"] == "skipped"
