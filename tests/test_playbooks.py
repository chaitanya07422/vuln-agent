from pathlib import Path

from vuln_agent.playbook_loader import PlaybookStore


def test_generic_and_wordpress_merge():
    root = Path(__file__).resolve().parents[1] / "playbooks"
    store = PlaybookStore(root)
    steps = store.for_tech(["wordpress"])
    assert store.section(["wordpress"], "users")
    assert store.section(["wordpress"], "auth")
    leak_paths = {s["path"] for s in steps.get("leaks", [])}
    assert "/.env" in leak_paths
    assert "/readme.html" in leak_paths


def test_unknown_still_gets_generic():
    root = Path(__file__).resolve().parents[1] / "playbooks"
    store = PlaybookStore(root)
    leaks = store.section(["unknown"], "leaks")
    assert any(s["path"] == "/.env" for s in leaks)
