"""Stopgap Linux agent: one bad event must never stall shipping.

Before this fix the journal loop kept a batch the core had rejected (422) and
re-sent it after every new line, so a single invalid event stopped the agent
from ever shipping again. These tests drive the batcher with a fake sender.
"""

import io
import urllib.error
from typing import Any, Dict, List
from unittest.mock import patch

from lsadra.endpoint_agent import linux_agent

CFG = {
    "server_url": "http://core.demo",
    "collector_endpoint": "/api/events/batch",
    "device_id": "dev-1.demo",
    "api_key": "key",
}


def _event(i: int) -> Dict[str, Any]:
    return {"schema_version": "1", "timestamp": "2026-01-15T02:01:12+00:00",
            "event_type": "ssh_failed_password", "raw_message": f"line {i}"}


def test_rejected_batch_is_dropped_and_later_events_still_ship():
    sent: List[List[Dict[str, Any]]] = []

    def fake_send(events, *_args):
        sent.append(list(events))
        return len(sent) > 1  # first batch rejected (422), the rest accepted

    with patch.object(linux_agent, "_send_batch", side_effect=fake_send):
        b = linux_agent._Batcher(batch_size=2, flush_interval=3600, cfg=CFG)
        for i in range(6):
            b.add(_event(i))
            b.maybe_flush()

    assert [[e["raw_message"] for e in batch] for batch in sent] == [
        ["line 0", "line 1"], ["line 2", "line 3"], ["line 4", "line 5"],
    ]
    assert b.buffer == []


def test_batch_size_is_capped_at_the_contract_limit():
    sent: List[int] = []
    with patch.object(linux_agent, "_send_batch", side_effect=lambda ev, *a: sent.append(len(ev)) or True):
        b = linux_agent._Batcher(batch_size=500, flush_interval=3600, cfg=CFG)
        assert b.batch_size == linux_agent.MAX_BATCH_SIZE == 100
        for i in range(250):
            b.add(_event(i))
        b.flush()
    assert sent == [100, 100, 50]


def test_buffer_is_bounded():
    b = linux_agent._Batcher(batch_size=100, flush_interval=3600, cfg=CFG)
    for i in range(linux_agent.MAX_BUFFERED_EVENTS + 25):
        b.add(_event(i))
    assert len(b.buffer) == linux_agent.MAX_BUFFERED_EVENTS
    assert b.dropped == 25
    assert b.buffer[0]["raw_message"] == "line 25"  # oldest dropped first


def test_idle_flush_after_interval():
    with patch.object(linux_agent, "_send_batch", return_value=True) as send:
        b = linux_agent._Batcher(batch_size=50, flush_interval=3, cfg=CFG)
        b.add(_event(0))
        b.maybe_flush(now=b.last_flush + 1)
        assert not send.called
        b.maybe_flush(now=b.last_flush + 3)
        assert send.call_count == 1


def test_503_retry_after_is_honoured():
    busy = urllib.error.HTTPError("http://core.demo", 503, "Busy", {"Retry-After": "7"}, io.BytesIO(b""))

    class _Ok:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    with patch.object(linux_agent.urllib.request, "urlopen", side_effect=[busy, _Ok()]), \
            patch.object(linux_agent.time, "sleep") as sleep:
        assert linux_agent._send_batch([_event(0)], "http://core.demo", "/x", "dev", "key")
    sleep.assert_called_once_with(7)


def test_log_paths_config_is_parsed(tmp_path):
    cfg_file = tmp_path / "config.yml"
    cfg_file.write_text('api_key: "k"\nlog_paths: ["/var/log/secure", /var/log/auth.log]\n')
    cfg = linux_agent.load_config(str(cfg_file))
    assert cfg["log_paths"] == ["/var/log/secure", "/var/log/auth.log"]


def test_main_tails_the_configured_paths(tmp_path):
    log = tmp_path / "secure"
    log.write_text("")
    cfg_file = tmp_path / "config.yml"
    # posture_interval_hours: 0 keeps main() from starting the posture thread.
    cfg_file.write_text(
        f"api_key: k\ndevice_id: dev\nposture_interval_hours: 0\nlog_paths: {log}, {tmp_path / 'missing'}\n"
    )
    with patch("sys.argv", ["agent", "--config", str(cfg_file)]), \
            patch.object(linux_agent, "_tail_paths") as tail, \
            patch.object(linux_agent, "_tail_journal") as journal:
        linux_agent.main()
    tail.assert_called_once()
    assert tail.call_args.args[0] == [str(log)]
    assert not journal.called
