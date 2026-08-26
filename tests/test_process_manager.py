import subprocess
from unittest.mock import MagicMock, patch

from core.process_manager import ProcessManager


class TestProcessManager:
    def test_init_empty(self):
        pm = ProcessManager()
        assert pm._processes == {}
        assert pm._running is False

    def test_register_process(self):
        pm = ProcessManager()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # signal "alive"
        pm.register("test_proc", mock_proc)
        assert "test_proc" in pm.get_all()
        assert pm.is_alive("test_proc") is True

    def test_register_multiple(self):
        pm = ProcessManager()
        p1 = MagicMock()
        p1.poll.return_value = None
        p2 = MagicMock()
        p2.poll.return_value = None
        pm.register("proc1", p1)
        pm.register("proc2", p2)
        assert len(pm.get_all()) == 2

    def test_kill_existing_process(self):
        pm = ProcessManager()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.wait.return_value = None
        pm.register("test_proc", mock_proc)
        result = pm.kill("test_proc")
        assert result is True
        assert "test_proc" not in pm.get_all()

    def test_kill_nonexistent_returns_false(self):
        pm = ProcessManager()
        result = pm.kill("does_not_exist")
        assert result is False

    def test_kill_all(self):
        pm = ProcessManager()
        p1 = MagicMock()
        p1.poll.return_value = None
        p1.wait.return_value = None
        p2 = MagicMock()
        p2.poll.return_value = None
        p2.wait.return_value = None

        pm.register("p1", p1)
        pm.register("p2", p2)
        pm.kill_all()

        assert len(pm.get_all()) == 0

    @patch("subprocess.run")
    def test_kill_all_runs_killall(self, mock_run):
        pm = ProcessManager()
        p1 = MagicMock()
        p1.poll.return_value = None
        p1.wait.return_value = None
        pm.register("hostapd", p1)
        pm.register("dnsmasq", p1)
        pm.kill_all()
        mock_run.assert_any_call(
            ["killall", "hostapd"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

    def test_is_alive_true(self):
        pm = ProcessManager()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        pm.register("alive", mock_proc)
        assert pm.is_alive("alive") is True

    def test_is_alive_false_dead(self):
        pm = ProcessManager()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        pm.register("dead", mock_proc)
        assert pm.is_alive("dead") is False

    def test_is_alive_unknown_false(self):
        pm = ProcessManager()
        assert pm.is_alive("unknown") is False

    def test_get_all_returns_copy(self):
        pm = ProcessManager()
        p1 = MagicMock()
        pm.register("proc1", p1)
        all_procs = pm.get_all()
        all_procs["new_key"] = MagicMock()
        assert "new_key" not in pm.get_all()


class TestWatchdogRestart:
    """Section 7 #2: ProcessManager._watch_one auto-respawns via callback."""

    def _sleep(self, _amount):
        # Patch time.sleep so the watchdog's 1-second poll cycle doesn't
        # actually take a second.
        return _amount

    def test_watchdog_calls_restart_callback_on_exit(self, monkeypatch):
        from core import process_manager as pm_mod

        # Short-circuit the 1s sleep loop in _watch_one.
        monkeypatch.setattr(pm_mod.time, "sleep", lambda _: None)

        # Two-stage callback: first call returns a "dead" proc so the
        # watchdog actually has work to do; second returns "alive".
        new_procs = []

        def make_callback():
            calls = {"n": 0}

            def cb():
                calls["n"] += 1
                proc = MagicMock()
                proc.poll.return_value = None  # alive
                new_procs.append(proc)
                return proc

            cb.calls = calls
            return cb

        cb = make_callback()
        pm = ProcessManager()

        # Build a Popen that has already exited (poll() != None).
        dead_proc = MagicMock()
        dead_proc.poll.return_value = 137
        pm.register("hostapd", dead_proc, restart=True, restart_callback=cb)

        # Give the watchdog thread time to fire the callback and replace
        # the dead process. Threshold is generous so this works on slow
        # boxes without flaking on fast ones.
        import time as _t

        deadline = _t.monotonic() + 2.0
        new = pm.get_all().get("hostapd")
        while (new is dead_proc or new is None) and _t.monotonic() < deadline:
            _t.sleep(0.05)
            new = pm.get_all().get("hostapd")

        assert cb.calls["n"] >= 1, "restart_callback was not invoked"
        # The new process should now be the one we replaced with.
        new = pm.get_all().get("hostapd")
        assert new is not None
        assert new is not dead_proc

    def test_kill_deregisters_restart_callback(self, monkeypatch):
        from core import process_manager as pm_mod

        monkeypatch.setattr(pm_mod.time, "sleep", lambda _: None)

        cb = MagicMock()
        pm = ProcessManager()
        proc = MagicMock()
        proc.poll.return_value = None
        pm.register("daemon", proc, restart=True, restart_callback=cb)

        # Give the watchdog thread a chance to start.
        import time as _t

        _t.sleep(0.1)

        pm.kill("daemon")
        # After deregister, kill_all shouldn't try to restart.
        assert pm.get_all().get("daemon") is None


class TestRegistryThreadSafety:
    """Quick sanity check on the _lock around concurrent modifications."""

    def test_concurrent_register_then_query(self):
        import threading as _th

        pm = ProcessManager()
        errors: list = []

        def register_one(i: int):
            try:
                proc = MagicMock()
                proc.poll.return_value = None
                pm.register(f"p{i}", proc)
            except Exception as e:
                errors.append(e)

        threads = [_th.Thread(target=register_one, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(pm.get_all()) == 20
