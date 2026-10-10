from pathlib import Path
import subprocess

from desktop import watcher


def test_defender_clean_result_is_reported(monkeypatch, capsys):
    monkeypatch.setattr(watcher, "find_defender_cli", lambda: Path("MpCmdRun.exe"))

    def fake_run(command, **kwargs):
        assert Path(command[-1]).is_absolute()
        return subprocess.CompletedProcess(
            command, 0, stdout="Scan finished. Scanning file found no threats.", stderr=""
        )

    monkeypatch.setattr(watcher.subprocess, "run", fake_run)
    watcher.scan_file_with_defender(Path("sample.zip"))

    output = capsys.readouterr().out
    assert "[DEFENDER CLEAN] sample.zip" in output
    assert "[UNVERIFIED]" not in output


def test_defender_threat_result_is_reported(monkeypatch, capsys):
    monkeypatch.setattr(watcher, "find_defender_cli", lambda: Path("MpCmdRun.exe"))

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 2, stdout="Threat detected.", stderr=""
        )

    monkeypatch.setattr(watcher.subprocess, "run", fake_run)
    watcher.scan_file_with_defender(Path("sample.exe"))

    assert "[DEFENDER DETECTION] sample.exe" in capsys.readouterr().out


def test_defender_timeout_is_unverified(monkeypatch, capsys):
    monkeypatch.setattr(watcher, "find_defender_cli", lambda: Path("MpCmdRun.exe"))

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=300)

    monkeypatch.setattr(watcher.subprocess, "run", fake_run)
    watcher.scan_file_with_defender(Path("sample.zip"))

    output = capsys.readouterr().out
    assert "[UNVERIFIED] sample.zip: Defender scan timed out." in output
    assert "[DEFENDER CLEAN]" not in output


def test_defender_inconclusive_exit_code_is_unverified(monkeypatch, capsys):
    monkeypatch.setattr(watcher, "find_defender_cli", lambda: Path("MpCmdRun.exe"))

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 2, stdout="Scan returned an unexpected result.", stderr=""
        )

    monkeypatch.setattr(watcher.subprocess, "run", fake_run)
    watcher.scan_file_with_defender(Path("sample.jar"))

    output = capsys.readouterr().out
    assert "[UNVERIFIED] sample.jar" in output
    assert "[DEFENDER CLEAN]" not in output


def test_missing_defender_scanner_is_unverified(monkeypatch, capsys):
    monkeypatch.setattr(watcher, "find_defender_cli", lambda: None)

    watcher.scan_file_with_defender(Path("sample.msi"))

    output = capsys.readouterr().out
    assert "[UNVERIFIED] sample.msi" in output
    assert "scanner was not found" in output
