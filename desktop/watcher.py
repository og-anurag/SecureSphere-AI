import sys
import time
from pathlib import Path


POLL_INTERVAL_SECONDS = 3
FILE_STABLE_CHECKS = 2

MONITORED_EXTENSIONS = {
    ".apk",
    ".exe",
    ".msi",
    ".zip",
    ".jar",
    ".bat",
    ".cmd",
    ".ps1",
    ".scr",
}


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from backend.app.utils.apk_checker import check_apk


def get_downloads_directory() -> Path:
    downloads = Path.home() / "Downloads"

    if not downloads.exists():
        downloads.mkdir(
            parents=True,
            exist_ok=True,
        )

    return downloads


def get_file_snapshot(
    folder: Path,
) -> dict[str, tuple[int, int]]:
    snapshot = {}

    for path in folder.iterdir():
        if not path.is_file():
            continue

        try:
            stat = path.stat()

            snapshot[str(path)] = (
                stat.st_size,
                stat.st_mtime_ns,
            )
        except OSError:
            continue

    return snapshot


def is_interesting_file(
    path: Path,
) -> bool:
    return (
        path.suffix.lower()
        in MONITORED_EXTENSIONS
    )


def wait_for_stable_file(
    path: Path,
) -> bool:
    previous_size = None
    stable_checks = 0

    for _ in range(10):
        try:
            current_size = path.stat().st_size
        except OSError:
            return False

        if current_size == previous_size:
            stable_checks += 1

            if stable_checks >= FILE_STABLE_CHECKS:
                return True
        else:
            stable_checks = 0

        previous_size = current_size
        time.sleep(1)

    return False


def scan_apk(path: Path) -> None:
    try:
        contents = path.read_bytes()

        result = check_apk(contents)

        risk = result.get(
            "risk",
            "Unknown",
        )

        score = result.get(
            "score",
            0,
        )

        reasons = result.get(
            "reasons",
            [],
        )

        print(
            f"[APK SCAN] {path.name} "
            f"-> {risk} ({score}/100)"
        )

        for reason in reasons:
            print(
                f"  - {reason}"
            )

    except Exception as exc:
        print(
            f"[APK SCAN ERROR] "
            f"{path.name}: {exc}"
        )


def handle_new_file(path: Path) -> None:
    print(
        f"[NEW DOWNLOAD] {path.name}"
    )

    if not wait_for_stable_file(path):
        print(
            f"[SKIPPED] {path.name} "
            "did not become stable."
        )
        return

    if path.suffix.lower() == ".apk":
        scan_apk(path)
    else:
        print(
            f"[MONITORED] {path.name} "
            f"(no dedicated scanner yet)"
        )


def run_watcher() -> None:
    downloads = get_downloads_directory()

    print(
        "SecureSphere AI Desktop Watcher"
    )

    print(
        f"Monitoring: {downloads}"
    )

    print(
        "Watching for: "
        + ", ".join(
            sorted(
                MONITORED_EXTENSIONS
            )
        )
    )

    print(
        "Press Ctrl+C to stop."
    )

    previous = get_file_snapshot(
        downloads
    )

    while True:
        time.sleep(
            POLL_INTERVAL_SECONDS
        )

        current = get_file_snapshot(
            downloads
        )

        new_files = (
            set(current) - set(previous)
        )

        for file_path in sorted(
            new_files
        ):
            path = Path(file_path)

            if not is_interesting_file(
                path
            ):
                continue

            handle_new_file(path)

        previous = current


if __name__ == "__main__":
    try:
        run_watcher()
    except KeyboardInterrupt:
        print(
            "\nSecureSphere AI "
            "Desktop Watcher stopped."
        )