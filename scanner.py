#!/usr/bin/env python3
"""
Мониторинг загрузок из браузера в папке «Загрузки» с проверкой через VirusTotal.
Обрабатывает только файлы с меткой Mark of the Web (Zone.Identifier).
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.ini"
CACHE_PATH = SCRIPT_DIR / "checked_hashes.json"
LOG_PATH = SCRIPT_DIR / "scanner.log"
TASK_NAME = "BrowserDownloadVirusScanner"
STARTUP_BAT = "BrowserDownloadScanner.bat"

PARTIAL_SUFFIXES = (
    ".crdownload",
    ".part",
    ".tmp",
    ".download",
    ".partial",
    ".!ut",
    ".opdownload",
)

VT_API = "https://www.virustotal.com/api/v3"
VT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # лимит бесплатного API VirusTotal
ENV_API_KEY = "VIRUSTOTAL_API_KEY"


@dataclass
class Settings:
    enabled: bool = True
    run_at_startup: bool = True
    watch_folder: Path = Path.home() / "Downloads"
    max_file_size_mb: int = 1024
    api_key: str = ""
    detection_threshold: int = 1
    debounce_seconds: float = 1.5
    api_rate_limit_seconds: float = 15.0
    scan_workers: int = 1
    debug: bool = False
    scan_existing_on_startup: bool = True


def expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw.strip()))).resolve()


def load_settings() -> Settings:
    parser = configparser.ConfigParser(interpolation=None)
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Не найден файл настроек: {CONFIG_PATH}")

    parser.read(CONFIG_PATH, encoding="utf-8")
    g = parser["general"] if parser.has_section("general") else {}
    vt = parser["virustotal"] if parser.has_section("virustotal") else {}
    perf = parser["performance"] if parser.has_section("performance") else {}
    log = parser["logging"] if parser.has_section("logging") else {}

    api_key = vt.get("api_key", fallback="").strip() or os.environ.get(ENV_API_KEY, "").strip()

    return Settings(
        enabled=g.getboolean("enabled", fallback=True),
        run_at_startup=g.getboolean("run_at_startup", fallback=True),
        watch_folder=expand_path(g.get("watch_folder", str(Path.home() / "Downloads"))),
        max_file_size_mb=g.getint("max_file_size_mb", fallback=1024),
        api_key=api_key,
        detection_threshold=vt.getint("detection_threshold", fallback=1),
        debounce_seconds=perf.getfloat("debounce_seconds", fallback=1.5),
        api_rate_limit_seconds=perf.getfloat("api_rate_limit_seconds", fallback=15.0),
        scan_workers=max(1, perf.getint("scan_workers", fallback=1)),
        debug=log.getboolean("debug", fallback=False),
        scan_existing_on_startup=g.getboolean("scan_existing_on_startup", fallback=True),
    )


def setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setLevel(level)
    handlers.append(file_handler)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


class HashCache:
    """Кэш уже проверенных файлов (по SHA-256)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                self._data = raw
        except (json.JSONDecodeError, OSError) as exc:
            logging.warning("Не удалось прочитать кэш: %s", exc)

    def contains(self, sha256: str) -> bool:
        with self._lock:
            return sha256 in self._data

    def get(self, sha256: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._data.get(sha256)
            return dict(entry) if entry else None

    def has_file(self, file_path: Path) -> bool:
        """Быстрая проверка: тот же путь, размер и время изменения уже в кэше."""
        try:
            stat = file_path.stat()
        except OSError:
            return False
        target = str(file_path.resolve())
        with self._lock:
            for entry in self._data.values():
                if (
                    entry.get("path") == target
                    and entry.get("size") == stat.st_size
                    and entry.get("mtime") == stat.st_mtime
                ):
                    return True
        return False

    def add(
        self,
        sha256: str,
        file_path: Path,
        verdict: str,
        *,
        malicious_count: int | None = None,
    ) -> None:
        try:
            stat = file_path.stat()
            size = stat.st_size
            mtime = stat.st_mtime
        except OSError:
            size = None
            mtime = None
        with self._lock:
            prev = self._data.get(sha256, {})
            self._data[sha256] = {
                "path": str(file_path.resolve()),
                "size": size,
                "mtime": mtime,
                "verdict": verdict,
                "malicious_count": malicious_count or prev.get("malicious_count"),
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save_unlocked()

    def _save_unlocked(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(self._data, fh, ensure_ascii=False, indent=2)
        tmp.replace(self.path)


def is_partial_download(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in PARTIAL_SUFFIXES)


def is_browser_download(path: Path) -> bool:
    """Файл помечен Windows как загруженный из интернета (Mark of the Web)."""
    zone_path = f"{path}:Zone.Identifier"
    try:
        with open(zone_path, "rb") as fh:
            content = fh.read().decode("utf-8", errors="ignore").lower()
    except OSError:
        return False
    return "zoneid=3" in content or "zoneid=4" in content


def is_file_stable(path: Path, pause: float = 0.4) -> bool:
    """Файл не меняется и не заблокирован загрузчиком."""
    try:
        size1 = path.stat().st_size
        time.sleep(pause)
        size2 = path.stat().st_size
        if size1 != size2:
            return False
        with path.open("rb"):
            pass
        return True
    except OSError:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def defender_quarantine(path: Path) -> bool:
    """Запускает точечную проверку Windows Defender; угрозы помещаются в карантин."""
    candidates = [
        Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe"),
        Path(r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"),
    ]
    mpcmd = next((p for p in candidates if p.exists()), None)
    if not mpcmd:
        logging.error("MpCmdRun.exe не найден — карантин Defender недоступен")
        return False

    try:
        result = subprocess.run(
            [str(mpcmd), "-Scan", "-ScanType", "3", "-File", str(path)],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=120,
        )
        logging.info("Defender scan exit=%s для %s", result.returncode, path.name)
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError) as exc:
        logging.error("Ошибка Defender: %s", exc)
        return False


def show_notification(title: str, message: str) -> None:
    try:
        ps = (
            f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            f"ContentType = WindowsRuntime] | Out-Null; "
            f"$t = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('VirusTotal Scanner'); "
            f"$x = [Windows.Data.Xml.Dom.XmlDocument]::new(); "
            f"$x.LoadXml('<toast><visual><binding template=\"ToastText02\">"
            f"<text id=\"1\">{title}</text><text id=\"2\">{message}</text>"
            f"</binding></visual></toast>'); "
            f"$t.Show([Windows.UI.Notifications.ToastNotification]::new($x))"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        logging.info("%s — %s", title, message)


class VirusTotalClient:
    def __init__(self, api_key: str, rate_limit: float) -> None:
        self.api_key = api_key
        self.rate_limit = rate_limit
        self._lock = threading.Lock()
        self._last_request = 0.0
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def _throttle(self) -> None:
        with self._lock:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_request = time.monotonic()

    def lookup_hash(self, sha256: str) -> dict[str, Any] | None:
        self._throttle()
        url = f"{VT_API}/files/{sha256}"
        resp = self.session.get(url, timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def upload_file(self, path: Path) -> dict[str, Any]:
        self._throttle()
        url = f"{VT_API}/files"
        with path.open("rb") as fh:
            resp = self.session.post(url, files={"file": (path.name, fh)}, timeout=300)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def malicious_count(report: dict[str, Any]) -> int:
        attrs = report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
        return int(stats.get("malicious", 0))

    @staticmethod
    def sha256_from_report(report: dict[str, Any]) -> str | None:
        attrs = report.get("data", {}).get("attributes", {})
        if sha := attrs.get("sha256"):
            return sha
        meta = report.get("meta", {})
        if isinstance(meta, dict):
            info = meta.get("file_info", {})
            if isinstance(info, dict) and info.get("sha256"):
                return info["sha256"]
        return None

    @staticmethod
    def analysis_link(sha256: str) -> str:
        return f"https://www.virustotal.com/gui/file/{sha256}"


class ScanWorker(threading.Thread):
    def __init__(
        self,
        work_queue: queue.Queue[Path],
        settings_provider: callable,
        cache: HashCache,
    ) -> None:
        super().__init__(daemon=True, name="ScanWorker")
        self.work_queue = work_queue
        self.settings_provider = settings_provider
        self.cache = cache

    def run(self) -> None:
        while True:
            path = self.work_queue.get()
            try:
                process_download(
                    path, self.settings_provider(), self.cache, source="watcher"
                )
            except Exception:
                logging.exception("Ошибка проверки %s", path)
            finally:
                self.work_queue.task_done()


def wait_for_analysis(
    vt: VirusTotalClient, analysis_id: str, timeout: float = 300.0
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        vt._throttle()
        resp = vt.session.get(f"{VT_API}/analyses/{analysis_id}", timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        status = payload.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            sha256 = VirusTotalClient.sha256_from_report(payload)
            if sha256:
                report = vt.lookup_hash(sha256)
                if report is not None:
                    return report
            return payload
        time.sleep(5)
    return None


def alert_malicious(path: Path, sha256: str, malicious: int, link: str) -> None:
    logging.warning(
        "УГРОЗА: %s — %s движков, %s",
        path.name,
        malicious,
        link,
    )
    webbrowser.open(link)
    defender_quarantine(path)
    show_notification(
        "Обнаружена угроза",
        f"{path.name}: {malicious} движков VirusTotal. Файл отправлен в карантин.",
    )


def process_download(
    path: Path,
    settings: Settings,
    cache: HashCache,
    *,
    require_browser_mark: bool = True,
    source: str = "watcher",
) -> str:
    """Проверяет один файл. Возвращает статус: skipped, clean, malicious, error."""
    if not settings.enabled:
        return "skipped"
    if not path.exists() or not path.is_file():
        logging.warning("Файл не найден: %s", path)
        return "skipped"
    if not settings.api_key:
        logging.error(
            "API-ключ VirusTotal не задан. Укажите его в config.ini или переменной %s",
            ENV_API_KEY,
        )
        return "error"

    max_bytes = settings.max_file_size_mb * 1024 * 1024
    try:
        size = path.stat().st_size
    except OSError as exc:
        logging.warning("Не удалось прочитать %s: %s", path.name, exc)
        return "skipped"
    if size > max_bytes:
        logging.info("Пропуск (>%s МБ): %s", settings.max_file_size_mb, path.name)
        return "skipped"

    if require_browser_mark and not is_browser_download(path):
        logging.info("Пропуск (не браузерная загрузка): %s", path.name)
        return "skipped"

    logging.info("Проверка: %s (%.1f МБ)", path.name, size / (1024 * 1024))
    sha256 = sha256_file(path)

    if cache.contains(sha256):
        entry = cache.get(sha256) or {}
        if source == "watcher" and entry.get("verdict") == "malicious":
            link = VirusTotalClient.analysis_link(sha256)
            malicious = int(entry.get("malicious_count", 1))
            logging.warning("Повторная загрузка известной угрозы: %s", path.name)
            alert_malicious(path, sha256, malicious, link)
            cache.add(sha256, path, "malicious", malicious_count=malicious)
            return "malicious"
        logging.info("Уже проверен ранее: %s", path.name)
        return "skipped"

    vt = VirusTotalClient(settings.api_key, settings.api_rate_limit_seconds)
    try:
        report = vt.lookup_hash(sha256)
    except requests.HTTPError as exc:
        logging.error("Ошибка VirusTotal (hash lookup): %s", exc)
        return "error"

    if report is None:
        if size > VT_MAX_UPLOAD_BYTES:
            logging.error(
                "Файл %s (%.1f МБ) отсутствует в базе VirusTotal и превышает лимит "
                "загрузки 32 МБ. Проверка невозможна без платного API.",
                path.name,
                size / (1024 * 1024),
            )
            return "error"
        logging.info("Загрузка на VirusTotal: %s", path.name)
        try:
            upload_resp = vt.upload_file(path)
        except requests.HTTPError as exc:
            logging.error("Ошибка загрузки на VirusTotal: %s", exc)
            return "error"
        upload_id = upload_resp.get("data", {}).get("id")
        if not upload_id:
            logging.error("VirusTotal не принял файл: %s", path.name)
            return "error"
        report = wait_for_analysis(vt, upload_id)
        if report is None:
            logging.error("Таймаут анализа VirusTotal: %s", path.name)
            return "error"

    malicious = vt.malicious_count(report)
    report_sha = VirusTotalClient.sha256_from_report(report) or sha256
    link = vt.analysis_link(report_sha)

    if malicious >= settings.detection_threshold:
        alert_malicious(path, report_sha, malicious, link)
        cache.add(report_sha, path, "malicious", malicious_count=malicious)
        return "malicious"

    logging.info("Чисто: %s (%s)", path.name, link)
    cache.add(report_sha, path, "clean")
    return "clean"


def queue_existing_downloads(
    watch_folder: Path,
    work_queue: queue.Queue[Path],
    cache: HashCache,
) -> int:
    """Ставит в очередь уже лежащие в папке браузерные загрузки."""
    queued = 0
    if not watch_folder.is_dir():
        return queued
    for entry in watch_folder.iterdir():
        if not entry.is_file() or is_partial_download(entry):
            continue
        if not is_browser_download(entry):
            continue
        if cache.has_file(entry):
            continue
        work_queue.put(entry)
        queued += 1
        logging.info("В очередь (существующий файл): %s", entry.name)
    return queued


def scan_file_cli(path: Path) -> int:
    settings = load_settings()
    setup_logging(True)
    cache = HashCache(CACHE_PATH)
    logging.info("Ручная проверка: %s", path)
    result = process_download(
        path.resolve(), settings, cache, require_browser_mark=False, source="manual"
    )
    logging.info("Результат: %s", result)
    return 0 if result in {"clean", "malicious", "skipped"} else 1


class DownloadHandler(FileSystemEventHandler):
    """Быстрая фильтрация событий (<0.5 с до постановки в очередь)."""

    def __init__(
        self,
        work_queue: queue.Queue[Path],
        settings_provider: callable,
        debounce: float,
    ) -> None:
        super().__init__()
        self.work_queue = work_queue
        self.settings_provider = settings_provider
        self.debounce = debounce
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def on_created(self, event: FileSystemEvent) -> None:
        self._schedule(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._schedule(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule(event, dest=getattr(event, "dest_path", None))

    def _schedule(self, event: FileSystemEvent, dest: str | None = None) -> None:
        if event.is_directory:
            return

        settings = self.settings_provider()
        if not settings.enabled:
            return

        path = Path(dest or event.src_path)
        if is_partial_download(path):
            return

        key = str(path).lower()
        with self._lock:
            old = self._timers.pop(key, None)
            if old:
                old.cancel()

            def enqueue() -> None:
                with self._lock:
                    self._timers.pop(key, None)
                if not path.exists():
                    return
                if is_partial_download(path):
                    return
                if not is_file_stable(path):
                    with self._lock:
                        self._timers[key] = threading.Timer(
                            self.debounce, enqueue
                        )
                        self._timers[key].daemon = True
                        self._timers[key].start()
                    return
                self.work_queue.put(path)

            timer = threading.Timer(settings.debounce_seconds, enqueue)
            timer.daemon = True
            timer.start()
            self._timers[key] = timer


class ConfigReloader(threading.Thread):
    def __init__(self, callback: callable, interval: float = 5.0) -> None:
        super().__init__(daemon=True, name="ConfigReloader")
        self.callback = callback
        self.interval = interval
        self._mtime: float | None = None

    def run(self) -> None:
        while True:
            time.sleep(self.interval)
            try:
                mtime = CONFIG_PATH.stat().st_mtime
            except OSError:
                continue
            if self._mtime is None:
                self._mtime = mtime
                continue
            if mtime != self._mtime:
                self._mtime = mtime
                try:
                    self.callback()
                    logging.info("Настройки перечитаны из config.ini")
                except Exception:
                    logging.exception("Ошибка перечитывания config.ini")


def python_executable() -> str:
    venv_pythonw = SCRIPT_DIR / ".venv" / "Scripts" / "pythonw.exe"
    if venv_pythonw.exists():
        return str(venv_pythonw)
    venv_python = SCRIPT_DIR / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def script_path() -> str:
    return str(Path(__file__).resolve())


def _run_cmd(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def startup_bat_path() -> Path:
    appdata = os.environ.get("APPDATA", "")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / STARTUP_BAT


def startup_bat_content() -> str:
    return (
        "@echo off\r\n"
        f'cd /d "{SCRIPT_DIR}"\r\n'
        f'start "" /min "{python_executable()}" "{script_path()}"\r\n'
    )


def is_startup_enabled() -> bool:
    if startup_bat_path().exists():
        return True
    result = _run_cmd(["schtasks", "/Query", "/TN", TASK_NAME])
    return result.returncode == 0


def ensure_startup(enabled: bool) -> None:
    bat = startup_bat_path()
    if enabled:
        bat.parent.mkdir(parents=True, exist_ok=True)
        bat.write_text(startup_bat_content(), encoding="utf-8")
        logging.info("Автозапуск: ярлык в папке «Автозагрузка» → %s", bat)
    elif bat.exists():
        bat.unlink()
        logging.info("Автозапуск отключён (удалён %s)", bat)


def manage_startup(enable: bool | None) -> int:
    """enable=True — автозапуск, False — удалить, None — показать статус."""
    if enable is None:
        if is_startup_enabled():
            print("Автозапуск: ВКЛ")
            bat = startup_bat_path()
            if bat.exists():
                print(f"  Папка «Автозагрузка»: {bat}")
            task = _run_cmd(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"])
            if task.returncode == 0:
                print(f"  Планировщик: {TASK_NAME}")
        else:
            print("Автозапуск: ВЫКЛ")
        return 0

    if enable:
        ensure_startup(True)
        tr = f'"{python_executable()}" "{script_path()}"'
        cmd = [
            "schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr,
            "/SC", "ONLOGON", "/RL", "LIMITED", "/F",
            "/WD", str(SCRIPT_DIR),
        ]
        result = _run_cmd(cmd)
        if result.returncode == 0:
            print(f"Автозапуск: планировщик «{TASK_NAME}» + папка «Автозагрузка»")
        else:
            print("Автозапуск: папка «Автозагрузка» (планировщик недоступен без прав админа)")
        _set_config_startup_flag(True)
        return 0

    ensure_startup(False)
    _run_cmd(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    print("Автозапуск отключён")
    _set_config_startup_flag(False)
    return 0


def _set_config_startup_flag(enabled: bool) -> None:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(CONFIG_PATH, encoding="utf-8")
    if not parser.has_section("general"):
        parser.add_section("general")
    parser.set("general", "run_at_startup", "true" if enabled else "false")
    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        parser.write(fh)


def run_monitor() -> int:
    settings_lock = threading.Lock()
    settings = load_settings()
    setup_logging(settings.debug)

    if settings.run_at_startup and not is_startup_enabled():
        ensure_startup(True)

    if not settings.api_key:
        logging.error(
            "API-ключ VirusTotal не задан. Укажите его в config.ini ([virustotal] api_key) "
            "или в переменной окружения %s",
            ENV_API_KEY,
        )

    watch_folder = settings.watch_folder
    if not watch_folder.is_dir():
        logging.error("Папка мониторинга не существует: %s", watch_folder)
        return 1

    def get_settings() -> Settings:
        with settings_lock:
            return settings

    def reload_settings() -> None:
        nonlocal settings
        new_settings = load_settings()
        with settings_lock:
            settings = new_settings
        setup_logging(settings.debug)

    cache = HashCache(CACHE_PATH)
    work_queue: queue.Queue[Path] = queue.Queue()

    workers = settings.scan_workers
    for _ in range(workers):
        ScanWorker(work_queue, get_settings, cache).start()

    handler = DownloadHandler(work_queue, get_settings, settings.debounce_seconds)
    observer = Observer()
    observer.schedule(handler, str(watch_folder), recursive=False)
    observer.start()

    ConfigReloader(reload_settings).start()

    if settings.scan_existing_on_startup:
        queued = queue_existing_downloads(watch_folder, work_queue, cache)
        if queued:
            logging.info("Найдено %s существующих браузерных загрузок для проверки", queued)

    logging.info("Мониторинг: %s (только браузерные загрузки)", watch_folder)
    logging.info("Настройки: %s", CONFIG_PATH)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Остановка...")
    finally:
        observer.stop()
        observer.join()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Проверка браузерных загрузок через VirusTotal"
    )
    parser.add_argument(
        "--startup",
        choices=["on", "off", "status"],
        help="Управление автозапуском при входе в Windows",
    )
    parser.add_argument(
        "--scan-file",
        metavar="PATH",
        help="Проверить один файл и выйти (для теста, без требования метки браузера)",
    )
    args = parser.parse_args()

    if args.scan_file:
        target = expand_path(args.scan_file)
        if not target.is_file():
            print(f"Файл не найден: {target}", file=sys.stderr)
            return 1
        return scan_file_cli(target)

    if args.startup == "on":
        return manage_startup(True)
    if args.startup == "off":
        return manage_startup(False)
    if args.startup == "status":
        return manage_startup(None)

    return run_monitor()


if __name__ == "__main__":
    raise SystemExit(main())
