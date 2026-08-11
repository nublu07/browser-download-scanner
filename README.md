# Browser Download Scanner

**RU:** Мониторинг загрузок из браузера в папке «Загрузки» с проверкой через [VirusTotal](https://www.virustotal.com). При обнаружении угрозы открывается страница отчёта, файл отправляется в карантин через Windows Defender.

**EN:** Monitors browser downloads in your Downloads folder via [VirusTotal](https://www.virustotal.com). On detection, opens the report page and quarantines the file via Windows Defender.

---

## Русский

### Возможности

- Проверяет **только файлы, скачанные из браузера** (метка Mark of the Web / `Zone.Identifier`)
- Следит **только за одной папкой** (по умолчанию «Загрузки»), не нагружая систему
- **Не проверяет повторно** уже просканированные файлы (кэш SHA-256)
- Быстрая реакция на новый файл; полная проверка VirusTotal выполняется в фоне
- При угрозе: страница VirusTotal + карантин Windows Defender + уведомление
- Настройки в `config.ini` (папка, лимит размера, автозапуск, отладка)

### Требования

- Windows 10/11
- Python 3.10+
- API-ключ VirusTotal ([получить](https://www.virustotal.com/gui/my-apikey))
- Windows Defender

### Установка

1. Склонируйте репозиторий:
   ```powershell
   git clone https://github.com/nublu07/browser-download-scanner.git
   cd browser-download-scanner
   ```

2. Запустите установку:
   ```powershell
   install.bat
   ```
   Или вручную:
   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\pip install -r requirements.txt
   copy config.ini.example config.ini
   ```

3. Откройте `config.ini` и укажите API-ключ:
   ```ini
   [virustotal]
   api_key = ВАШ_КЛЮЧ
   ```

4. Включите автозапуск и запустите мониторинг:
   ```powershell
   .\.venv\Scripts\python.exe scanner.py --startup on
   .\.venv\Scripts\pythonw.exe scanner.py
   ```

### Настройки (`config.ini`)

| Параметр | Описание |
|----------|----------|
| `enabled` | Включить/выключить мониторинг |
| `run_at_startup` | Автозапуск при входе в Windows |
| `watch_folder` | Папка для мониторинга |
| `max_file_size_mb` | Максимальный размер файла (по умолчанию 1024 = 1 ГБ) |
| `api_key` | Ключ VirusTotal API |
| `detection_threshold` | Сколько движков должны сработать |
| `debug` | Подробный лог в `scanner.log` |

Изменения в `config.ini` применяются автоматически (перечитываются каждые 5 сек).

### Управление автозапуском

```powershell
python scanner.py --startup on      # включить
python scanner.py --startup off     # отключить
python scanner.py --startup status  # статус
```

### Структура проекта

```
browser-download-scanner/
├── scanner.py           # основной скрипт
├── config.ini.example   # шаблон настроек
├── install.bat          # установка
├── requirements.txt     # зависимости
└── README.md
```

### Ограничения

- Бесплатный тариф VirusTotal: ~4 запроса/мин — настраивается через `api_rate_limit_seconds`
- Полная проверка нового файла может занять больше 0.5 сек (ограничение API), но система не блокируется
- Проверяются только загрузки с меткой браузера; файлы, скопированные вручную или через torrent, игнорируются

---

## English

### Features

- Scans **browser downloads only** (Mark of the Web / `Zone.Identifier`)
- Watches **a single folder** (Downloads by default) — low system impact
- **Skips already scanned** files (SHA-256 cache)
- Fast detection; full VirusTotal scan runs in the background
- On threat: VirusTotal report page + Windows Defender quarantine + notification
- Settings in `config.ini` (folder, size limit, startup, debug)

### Requirements

- Windows 10/11
- Python 3.10+
- VirusTotal API key ([get one](https://www.virustotal.com/gui/my-apikey))
- Windows Defender

### Installation

1. Clone the repository:
   ```powershell
   git clone https://github.com/nublu07/browser-download-scanner.git
   cd browser-download-scanner
   ```

2. Run the installer:
   ```powershell
   install.bat
   ```
   Or manually:
   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\pip install -r requirements.txt
   copy config.ini.example config.ini
   ```

3. Edit `config.ini` and set your API key:
   ```ini
   [virustotal]
   api_key = YOUR_KEY
   ```

4. Enable startup and run the monitor:
   ```powershell
   .\.venv\Scripts\python.exe scanner.py --startup on
   .\.venv\Scripts\pythonw.exe scanner.py
   ```

### Configuration (`config.ini`)

| Parameter | Description |
|-----------|-------------|
| `enabled` | Enable/disable monitoring |
| `run_at_startup` | Run at Windows logon |
| `watch_folder` | Folder to watch |
| `max_file_size_mb` | Max file size (default 1024 = 1 GB) |
| `api_key` | VirusTotal API key |
| `detection_threshold` | Number of engines that must flag the file |
| `debug` | Verbose log to `scanner.log` |

Changes to `config.ini` are picked up automatically (reloaded every 5 seconds).

### Startup management

```powershell
python scanner.py --startup on      # enable
python scanner.py --startup off     # disable
python scanner.py --startup status  # check status
```

### Project structure

```
browser-download-scanner/
├── scanner.py           # main script
├── config.ini.example   # settings template
├── install.bat          # installer
├── requirements.txt     # dependencies
└── README.md
```

### Limitations

- VirusTotal free tier: ~4 requests/min — adjust via `api_rate_limit_seconds`
- Full scan of a new file may take longer than 0.5 s (API limits); the system stays responsive
- Only browser-marked downloads are scanned; manually copied or torrent files are ignored

---

## License

MIT
