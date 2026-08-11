# Browser Download Scanner

**RU:** Фоновый сканер браузерных загрузок через [VirusTotal](https://www.virustotal.com). При угрозе — страница отчёта, уведомление и проверка Windows Defender.

**EN:** Background scanner for browser downloads via [VirusTotal](https://www.virustotal.com). On threat — report page, notification, and Windows Defender scan.

---

## Быстрый старт / Quick start

| Файл | Действие |
|------|----------|
| `install.bat` | Первая установка |
| `start.bat` | Запустить мониторинг |
| `stop.bat` | Остановить |
| `status.bat` | Статус |
| `config.ini` | Настройки и API-ключ |

---

## Русский

### Возможности

- Только **браузерные загрузки** (Mark of the Web / `Zone.Identifier`)
- Мониторинг **одной папки** (по умолчанию «Загрузки»)
- Кэш SHA-256 — повторно не тратит запросы к API
- Повторная загрузка **известной угрозы** снова показывает VirusTotal
- Автозапуск через папку «Автозагрузка» Windows
- Горячее перечитывание `config.ini` (каждые 5 сек)

### Установка

1. Установите [Python 3.10+](https://www.python.org/downloads/)
2. Запустите **`install.bat`**
3. Укажите API-ключ в `config.ini`:
   ```ini
   [virustotal]
   api_key = ВАШ_КЛЮЧ
   ```
   Ключ: https://www.virustotal.com/gui/my-apikey
4. Запустите **`start.bat`**

### Настройки (`config.ini`)

| Параметр | Описание |
|----------|----------|
| `enabled` | Вкл/выкл мониторинг |
| `run_at_startup` | Автозапуск при входе в Windows |
| `watch_folder` | Папка для мониторинга |
| `max_file_size_mb` | Лимит размера (1024 = 1 ГБ) |
| `scan_existing_on_startup` | Проверить уже лежащие файлы при старте |
| `api_key` | Ключ VirusTotal |
| `detection_threshold` | Сколько движков должны сработать |
| `debounce_seconds` | Ожидание завершения скачивания |
| `api_rate_limit_seconds` | Пауза между запросами API (~4/мин) |
| `debug` | Подробный лог в `scanner.log` |

### Команды

```powershell
start.bat                              # запуск
stop.bat                               # остановка
status.bat                             # статус
scanner.py --scan-file "C:\path\file"  # проверить один файл
scanner.py --startup on|off|status     # автозапуск
```

### Структура

```
Browser Download Scanner/
├── install.bat          # установка
├── start.bat            # запуск
├── stop.bat             # остановка
├── status.bat           # статус
├── scanner.py           # основной скрипт
├── config.ini           # ваши настройки (не в git)
├── config.ini.example   # шаблон
├── requirements.txt
└── README.md
```

### Ограничения

- Бесплатный VirusTotal: ~4 запроса/мин, загрузка файлов до 32 МБ
- Файлы >32 МБ проверяются только если уже есть в базе VT (по hash)
- Torrent, ручное копирование — игнорируются (нет метки браузера)

---

## English

### Features

- **Browser downloads only** (Mark of the Web)
- **Single folder** watch (Downloads by default)
- SHA-256 cache avoids redundant API calls
- Re-downloading a **known threat** triggers alert again
- Autostart via Windows Startup folder
- Hot-reload of `config.ini`

### Installation

1. Install [Python 3.10+](https://www.python.org/downloads/)
2. Run **`install.bat`**
3. Set API key in `config.ini`
4. Run **`start.bat`**

### Commands

```powershell
start.bat    # start monitoring
stop.bat     # stop
status.bat   # show status
```

---

## License

MIT — see [LICENSE](LICENSE)
