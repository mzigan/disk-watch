# План disk-watch

- Модули: config, devices, smart, alert, kernel, state, notifier; main связывает CLI и задачи Tokio.
- Discovery: lsblk JSON, только физические disk; namespace NVMe объединяются по контроллеру. Sysfs даёт partition/ATA aliases для корреляции.
- SMART: smartctl -j -a с timeout, serde_json; ненулевой exit status интерпретируется как битовая маска. Неизвестные vendor attributes игнорируются.
- State: versioned JSON, ключ WWN либо model+serial; fallback device явно отмечается. Предыдущий SMART, temperature latch, присутствие, kernel evidence и bounded recent alerts. Atomic temp/write/fsync/rename, lock для единственного writer; повреждение не мешает запуску.
- Journald: отдельная задача journalctl -k -f -o json, cursor для возобновления, reconnect. Исходные сообщения сохраняются в событиях. Невозможность корреляции не теряет событие. SMART не очищает kernel evidence.
- Events: Info/Warning/Critical, сравнение счётчиков, восстановление, температурный hysteresis. Kernel события всегда логируются, desktop suppression по категории/диску с cooldown.
- CLI: daemon, check (однократные SMART + последние 200 kernel записей), devices, status. Общие --config и --state. check/status выводят snapshot и alerts.
- Уведомления: tracing в stderr/journal; optional notify-send только при явно доступной session bus. Telegram и автоматические self-tests отложены.
- Ограничения: kernel evidence сохраняется как исторический факт; отсутствие новых ошибок не доказывает восстановления. ATA port может соответствовать нескольким дискам — сообщаем неоднозначность. SMART polling не блокирует чтение journal; команды имеют timeout. Нет shell interpolation.
- Проверки: fixtures для HDD/SSD/NVMe/kernel, diff/severity/suppression/recovery/state; fmt, clippy, test, release build. Проверка реальных устройств только read-only.

## Доработка после аудита

Сохраняются восемь модулей. SMART: до 3 параллельных команд, отдельный результат
на диск; explicit exit bits, Option-поля и stale markers, identity race, sleeping
и enum self-test. Journal: storage context, точное имя перед ATA-портом,
проверка diskseq/boot/time, cursor cache + monotonic watermark. Background task
exit завершает daemon для systemd restart. State v2 читает v1; один coalescing
writer с spawn_blocking не задерживает обработку событий. Suspend/resume,
watchdog, exotic bridges, durable notifications сознательно остаются за рамками.
