# disk-watch

Небольшой Linux-specific демон для Linux Mint / Debian / Ubuntu с systemd.
Независимо следит за SMART HDD/SATA SSD/NVMe и I/O-ошибками ядра.
Без серверов, БД и web UI; восемь основных модулей в `src/`.

**SMART PASSED не гарантирует исправность и не предсказывает все отказы.**
Timeout, I/O error, UNC, reset link и aborted journal учитываются независимо.
Хороший SMART не сбрасывает исторический kernel Critical.

## Сборка и установка

Нужны Rust stable >= 1.89, `smartmontools` (7.2+),
`lsblk` из util-linux и `journalctl`. Для необязательных desktop notifications —
`notify-send` из `libnotify-bin`.

```bash
sudo apt install smartmontools util-linux
cargo build --release --locked
sudo install -m755 target/release/disk-watch /usr/local/bin/disk-watch
sudo install -d -m755 /etc/disk-watch
sudo install -d -m700 /var/lib/disk-watch
sudo install -m644 packaging/config.toml /etc/disk-watch/config.toml
sudo install -m644 packaging/disk-watch.service /etc/systemd/system/disk-watch.service
sudo systemctl daemon-reload
sudo systemctl enable --now disk-watch
journalctl -u disk-watch -f
```

Root нужен для доступа `smartctl` к устройствам. Unit ограничивает запись
каталогом state, сохраняя доступ к `/dev`, `/sys` и journal. Сборка сама ничего
не устанавливает и не запускает.

## CLI

```bash
sudo disk-watch devices
sudo disk-watch check
sudo disk-watch status
sudo disk-watch status --verbose # подробности и Recent events
sudo disk-watch daemon
sudo disk-watch --config ./packaging/config.toml --state /tmp/disk-watch/state.json check
```

- `devices`: discovery без SMART, текущие пути, model/serial/WWN.
- `check`: один SMART-проход, kernel journal, сохранение state и вывод результатов.
  Без cursor читает последние 200 сообщений текущей загрузки; с cursor — новые
  записи после него. Код 1 означает неполную проверку/ошибку команды или конфигурации;
  сам health Warning/Critical не меняет код 0. Пропуск sleeping HDD — не ошибка.
- `status`: только краткий summary (counts и причины для Critical/Warning/Unknown).
- `status --verbose`: тот же summary, затем подробные данные state и Recent events
  без обращения к накопителям, включая возраст данных через
  время последней успешной SMART-проверки в Unix seconds. Это исторический snapshot,
  а не подтверждение работы демона или свежести показателей прямо сейчас.
- `daemon`: SMART/discovery по таймеру и непрерывный kernel journal.

`check` и `daemon` блокируют один lock рядом со state. При работающем сервисе
используйте `status` либо отдельный `--state`. Чтение status не блокирует writer.

## Конфигурация и Unknown

Образец: [packaging/config.toml](packaging/config.toml). По умолчанию читается
`/etc/disk-watch/config.toml`; если его нет, используются встроенные значения.
Ошибки TOML, неизвестные ключи и явно заданный отсутствующий файл — ошибка.
Изменения применяются после перезапуска.

SMART/discovery: сразу при старте, затем через 1800 секунд после завершения прохода.
Не больше трёх `smartctl` одновременно; timeout каждой команды — 60 секунд.
Каждый готовый результат обрабатывается сразу, не дожидаясь остальных дисков.
Температура: HDD 50 °C, SSD 60 °C, NVMe 70 °C, hysteresis 5 °C.
`[smart].enabled = false` сохраняет discovery и kernel monitoring.
`[devices].ignore_serials` исключает SMART-проверку; такие устройства остаются
в топологии для проверки неоднозначности ATA-порта.

`Unknown` означает, что текущее здоровье нельзя подтвердить: нет пригодного
snapshot, диск спит, чтение не удалось, идентичность изменилась или часть ранее
известных полей пропала. Предыдущие значения сохраняются с `stale/unknown fields`,
а `last known severity` отдельно показывает прошлое знание. `None` — поле не
получено. Отсутствие поля никогда не означает ноль или восстановление.
Достоверный свежий `DISK FAILING` и kernel Critical остаются Critical даже при
неполной SMART-проверке. Ошибка проверки не обнуляет предыдущие показатели.

Exit status smartctl разбирается по битам: ошибки получения данных отдельно от
`DISK FAILING`, prefailure и исторических threshold/error-log/self-test признаков.
При ошибке чтения/checksum сомнительные измерения не принимаются; явные health-биты
сохраняются. Поэтому `4 | 8` даёт Critical плюс сообщение о неполной проверке.
Исторические биты 5–7 дают Warning при появлении и не означают сами по себе отказ.

## Спящие диски и vendor SMART

```toml
[smart]
enabled = true
skip_sleeping = true
```

По умолчанию HDD проверяются с `-n standby,3`: sleeping/standby даёт `Sleeping`,
сохраняет snapshot и время последней успешной проверки. Код 3 считается пропуском
только при подтверждающем JSON `power_mode` либо сообщении о STANDBY/SLEEP в
`smartctl.messages` (формат 7.2). Ошибки bridge дают Warning; в 7.2 неподдержанный
power check может быть проигнорирован самим smartctl. SSD/NVMe этой опцией не ограничиваются. При `false` опрос может
раскручивать HDD. Autodetection `smartctl` тоже может разбудить некоторые bridge:
универсальной гарантии для USB/RAID нет. Экзотические мосты с требуемым `-d` не поддержаны.
Семантика `-n` описана в [smartctl manual](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_2/smartmontools/smartctl.8.in).

ATA-показатели распознаются по известным именам, не только ID. `197/Not_In_Use`
не становится pending sector. Неизвестные поля сохраняются в `unknown_attributes`
и не создают health alert. Составной raw, например Seagate `Command_Timeout`
с несколькими числами, не сравнивается как один счётчик. Для `Command_Timeout`
необходим явно скалярный `raw.string`, совпадающий с `raw.value`.
Остаток ресурса SSD трактуется только для известных имён.

Self-tests не запускаются. Последний доступный в JSON результат различает
`Passed`, `Failed`, `Aborted`, `InProgress`, `Unknown`. Доступность self-test log
в `smartctl -a` зависит от версии и устройства; отсутствие результата не считается
успешным тестом. Автоматического расписания нет.

## Идентичность и kernel journal

Discovery: `lsblk --json --paths --nodeps`, только физические `disk`, без
loop/ram/zram/dm/md/partitions. NVMe namespaces объединяются в `/dev/nvmeN`.
Ключ state — WWN либо model+serial; при отсутствии идентификаторов — путь с Warning.
Нулевой WWN (в том числе с `0x` или разделителями) считается отсутствующим в discovery,
SMART и при выборе identity. Старые общие записи `wwn:0000000000000000` при загрузке
исключаются с Warning: принадлежность их истории восстановить нельзя.
Обогащение identity из истории и перенос state требуют совпадения стабильной identity:
путь, diskseq, порядок устройств и один serial без model для этого не используются.
При получении стабильной identity история path-only записи не переносится.
Перед stale merge проверяется, что прежний SMART snapshot не противоречит identity диска.
Если чужие значения уже сохранены под правильными идентификаторами нового диска,
их происхождение восстановить нельзя; потребуется ручной сброс загрязнённого state.
Данные SMART могут дополнить отсутствующие идентификаторы. Несовпадающие serial/WWN
или смена Linux diskseq дают `StaleRace` и Warning, без записи нового snapshot
старому диску. Если стабильные идентификаторы недоступны, проверяется model.
Различия написания model при совпадающем serial/WWN не считаются заменой диска.

Kernel reader использует JSON `journalctl -k -f`, cursor и структурированное время.
Kernel evidence сохраняется только под identity, выбранной при корреляции события;
`uncorrelated` события остаются в общем журнале и не меняют health конкретных дисков.
`failed command` требует storage-контекста; `wifi: failed command` игнорируется.
Классификация находится в `src/alert.rs` и `src/kernel.rs`.

Sysfs связывает ATA-порты и partitions с дисками. Явное `dev sdX` (также `/dev/sdX`
и известные partitions) сначала сопоставляется напрямую с текущим discovery map,
без требований к diskseq и возрасту записи. Затем проверяются имена в квадратных
скобках (`[sde]`, `[nvme0n1]`) по тому же текущему discovery map.
Неизвестное или неоднозначное имя
даёт `uncorrelated`, без попытки угадать диск по ATA-порту.
Для остальных сообщений сохраняются проверки ATA-корреляции: boot id, время
относительно discovery и актуальный sysfs diskseq; неоднозначность даёт `uncorrelated`.
Прямое сопоставление отражает текущую карту: при переиспользовании `/dev/sdX`
историческая запись может относиться к другому накопителю.
Нет исторической топологии и udev subscription; новая топология определяется
следующим discovery. RAID/HBA/multipath и exotic USB bridges вне поддержки MVP.

State хранит cursor, boot id, последние 2048 cursor и monotonic watermark текущей
загрузки. Повторный `check` не размножает события. Если cursor удалён vacuum,
есть одна попытка bounded replay последних 200 сообщений с дедупликацией.
Записи старее watermark не принимаются; равные timestamps различаются cursor.
Без корректных cursor/monotonic timestamp полнота дедупликации не гарантируется.
Удалённые journal-записи восстановить невозможно.

## State и эксплуатационные ограничения

Файл `/var/lib/disk-watch/state.json`, версия 2; версия 1 читается с миграцией.
Старые snapshots сохраняются, но до новой проверки не объявляются свежими.
При повреждении state выводится Warning и начинается пустая история.
Диски и последние 100 alerts сохраняются; historical kernel severity сама не исчезает.
Для ручного сброса остановите сервис и переместите state в резервную копию.

В daemon единственный writer получает последний snapshot примерно раз в 2 секунды.
Запись и fsync идут через `spawn_blocking`: temp + fsync + rename + fsync каталога,
права 0600. Медленная запись не останавливает обработку kernel/SMART; промежуточные
snapshots объединяются, очередь не растёт. Ошибка записи даёт повтор через 2 секунды.
SIGINT/SIGTERM запрашивают финальную запись. При аварии возможен replay последних
событий. Зависший kernel I/O нельзя гарантированно отменить: при зависшем fsync
окончательное ограничение остановки задаёт systemd `TimeoutStopSec=15`.

Неожиданный exit/panic journal reader, SMART scheduler или writer завершает daemon
с ошибкой; systemd `Restart=on-failure` перезапускает сервис через 5 секунд.
**Watchdog и timeout молчания kernel journal отсутствуют**: тишина не означает сбой.
Специальной обработки suspend/resume нет; после resume таймер продолжает ожидание,
немедленный SMART/discovery не гарантирован.

Desktop notifications по умолчанию выключены. `[alerts].desktop = true` требует
`notify-send` и явно доступного `DBUS_SESSION_BUS_ADDRESS`. Системный root service
обычно не имеет пользовательской DBus-сессии; программа не угадывает пользователя.
Повтор kernel category/disk/severity подавляется на 300 секунд. Доставка best effort:
ошибка DBus/переполнение очереди не создаёт durable retry; исходное событие остаётся
в journal. Большие/нестандартные MESSAGE могут быть пропущены с Warning; специального
парсера таких записей нет. Telegram и автоматические self-tests не реализованы.

Внешние команды запускаются отдельными аргументами `Command`, без shell interpolation.
Управляющие символы в выводе и markup desktop body экранируются.

## Проверки

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

Unit/CLI regression tests используют fixtures и подставные команды; настоящие диски
не нужны. Покрыты mixed exit bits, race идентичности, missing fields, vendor raw,
replay, немедленный Critical, медленный writer, остановка reader, sleeping и aborted
self-tests, а также прежние проверки diff/hysteresis/state/SMART PASSED + kernel Critical.

### Обновление

```bash
cargo build --release
sudo install -m755 target/release/disk-watch /usr/local/bin/disk-watch
sudo systemctl restart disk-watch
```