# Модель угроз и ограничения

## Доверенная база

Доверяются встроенный/явно настроенный product_id, закреплённый Ed25519 JWK,
версия и Rust target **приложения**, его lifecycle adapter, data fingerprint,
readiness decision, ОС/kernel, filesystem и владелец учётной записи процесса.
Update server, manifest/descriptor и сеть считаются недоверенными.
Readiness route принадлежит приложению и не принимает решение об установке.

Злоумышленник, управляющий сервером или сетью, может задержать/скрыть релиз,
повредить документ/байты, подменить URL, предложить другой продукт/ABI/версию,
вернуть чрезмерный объём или redirect. Он не должен получить возможность
выполнить неподписанный или несоответствующий бинарник.

Другой локальный пользователь может пытаться подставить symlink, path traversal,
небезопасный writable каталог или конкурирующий процесс. Файлы обновлений
изолированы процессными 0700 каталогами. Root и другой процесс **того же UID**
за границей защиты: они способны заменить приложение/библиотеку или изменить
саму доверенную конфигурацию. Нет sandbox для подписанного publisher-кода.

## Защитные проверки

| Угроза | Проверка |
| --- | --- |
| Подмена ключа/алгоритма | Единственный закреплённый Ed25519 JWK, strict verify; unknown/duplicate JSON fields, private `d`, jku/jwk/crit/b64=false отвергаются |
| Неполный подписанный контекст | Проверяются исходные ASCII signing bytes, schema=1, UUID продукта, точный os/arch, каноническая SemVer, descriptor version, размер и lowercase SHA-256 |
| Downgrade или повтор той же precedence | Требуется строго более новая стабильная версия; build metadata не повышает precedence |
| Чужой VerifiedUpdate | Download заново проверяет ключ, product, target и version своего клиента |
| Подмена URL/redirect | HTTPS; HTTP только с literal loopback IP; нет credentials/fragment/proxy; metadata redirect только same-origin, artifact только explicit allowlist; максимум три перехода |
| Unbounded/slow download | Connect/read/total deadlines; документ 16 КиБ, JWS 4096, manifest 512 КиБ; streaming до подписанного размера, превышение немедленно отклоняется |
| Повреждение файла | Exact bytes + SHA-256; Linux ELF64 header, machine, program segments, ranges и entry point; bounded execution preflight проверяет runtime/ABI/data compatibility |
| Подмена локальных файлов | O_NOFOLLOW/O_CLOEXEC/O_NONBLOCK, create_new, regular files, owner/modes, все предки без symlink и небезопасной записи; staged bytes/backup/current hash перепроверяются перед rename |
| Конкурирующий/повторный switch | File locks state/operation/server/supervisor, случайный ID, stage binding, Linux PID+starttime, current binary hash; prepared file не переиспользуется |
| Авария вместо штатного stop | Durable clean marker + EOF + exit исходного процесса; у supervisor дополнительно успешный exit и bounded control pipe |
| Потеря питания/авария при switch | Сначала fsync файла и директорий/backup/job/intent; затем atomic same-filesystem rename и fsync обеих директорий; восстановление по прежнему hash |
| Старая/чужая готовность | Фиксированный loopback probe без redirect/proxy, точные version + случайный nonce запуска, проверка живого child и survival window |
| Ошибка новой версии | Завершение child, проверка backup, binary-only rollback и readiness прежней версии |
| Затёртая ручная установка | Неизвестный current hash блокирует restore; original launcher с новым hash осознанно supersedes прежний runtime |
| Утечка секретов | Typed errors с ErrorKind вместо OS paths/remote bodies; redacted Debug; URL/argv/cwd/environment отсутствуют в update jobs и status; transient JWS context не содержит transport URL |
| Изменение пользовательских данных updater-ом | Runtime пишет только executable и отдельное updater-поддерево; не открывает бизнес-БД, не применяет migrations, не создаёт копий данных |

Сетевые defaults: connect 5 с, read 15 с, документы 20 с, artifact 600 с;
нет автоматической распаковки архивов или content decompression. Preflight 10 с,
16 КиБ; control pipe до 128 КиБ. Readiness HTTP request до 2 с/4 КиБ;
общий startup deadline настраивается, максимум 300 с.

## Чего гарантии не включают

- Протокол v1 не TUF: нет freshness/expiry, revocation, threshold signing или
  гарантии защиты от freeze. Сервер может предложить более старый **ещё не
  установленный**, но всё ещё более новый чем current подписанный выпуск.
- Нет автоматической ротации ключей. Смена закреплённого trust anchor требует
  явно доставленной доверенной конфигурации/нового launcher. Работающий supervisor
  продолжает проверять своим первоначальным источником доверия.
- Подпись подтверждает издателя и байты, а не безопасность бизнес-кода. Совпадение
  fingerprint не доказывает семантическую совместимость; malicious/ошибочный
  publisher может ложно сообщить совместимость и повредить данные при запуске.
- Binary rollback не восстанавливает БД, файлы, внешние эффекты или очереди.
  Изменённые migrations требуют ручного плана backup/migration и ManualOnly.
- Гарантии atomicity/durability рассчитаны на локальную Linux filesystem с
  корректными rename/fsync/hard-link/flock semantics. NFS/CIFS/overlay и аварии
  накопителя требуют отдельных испытаний. Staging на другой filesystem запрещён.
- Предки с symlink, чужим владельцем или небезопасной записью намеренно не
  поддерживаются. Исходный root-owned read-only launcher допустим только для
  supervisor; рабочая копия/staging всегда принадлежат UID процесса.
- Snapshot polling — диагностика, а не транзакционный IPC для бизнес-решений.
  Не интерпретируйте `signature_verified` как проверку скачанных байтов.
- Child stdout в supervisor — control channel. Произвольные логи в stdout
  отменяют handoff. При некорректной интеграции безопаснее остановка, чем догадка.
- Во standalone child после успешного handoff живёт независимо от worker.
  Если worker погиб во время readiness, остановите оставшийся server прежде
  recovery. Supervisor использует PR_SET_PDEATHSIG и не оставляет orphan server
  после SIGKILL launcher.
- Библиотека не управляет systemd, sudo, сервисами, реестрами внешнего менеджера,
  startup policy, рестартами после обычного crash приложения или обновлением rootfs.
- 0.1.0 ещё не прошла обратную интеграцию в MockPort. Тесты fault injection не
  заменяют независимый security audit и испытания реального отключения питания.

## Регрессии безопасности

Rust tests сохраняют исходные malformed JWS/context/JSON/hash/ELF/redirect cases.
Дополнительно проверяются cross-client trust, удаление URL из Debug, traversal
в промежуточных каталогах, FIFO, реальные file locks, backup invariants и отказ
перезаписывать ручную установку. OpenSSL E2E signer обеспечивает независимую
реализацию подписывания. Process E2E проверяет успешные и аварийные пути на
временных данных, сохранение argv/cwd/environment и отсутствие test-секретов
в **каждом** постоянном JSON runtime.
