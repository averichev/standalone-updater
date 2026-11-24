# Аудит и решения переноса

Источник: averichev/mockport, commit `e8705bceffc34d047023af4970997af8453ddf58`.
Проверены все модули, тесты и сценарии, перечисленные в задаче.

| Исходный модуль | Универсальная часть | Граница приложения / результат |
| --- | --- | --- |
| `src/self_update/client.rs` | HTTP, JWS Compact/Ed25519, RFC 7638, SemVer, product/target, лимиты, streaming/hash | `src/client.rs`; сохранён wire v1, URL источников передаются явно |
| `src/self_update/models.rs` | Descriptor, verified candidate, signed context, lifecycle/progress | `src/models.rs`; доверенный candidate по-прежнему нельзя десериализовать/сконструировать снаружи |
| `src/self_update/files.rs` | ELF, защищённые файлы, locks, fsync, права, disk space, identity процесса | ELF вынесен в `src/artifact.rs`; Linux filesystem/runtime — в `src/runtime/files.rs` |
| `src/application/updates.rs` | Проверка/подготовка, выбор конкретной версии, durable state, передача управления | `runtime/manager.rs`; удалены crate VERSION, MockPort Config, SocketAddr сервера, SQLx shutdown и application name |
| `src/infrastructure/update_worker.rs` | Preflight, worker copy, clean marker + EOF + parent exit, switch, health, rollback, recovery | `runtime/worker.rs`; вместо SQLite fingerprint — явный контракт данных, вместо `/health` — настроенный readiness route |
| `src/infrastructure/update_supervisor.rs` | Стабильный launcher PID, private runtime, контроль child, восстановление | `runtime/supervisor.rs`; нет фиксированного имени `mockport`, data dir или переменных MOCKPORT_* |
| `src/transport/updates.rs` | Полезный образец адаптера HTTP | Не перенесён в библиотеку; admin/CSRF/Origin остаются в приложении |
| `src/infrastructure/config.rs` | Определение ABI из compiled Rust target | Заменено явным RuntimeConfig/BuildInfo; release.config.json, OS-specific data directory, environment policy остаются у приложения |
| `src/main.rs` | Ранняя role dispatch, shutdown ordering, stderr logging | В `runtime::launch` и пример; browser, CLI admin, SQLx и transport/router не перенесены |
| `tests/self_update.rs` | Подписи, SemVer, лимиты, streaming, redirects, ELF, filesystem, concurrency | Проверки протокола сохранены в `tests/protocol.rs`; Linux filesystem/switch в `runtime/tests.rs` |
| `scripts/self-update-e2e.py` | Одноразовые сборки и ключи, Linux процессы, аварии/откат | Методика сохранена; новый `scripts/e2e.py` использует только независимый пример и OpenSSL |
| `docs/self-update.md` | Модель доверия, данные, lifecycle и recovery | Переработано для публичного контракта; сведения об авторизации и БД MockPort не объявлены свойствами crate |

Новая реализация не заменяет updater другим фреймворком. Сохранены проверенные
последовательности: резервирование блоков → download → hash/ELF → preflight →
hard-link backup → clean shutdown → durable intent → rename → readiness → rollback.
Supervisor и отдельный краткоживущий worker остаются двумя режимами одного файла.

## Уточнения, потребовавшие изменений

- Подготовка и установка разделены: оператор может проверить состояние и
  отключить источник после загрузки. До `install` shutdown не запрашивается.
- Worker и supervisor получают подписанный контекст без транспортного URL.
  Исходные argv/cwd остаются в доверенной конфигурации процесса; в заданиях их нет.
  Постоянные manifest hints также не содержат signed URL. Debug скрывает URL.
- `download` повторно проверяет candidate своим ключом, UUID, target и версией.
  Передача `VerifiedUpdate` между клиентами не обходит границу доверия.
- Проверяются все предки локальных путей; промежуточный symlink тоже отклоняется.
  FIFO открываются неблокирующе и затем отклоняются как не-regular.
- Staging явно задаётся через каталог обновлений, проверяется та же filesystem.
  Отдельный product binding не позволяет случайно разделить состояние двух продуктов.
- File locks имеют явный unlock при выходе из scope: унаследованный до exec FD
  постороннего дочернего процесса не продлевает освобождённую блокировку.
  В pre_exec не выделяется память на error path после fork.
- Recovery учитывает также `failed + recovery_required`, а не только переходные
  стадии. Бинарник, заменённый вручную вне задания, не перезаписывается откатом.
- Windows/macOS download проверяет подписанный размер/хеш без требования ELF;
  установка существует только для Linux, без фиктивных platform stubs.

Wire-протокол не изменён. Новый BuildInfo — локальный контракт runtime, а не
изменение standalone-protocol v1. На этапе обратной интеграции нужен адаптер.

## Проверенные альтернативы низкого уровня

- [reqwest 0.13](https://docs.rs/reqwest/0.13.5/reqwest/) остаётся HTTP-клиентом:
  строгая redirect policy, timeout и ограничение потока не требуют нового backend.
- [ed25519-dalek](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/) остаётся
  криптографическим primitive; применяется `verify_strict`. Не добавлен общий JWT
  framework: он расширил бы поддерживаемые алгоритмы и схему без необходимости.
- [std::fs::File::try_lock](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
  доступен в выбранном MSRV и заменяет fs2 для блокировок. libc уже нужен для
  Linux process identity/signals; statvfs/posix_fallocate сохраняют исходную
  проверку свободного места и реальное выделение блоков без второй lock-библиотеки.
- [fs4](https://docs.rs/fs4/) рассмотрен как поддерживаемая альтернатива fs2;
  при Linux-only runtime и стандартных file locks дополнительная зависимость
  не даёт доказанного преимущества.
- [self_update](https://docs.rs/self_update/) и self_replace не использованы:
  само по себе скачивание/замена не заменяет текущий протокол подписи, clean-stop
  handoff, nonce readiness, совместимость данных и recovery supervisor.
- Ручной ELF64 validator сохранён: проверяются только два допустимых Linux ABI,
  header, segment bounds и executable entry point. Добавление универсального
  object/parser crate ради этого узкого набора проверок не улучшает установленный
  контракт. Исполнимость дополнительно проверяется bounded preflight-процессом.
