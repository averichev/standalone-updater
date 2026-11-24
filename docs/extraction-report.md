# Отчёт о выделении standalone-updater 0.1.0

Проверка выполнена 2026-11-24. Рабочий MockPort, «Релизы» и «Мой Хост» не изменены.
Crate самостоятельный; MIT, MSRV 1.91, Cargo.lock, publish=false. Публичный GitHub
разрешён владельцем отдельно для использования в Cargo.toml других проектов.
Release/tag/crates.io не создавались. Стабильность API не объявлена.

## Перенесённые механизмы

`self_update/client.rs` → `src/client.rs`: протокол, HTTP, JWS/Ed25519, RFC 7638,
UUID, SemVer и target, bounded streaming, hash/size. `self_update/models.rs` →
`src/models.rs`: descriptor, immutable verified candidate, signed context,
states/progress/errors. `self_update/files.rs` → `src/artifact.rs` и
`src/runtime/files.rs`: ELF64, filesystem policy, locks, fsync, disk reservation,
process identity. `application/updates.rs` → `runtime/manager.rs`:
check/prepare/install/cancel, status и lifecycle handoff. Infrastructure worker и
supervisor → `runtime/worker.rs`/`supervisor.rs`: private working copy, стабильный
launcher PID, отдельная временная копия worker, clean-stop handshake, atomic
switch, restart/readiness, rollback, crash recovery. Подробное сопоставление — audit.md.

Axum routes, auth/CSRF/Origin, SQLite/SQLx, frontend, browser, release.config.json
и бизнес-конфигурация MockPort остались за границей crate. Серверные пути/домены
не зашиты в библиотеку; обязательный JWS typ взят из внешнего протокола v1.

## Публичный API

Клиент: `UpdateSource`, `PublicKey`, `UpdateClient::{new,check,verify,download}`,
`VerifiedUpdate`, `SignedMetadata`, `DownloadEvent`, `OperationStatus`, `Stage`,
`CheckOutcome`, typed `UpdateError`.

Linux feature: `BuildInfo`, `RuntimeConfig`, `InstallationMode`, `DataPolicy`,
`Readiness`, `runtime::{launch,recover,active_executable}`, `Launch`,
`UpdateManager::{check,prepare,install,cancel_prepared,status,summary,
shutdown_requested,ready_response,finish_shutdown}` и `InstallRequest`.

Поток интеграции: ранний BuildInfo → launch → check → prepare → явный install →
graceful drain/закрытие ресурсов приложением → finish_shutdown → выход main.
После prepare установка офлайн. External и ManualOnly сохраняют check, запрещая
подготовку/установку. Readiness route и решение о готовности принадлежат приложению.

## Проверки

Локальный Linux стенд: Docker, aarch64 GNU, rustc 1.91.1. Клиент дополнительно
проверен на macOS aarch64; матрица CI повторяет проверки на Ubuntu/macOS/Windows
с MSRV и stable. Фактический результат remote CI доступен в GitHub Actions.

- `cargo fmt --all -- --check` — проходит.
- `cargo clippy --locked --all-features --all-targets -- -D warnings` — проходит.
- `cargo test --locked --all-features` — 9 Linux unit tests, 14 protocol integration
  tests, 1 compiling rustdoc example; все проходят.
- `cargo test --locked --no-default-features` — 14 protocol tests и rustdoc проходят.
- `RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps` — проходит.
- Cargo package contents проверены через `cargo package --list --allow-dirty`;
  нет production-конфигурации, приватных ключей, target/fixtures или MockPort assets.
- cargo-audit 0.23.0: 190 зависимостей, 0 известных уязвимостей, 0 предупреждений.
  RustSec database: 1566 advisories, commit
  `1d328b6bb9f2f350bf65c1c81ab68781cb9e018a`.

`scripts/e2e.py` проходит **21 процессный сценарий** на независимом
`examples/axum-service.rs`. Подписи создаёт одноразовый Ed25519 key через OpenSSL,
проверяет библиотека Rust. Проверены:

- Оба режима: signed update 0.5.0 → 0.6.0, restart, байты бинарника, конкурентная
  подготовка, прогресс, offline install/restart, неизменные config/data/argv/cwd/env.
- Supervisor: повторное обновление → 0.7.0, тот же PID, запуск после SIGKILL.
- Оба режима: rollback при startup failure и health failure.
- Оба режима: несовместимый data fingerprint отклоняется до shutdown.
- Оба режима: SIGKILL во время загрузки не меняет executable и восстанавливает
  доступность checks; partial удаляется без доступа к источнику.
- Supervisor: SIGKILL после switch автоматически восстанавливает backup.
- Standalone: SIGKILL worker после switch, остановка оставшегося server,
  явный offline recovery и запуск прежней версии.
- External, read-only standalone directory и ManualOnly supervisor: check доступен,
  install запрещён, artifact не запрашивается.
- Оба режима: ошибка shutdown и EOF без clean marker не разрешают switch.
- Standalone: клиент install отключается без чтения ответа; фоновый handoff
  доводит установку до подтверждённой готовности.
- Ограниченный реальный tmpfs: нехватка места обнаруживается до download/shutdown.
- Непривилегированный UID: обновляется private working copy root-owned launcher
  в каталоге без права записи; исходный launcher неизменен.

Дополнительные unit-регрессии: symlink в предках, traversal/FIFO/modes,
fsync/persistent state, process identity, чужой product binding, повреждённый
backup, ручная замена бинарника, stale/replayed recovery, nonce и survival check.
Отдельный fork-тест проверяет, что унаследованный до exec FD не продлевает уже
освобождённый lock. `pre_exec` error path не выделяет память после fork.

Машинные локальные отчёты создаются в target/validation и не публикуют тестовые
данные. Production-файлы и signing keys при испытаниях не открывались.

## Адаптеры и оставшиеся ограничения

Приложению нужны собственные build identity, source config, full Rust target,
fingerprint данных, lifecycle/bootstrap role dispatch, admin transport,
shutdown drain/close и readiness decision. Для SQLx закрытие pool и SELECT 1
остаются приложению. Новый формат local journal требует отдельного безопасного
перехода; незавершённые задания MockPort автоматически не мигрируют.

Установка только Linux ELF64 x86_64/aarch64; общий клиент поддерживает шесть target
протокола. Локальные процессные испытания этого выделения проведены на aarch64 GNU;
дополнительная матрица deployment/musl/filesystem и настоящая обратная интеграция
MockPort остаются release gate. Нет гарантий data rollback, TUF/freshness/revocation,
защиты от root/того же UID, retention policy, manager registry/systemd/sudo или
постоянного внешнего агента. Readiness в 0.1.0 — fixed loopback HTTP route.

Откат бинарника не означает откат данных. Exact fingerprint блокирует изменённые
migrations, но издатель обязан сохранять семантику форматов. Подробные гарантии —
security.md; дальнейшие действия — mockport-migration.md и release-gate.md.
