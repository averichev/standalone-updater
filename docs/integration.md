# Контракт приложения

## Источник и identity

Приложение задаёт `UpdateSource` из своей доверенной конфигурации: постоянный
product UUID, публичный Ed25519 JWK, независимые manifest/descriptor URL,
точный allowlist artifact origin и предел размера. Descriptor URL не содержит
query; библиотека добавляет единственный `current_version`. Единственная
подстановка — `{target}`. Никогда не принимайте эти параметры из admin-запроса.

`UpdateClient::new(source, current_version, protocol_target)` не выполняет сеть.
`check().await` одновременно читает descriptor и необязательный manifest.
204 означает отсутствие подписанного обновления. Недоступный manifest не
отменяет валидную подпись; ошибка descriptor/подписи не разрешает install из manifest.
`VerifiedUpdate` закрыт для самостоятельного конструирования/десериализации.
`download` ещё раз проверяет его своим trust anchor и пишет только в явно
переданный вызывающим writable regular file. Вызывающий отвечает за изоляцию
этого файла и удаление partial при ошибке. Linux runtime делает это сам.

Для Windows/macOS доступны проверка и загрузка с проверкой размера/хеша.
Linux-кандидаты дополнительно проходят ELF64 validation. Для установки нужен
feature `linux-runtime` и сборка под Linux; на других ОС `runtime` отсутствует.

## Минимальный bootstrap runtime

Полный компилируемый адаптер: `examples/axum-service.rs`. Его HTTP handlers,
loopback restriction, bearer authorization и Origin policy — код примера,
а не свойства библиотеки. В реальном приложении используйте его действующую
административную границу, CSRF и политику Origin.

`BuildInfo` формируется **из версии приложения и его compilation target**:

```rust
use standalone_updater::runtime::BuildInfo;

let build = BuildInfo {
    version: "0.5.0".into(),
    rust_target: "x86_64-unknown-linux-musl".into(),
    product_id: "44872c33-bef2-4c34-9290-29d762b6d965".into(),
    self_update_protocol: 1,
    data_compatibility: "migrations-and-formats-fingerprint-v1".into(),
};
```

`build.handle_cli()?` вызывается до чтения бизнес-конфигурации и открытия данных.
Он отвечает только на изолированный `--standalone-updater-build-info`.
Кандидат обязан обработать этот запрос без migrations/startup side effects.
Preflight ограничен 10 секундами и 16 КиБ stdout. `rust_target`, product,
runtime protocol и fingerprint должны совпасть; version должна быть ожидаемой.

Сохраните исходные аргументы приложения, исключив первый внутренний role flag.
Зарезервированы `SERVER_ARGUMENT`, `WORKER_ARGUMENT`, `RECOVER_ARGUMENT` и
`BUILD_INFO_ARGUMENT`. Их константы экспортирует runtime. Пример показывает
полную диспетчеризацию, включая worker и recovery до бизнес-старта.

`RuntimeConfig` содержит:

| Поле | Значение |
| --- | --- |
| `source`, `build` | Закреплённое доверие и identity текущего приложения |
| `executable` | Полный реальный путь исполняемого файла, обычно `current_exe()` |
| `updates_directory` | Отдельный process-owned каталог 0700 для state/runtime/staging |
| `arguments`, `working_directory` | Прежние параметры запуска, без updater role flag |
| `mode` | Supervisor, Standalone или External |
| `data_policy` | RequireExact либо ManualOnly |
| `readiness` | Фиксированный локальный HTTP-адрес, route, deadline, survival window |

`runtime::launch(config).await?` вызывается перед listener, migrations и БД.
`Launch::Exit(code)` означает завершение внутренней роли; верните code из main.
`Launch::Serve(manager)` разрешает обычный запуск приложения. Не печатайте
логи в stdout: в supervisor-режиме он принадлежит control pipe. Используйте stderr.

Каталог обновлений не должен быть каталогом пользовательских данных целиком:
это отдельное поддерево, например `<data>/updater`. В нём создаются:

```text
product.json          привязка состояния к product_id
status.json           redacted snapshot / progress
job.json              локальное задание восстановления без URL/argv/environment
*.lock                state, operation, server, supervisor locks
runtime/<имя файла>   рабочий бинарник supervisor (исходное имя не фиксировано)
runtime/launcher.json SHA-256 и product identity исходного launcher
staging/              candidate, backup, временный worker и clean-stop markers
```

Runtime автоматически создаёт приватные каталоги, но не меняет права существующих
каталогов. Предки должны принадлежать root/процессу и не разрешать group/other write;
допускается root-owned sticky temporary root. Symlink предки отклоняются.
В standalone бинарник/его каталог должны принадлежать процессу и допускать запись;
staging должен находиться на той же filesystem. В supervisor исходный launcher
может принадлежать root и быть read-only; заменяется только private working copy.

## Операции, прогресс и подтверждение

`manager.check()` возвращает snapshot с ID и начинает фоновой check.
`manager.status()`/`summary()` возвращают сериализуемые данные. Перечень `Stage`
и `CheckOutcome` находится в rustdoc; bytes — фактически принятые байты,
а не искусственный процент запуска/миграций. Снимок синхронизируется примерно
каждые 200 мс и в конце загрузки. Для SSE приложение само организует доставку
этих снимков; обязательного HTTP runtime/frontend в библиотеке нет.

После `available` вызовите `prepare(InstallRequest { check_id, version })`.
Подготовка повторно проверяет descriptor и совпадение version/size/hash с выбранным
релизом, резервирует место, скачивает, проверяет и preflight-ит бинарник, сохраняет
backup и durable recovery record. URL никогда не становится локальным именем.
Успех — `prepared`. Пока подготовка активна, сервер продолжает работать.

`install(operation_id).await` работает по подготовленным локальным байтам;
доступ к release source уже не нужен. Подпись/файлы проверяются повторно.
Только после готовности worker/supervisor меняет stage на `stopping` и запрашивает
shutdown. `cancel_prepared(id)` допустим только до этого момента и требует
нового check для повторной попытки. Повторный install уже stopping/completed/
rolled_back операции возвращает её snapshot без повторного переключения.

Межпроцессные file locks запрещают параллельные check/prepare/switch/recover.
Новая попытка с чужим/устаревшим ID или изменившимся релизом получает `Stale`;
активная операция — `Busy`. `Prepared` не разрешает другой check, даже когда
фоновая загрузка уже освободила operation lock.

## Graceful shutdown

В существующую shutdown future добавьте `manager.shutdown_requested()`:

```rust,ignore
tokio::select! {
    _ = application_signal() => {},
    _ = manager.shutdown_requested() => {},
}
// Axum: завершить with_graceful_shutdown и дождаться drain.
// Приложение: закрыть pool, flush/close собственных ресурсов с deadline.
manager.finish_shutdown()?;
// Немедленно вернуться из main.
```

Не вызывайте `finish_shutdown` при timeout, error или незавершённом drain.
Само закрытие pipe/авария родителя **не** разрешает переключение. Worker требует
clean-stop marker, EOF без дополнительных команд, завершение родителя с тем же
PID/starttime и свободный server lock. Supervisor требует успешный exit child,
проверенный control message и marker. Код библиотеки не вызывает SQLx pool.close
и не решает, завершены ли бизнес-операции.

## Готовность и данные

`Readiness::http(address, "/ready")` задаёт route; wildcard bind отображается на
loopback, удалённый адрес и port=0 отклоняются. Timeout по умолчанию 30 секунд,
survival — 300 мс. Health requests не используют proxy или redirects и ограничены
4 КиБ. Приложение проверяет свои ресурсы и только затем возвращает
`manager.ready_response()` (`status=ok`, version, уникальный update_instance).
Старый процесс, другой экземпляр и только открытый TCP-порт не проходят проверку.

`RequireExact` требует непустой fingerprint, совпадающий с candidate BuildInfo.
Для SQLx вычисляйте его из embedded migration versions/checksums, как в MockPort,
и включайте версию других форматов данных, если они есть. Не используйте только
номер приложения или вручную забываемый «schema v1» в production.
`ManualOnly` запрещает install, сохраняя checks. Библиотека не читает, не мигрирует,
не копирует и не откатывает бизнес-данные. Подписанный бинарник сам имеет права
приложения; издатель обязан сохранять семантическую совместимость.

## Сбой и ручное восстановление

При запуске/health failure новый child завершается SIGTERM, затем SIGKILL после
10 секунд. Backup переключается через hard link + rename, прежняя версия также
проходит readiness. Ошибка readiness после восстановления оставляет `failed`
и необходимость ручного старта; нельзя объявлять работоспособность по одному хешу.

Supervisor при следующем старте после прерванного switch/health автоматически
возвращает проверенный backup. Standalone сохраняет recovery_required и требует
остановить все процессы и вызвать тот же бинарник с `RECOVER_ARGUMENT`, либо
`runtime::recover(&config)`. Это офлайн операция; после неё запустите приложение
с исходными cwd/argv/environment. Она возвращает бинарник, а не данные.
Completed job нельзя повторно применить как recovery.

Новая ручная замена original launcher в supervisor intentionally выбирает новую
исходную версию. Обычный restart использует ранее обновлённую working copy без
сети. Для прикладных CLI-команд (`--version` и прочих) можно использовать
`runtime::active_executable(config)` и делегировать соответствующий запрос.
Build-info preflight всегда должен описывать именно запрошенный файл.

После подтверждённого успеха последний backup сохраняется. Прежние backups,
готовые файлы прерванных prepare и orphan worker copies могут занимать место:
автоматической retention policy в 0.1.0 нет. Удаляйте их только при остановленном
приложении после проверки отсутствия незавершённого recovery. Никогда не
удаляйте `.lock` файлы активного runtime: новый inode обошёл бы существующий lock.
