# standalone-updater

Независимая Rust-библиотека подписанных обновлений standalone-приложений.
Проверяет протокол v1 и, с feature `linux-runtime`, устанавливает Linux-бинарник
с graceful shutdown, проверкой готовности, откатом и восстановлением после аварии.

**0.1.0 — экспериментальная версия.** Публикация отключена через `publish = false`.
Публичный API и локальный формат состояния ещё могут меняться. Выпуск на crates.io
и объявление стабильности допускаются только после повторной интеграции в MockPort,
проверки лицензии и отдельного разбора безопасности. GitHub release и tag не созданы.

Для проекта с одним серверным бинарником начните с
[руководства по внедрению в Rust-приложение с SQLite и встроенным фронтендом](docs/rust-sqlite-app.md).

MSRV: **Rust 1.91**, edition 2024. `Cargo.lock` включён для разработки и испытаний.
Основные зависимости: reqwest 0.13, ed25519-dalek 3, sha2 0.11, base64 0.23,
serde, semver, Tokio. Версии зафиксированы lock-файлом; разрешение зависимостей
учитывает MSRV. На Unix libc используется для работы с приватными файлами.
Linux runtime дополнительно включает getrandom и процессные
возможности Tokio. Клиент не зависит от Axum, SQLx, MockPort или frontend.

## Подключение до публикации

```toml
[dependencies]
standalone-updater = { path = "../standalone-updater" }
# Для установки на Linux:
# standalone-updater = { path = "../standalone-updater", features = ["linux-runtime"] }
```

Для GitHub-зависимости используйте точный `rev`. Публичный репозиторий не требует
настройки Git-аутентификации потребителей. Cargo.lock потребителя также следует
хранить в репозитории.

## Только проверка

```rust,no_run
use standalone_updater::{UpdateClient, UpdateSource};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
// Издатель поставляет доверенную конфигурацию вместе с приложением.
let source: UpdateSource = serde_json::from_slice(&std::fs::read("source.json")?)?;
let client = UpdateClient::new(source, "0.5.0", "linux-x86_64")?;
let result = client.check().await?;
if let Some(update) = result.update {
    println!("Подписанный выпуск {}", update.metadata().version);
}
# Ok(()) }
```

Для канала достаточно одного адреса — `manifest_url`. По нему издатель размещает JSON
со списком выпусков и добавляет к каждому файлу для автоматического обновления поле
`signed_metadata`. Клиент выбирает выпуск для своей платформы, проверяет подпись Ed25519
закреплённым ключом, а при скачивании сверяет размер и SHA-256 файла.
На macOS и Windows доступны проверка и загрузка, на Linux также доступна установка.

При первом подключении подписанных обновлений сгенерируйте для приложения случайный UUID v4
и пару ключей Ed25519. В `source.json` запишите UUID в `product_id`, а публичную часть пары в формате JWK — в
`public_key`. Для приложения с подписанными выпусками сохраните его действующие UUID и ключ.
Ниже приведён пример с тестовыми значениями. [Как создать UUID и ключ подписи](docs/integration.md#как-создать-uuid-и-ключ-подписи)

```json
{
  "product_id": "44872c33-bef2-4c34-9290-29d762b6d965",
  "manifest_url": "https://updates.example.test/catalog.json",
  "public_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  },
  "allowed_download_origins": ["https://downloads.example.test"],
  "max_artifact_bytes": 268435456
}
```

Существующие конфигурации с отдельным `descriptor_url` продолжают получать подпись по
этому адресу. Для перехода сначала опубликуйте подписи в манифесте, затем уберите
`descriptor_url` из конфигурации приложения. [Формат манифеста и выбор выпуска](docs/integration.md#источник-и-identity)

## Пользовательские каналы

Приложение поставляет встроенный канал `default`. Через `ChannelStore` пользователь
может сохранить несколько именованных ссылок на манифесты и выбрать одну, даже когда
встроенный сервер недоступен. Выбор сохраняется после перезапуска. Каждая ветка ведёт
свой список выпусков. Все выпуски проверяются ключом издателя приложения.

В этом примере пользователь добавляет ветку `1.x`, проверяет её и возвращается на встроенный канал.

```sh
cargo run --example channels -- source.json ./update-settings add 1.x https://updates.example.test/1.x.json
cargo run --example channels -- source.json ./update-settings select 1.x
cargo run --example check -- source.json 1.4.0 linux-x86_64 ./update-settings
cargo run --example channels -- source.json ./update-settings select default
```

В Linux-сервисе тот же список доступен через `manager.channels()`. Следующая проверка
использует выбранный канал без перезапуска сервиса. [Подключение каналов в Rust](docs/integration.md#пользовательские-каналы)

## Linux runtime

Полный независимый потребитель — [examples/axum-service.rs](examples/axum-service.rs).
Axum подключён только как dev-dependency. В библиотеке нет HTTP-маршрутов или
административной авторизации.

1. Приложение формирует `BuildInfo` и отвечает на ранний build-info запрос.
2. Формирует `RuntimeConfig`: источник, реальный путь бинарника, приватный каталог
   обновлений, исходные argv/cwd, режим, политика данных и readiness route.
3. Вызывает `runtime::launch` до открытия БД и HTTP listener.
4. Получает `UpdateManager`, вызывает `check`, затем `prepare(InstallRequest)`.
5. Получает структурированный `status()`/`summary()` через polling или свой SSE.
6. Отдельно вызывает `install(operation_id)`. После подготовки источник больше
   не требуется. `cancel_prepared` позволяет отказаться до начала shutdown.
7. Ждёт `shutdown_requested()`, завершает запросы и закрывает свои ресурсы.
8. Вызывает `finish_shutdown()` и немедленно возвращается из main.

Readiness route возвращает `manager.ready_response()` только после прикладной
проверки готовности. Библиотека проверяет версию, случайный nonce экземпляра и
выживание процесса. Она не знает устройства бизнес-БД.

| Режим | Владение процессом и установкой |
| --- | --- |
| `Supervisor` | Стабильный PID исходного launcher; обновляется приватная рабочая копия. Исходный файл может быть root-owned/read-only. |
| `Standalone` | Временная копия того же бинарника становится worker, меняет принадлежащий приложению исполняемый файл и запускает новую версию. |
| `External` | Проверка доступна; подготовка и установка запрещены. Внешний менеджер или оператор устанавливает обычный файл. |

Нужен один распространяемый бинарник; отдельный агент, служба, updater-пакет,
`sudo` или изменение systemd unit не требуются. Для standalone staging и бинарник
должны находиться на одной файловой системе. Приложение само выбирает каталоги и
имя исполняемого файла. Ручная замена остаётся возможной.

## Гарантии и границы

Сохранены строгая проверка JWS, запрет downgrade, лимиты, потоковая загрузка,
проверка размера/SHA-256/ELF, file locks, защищённые локальные пути, атомарный
rename и fsync. Перед заменой необходим подтверждённый clean shutdown.
В постоянном задании нет URL, argv, environment, токенов или private key.

Откатывается **бинарник**, а не данные. `DataPolicy::RequireExact` требует
совпадения непустого fingerprint миграций/форматов. Даже при совпадении издатель
отвечает за семантическую совместимость. Для несовместимых изменений предусмотрен
`ManualOnly`; автоматический rollback данных не обещается.

Доверенная граница — владелец процесса и root. Нет защиты от издателя со
скомпрометированным ключом, root или другого процесса той же учётной записи.
Протокол v1 не гарантирует свежесть релиза, отзыв ключей или защиту от freeze.
Подробности: [модель угроз](docs/security.md).

## Проверки

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo doc --locked --all-features --no-deps
python3 scripts/e2e.py --native # Linux, одноразовые ключи/каталоги/процессы
python3 scripts/e2e.py          # macOS: тот же сценарий в Docker Linux
```

Повторное испытание готовых фикстур: `--run-only`. E2E собирает независимый
Axum-сервис версий 0.5.0, 0.6.0 и 0.7.0, а также варианты startup/health/data
failure. Подписи создаёт OpenSSL, проверяет Rust-библиотека. Production-данные
и ключи не используются. Отчёт создаётся в `target/validation/e2e.json`.

Документы: [контракт интеграции](docs/integration.md), [аудит переноса](docs/audit.md),
[миграция MockPort](docs/mockport-migration.md), [происхождение и лицензия](docs/provenance.md),
[ограничения и выпуск](docs/release-gate.md), [отчёт и проверки](docs/extraction-report.md).

Лицензия MIT. Код выделен из авторских модулей MockPort с сохранением механизмов
и тестов. Рабочая реализация MockPort в рамках этой задачи не изменялась.
