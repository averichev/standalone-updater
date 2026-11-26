# Контракт приложения

Пошаговый пример для сервиса с SQLite, встроенным интерфейсом и подписанными релизами приведён в
[руководстве по внедрению в Rust-приложение](rust-sqlite-app.md).

## Как создать UUID и ключ подписи

При первом подключении подписанных обновлений вы сами один раз генерируете для приложения
**случайный UUID v4 и пару ключей Ed25519**. UUID становится постоянным `product_id`.
Публичную часть пары экспортируйте в формате JWK для поля `public_key`. Эти два значения
общие для всех версий и каналов продукта. Если у приложения уже есть подписанные выпуски,
используйте действующие UUID и ключ подписи.

Чтобы создать оба значения с нуля, выполните команду на машине подписания в приватном
каталоге вне репозитория. Пример использует Node.js и оболочку `sh`.

```sh
node --input-type=module <<'JS'
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
writeFileSync('update-signing.pem', pem, { flag: 'wx', mode: 0o600 });

console.log(JSON.stringify({
  product_id: randomUUID(),
  public_key: publicKey.export({ format: 'jwk' }),
}, null, 2));
JS
```

Скопируйте оба поля из вывода в доверенную конфигурацию приложения. Тот же UUID укажите
в подписываемом поле `application_id` и, при использовании Linux runtime, в `BuildInfo.product_id`.
Файл `update-signing.pem` содержит закрытый ключ. Храните его на машине подписания или
в хранилище секретов CI и используйте для подписи метаданных каждого выпуска.

## Источник и identity

URL канала — полный адрес манифеста (`manifest_url`). Его можно раздавать как статический
JSON-файл по HTTPS. При каждой проверке клиент делает один GET по указанному адресу
и сравнивает версии локально. В Rust такой источник можно создать через
`UpdateSource::from_manifest`.

Пример манифеста для одного выпуска. В `signed_metadata` подставьте полную строку
JWS Compact, которой издатель подписал метаданные указанного файла.

```json
{
  "schema_version": 2,
  "releases": [{
    "version": "1.4.1",
    "notes": "Добавлен экспорт отчёта.",
    "artifacts": [{
      "purpose": "executable",
      "target": "linux-x86_64",
      "download_url": "https://downloads.example.test/myapp-1.4.1-linux-x86_64",
      "signed_metadata": "<JWS Compact этого файла>"
    }]
  }]
}
```

Клиент ищет самую новую стабильную версию выше установленной среди записей с подписью,
ролью `executable` и своим `target`. Он учитывает и `releases`, и запись для своей
платформы в `latest_by_type.executable`. Подпись v1 связывает UUID приложения, версию,
ОС, архитектуру, размер и SHA-256. Если у выбранного выпуска неверная подпись или адрес
файла не разрешён, `check().await` возвращает ошибку. Запись без `signed_metadata` может
дать ссылку для ручного скачивания. При отсутствии подходящего подписанного выпуска
`CheckResult.update` равен `None`. Если сам манифест недоступен или повреждён,
проверка завершается ошибкой.

В доверенной конфигурации приложения задаются встроенный источник, ключ издателя,
разрешённые origin загрузки и предел размера. Пользовательский канал задаёт только URL манифеста.
JWS требует удостоверить происхождение ключа для проверки подписи.
[RFC 7515, §10.3](https://www.rfc-editor.org/rfc/rfc7515.html#section-10.3)

`UpdateClient::new(source, current_version, protocol_target)` не выполняет сеть.
`VerifiedUpdate` закрыт для самостоятельного конструирования/десериализации.
`download` ещё раз проверяет его своим trust anchor и пишет только в явно
переданный вызывающим writable regular file. Вызывающий отвечает за изоляцию
этого файла и удаление partial при ошибке. Linux runtime делает это сам.

Для Windows/macOS доступны проверка и загрузка с проверкой размера/хеша.
Linux-кандидаты дополнительно проходят ELF64 validation. Для установки нужен
feature `linux-runtime` и сборка под Linux; на других ОС `runtime` отсутствует.

### Совместимость с отдельным дескриптором

Если в конфигурации указан непустой `descriptor_url`, клиент по-прежнему запрашивает
его параллельно с манифестом. Адрес дескриптора задаётся без query. Клиент подставляет
`{target}` при наличии и добавляет `current_version`. Дескриптор с HTTP 200 определяет
кандидата на установку, HTTP 204 означает отсутствие обновления, а ошибка запроса или
подписи прерывает проверку. Манифест в этом режиме даёт только описание и ручные ссылки.
Даже при его недоступности клиент может принять корректно подписанный дескриптор.

Для перехода добавьте `signed_metadata` к файлам в манифесте, затем уберите
`descriptor_url` в новых клиентах. Старым клиентам по-прежнему нужен адрес дескриптора.

### Пользовательские каналы

Встройте исходный `UpdateSource` в приложение. Для клиента или монитора откройте
`ChannelStore` в постоянном приватном каталоге приложения. Например, в проекте,
где `source.json` лежит рядом с модулем Rust, его можно подключить через `include_str!`.

```rust,no_run
use standalone_updater::{ChannelStore, CheckResult, UpdateClient, UpdateSource};
use std::path::Path;

async fn check(settings_dir: &Path) -> Result<CheckResult, Box<dyn std::error::Error>> {
    let default: UpdateSource = serde_json::from_str(include_str!("source.json"))?;
    let channels = ChannelStore::open(settings_dir, default)?;
    let client = UpdateClient::new(channels.active_source()?, "1.4.0", "linux-x86_64")?;
    Ok(client.check().await?)
}
```

В обработчике добавления вызовите `channels.add("1.x", manifest_url)?`. Список для
экрана настроек возвращает `channels.list()?` с именем, URL и признаком `selected`.
Команда `channels.select("1.x")?` сохраняет выбор. После этого создайте клиент или
монитор с новым `active_source()?`. Чтобы вернуться, вызовите `select(DEFAULT_CHANNEL)`.
Удалить неактивную пользовательскую ветку можно через `remove("1.x")`.
Встроенный канал всегда берётся из текущей сборки. Ссылки пользователя и выбор
записываются в `channels.json` и привязаны к `product_id`.

Для Linux runtime передайте встроенный источник в `RuntimeConfig.source` и используйте
`manager.channels()`. Настройки сохраняются в `updates_directory`. Методы `check`
и `prepare` фиксируют источник при старте операции. Если после проверки выбран другой
манифест, старый `check_id` получает `Stale`. Уже подготовленный файл привязан к своей
операции до `install` или `cancel_prepared`. При переходе со старого формата
состояния повторите проверку доступного выпуска, чтобы привязать её к манифесту.

Клиент запрашивает выбранный манифест и возвращает ошибку при его недоступности.
Возврат на встроенный канал выполняется явным выбором. Для пользовательской ветки
подпись берётся из `signed_metadata` файла в этом манифесте. Смена пути сохраняет
ключ, UUID, разрешённые origin файлов и лимит размера приложения. Если файлы ветки
раздаются с резервного хоста, добавьте его в `allowed_download_origins` встроенного источника.
В протоколе v1 подпись
удостоверяет выпуск, а состав ветки определяется её манифестом.

На всех ветках версия сравнивается с уже установленной. Например, сборка `1.4.0`
может получить `1.4.1` из ветки `1.x`, даже если во встроенном канале вышла `2.0.0`.
После установки `2.0.0` переход на `1.x` сохранит установленную версию, пока
в выбранном манифесте нет более нового стабильного выпуска.

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
Подготовка повторно запрашивает источник, проверяет подпись и совпадение version/size/hash с выбранным
релизом, резервирует место, скачивает, проверяет и preflight-ит бинарник, сохраняет
backup и durable recovery record. URL никогда не становится локальным именем.
Успех — `prepared`. Пока подготовка активна, сервер продолжает работать.

`install(operation_id).await` возвращает начальный snapshot и запускает фоновую
установку по подготовленным локальным байтам; доступ к release source уже не нужен.
Обрыв запроса не отменяет handoff. Ошибки проверки ID/state возвращаются сразу,
ошибки установки отражаются в status. Подпись/файлы проверяются повторно.
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

`manager.manual_release()` возвращает последний manual-download hint с URL
только из памяти для прикладного UI. Он не разрешает автоматическую установку.
URL не записывается в journal/status; после перезапуска нужна новая проверка.

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

## Проверка без installation runtime

`UpdateMonitor::new(source, version, target)` выполняет фоновые проверки на любой
поддерживаемой платформе. Установка отсутствует. Для сохранения последней проверки
после перезапуска вызовите `.with_cache(&private_directory)`. `checks.json` привязан
к источнику, его политике доверия, версии и платформе, содержит только redacted OperationStatus и никогда
не принимается как installation/recovery journal. Проверка, прерванная до
сохранения результата, становится failed без recovery_required. URL ручного
скачивания остаётся только в памяти; после restart нужна новая проверка.
Для кэша старого формата без привязки к манифесту выполните проверку заново.
Без with_cache файловых операций нет. Небезопасные права и symlink отклоняются;
приложение может явно продолжить работу с монитором без кэша при ошибке диска.
