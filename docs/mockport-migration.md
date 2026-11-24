# Последующая обратная интеграция в MockPort

Эта задача **не меняет MockPort**. Следующая интеграция должна быть отдельной
работой с повторным прогоном его настоящего self-update E2E, включая SQLite,
сессии, CSRF, browser restart, контейнер/PID 1 и read-only deployment.

1. Подключить crate по точному Git rev, пока не пройдён release gate. Сохранить
   текущий product UUID, закреплённый public JWK, endpoint URL/allowlist и версию.
   Не генерировать второй счётчик версии и не менять wire-протокол «Релизов».
2. Сформировать `BuildInfo` из `mockport::VERSION`, BUILD_TARGET и существующего
   `migration_fingerprint()` по SQLx versions/checksums. Добавить идентичность
   иных изменяемых форматов к fingerprint. Сохранить RequireExact.
3. Ранний `--build-info` MockPort оставить совместимым для прежних CLI-потребителей;
   добавить обработку зарезервированного BuildInfo/worker/server/recover контракта
   crate перед конфигурацией БД. При необходимости адаптировать старый internal
   `--update-*` CLI на переходный период.
4. Собрать `RuntimeConfig` из действующей UpdateConfig, executable/cwd/argv,
   `<MOCKPORT_DATA_DIR>/self-update` или явно выбранного **нового** updater dir,
   существующего режима и fixed HTTP bind. Сопоставить automatic → Supervisor,
   standalone → Standalone, external → External. Root-owned launcher не должен
   превращаться в причину отключения Supervisor.
5. В `/health` оставить реальную проверку `SELECT 1`/готовности SQLx и возвращать
   ReadyResponse только после успеха. Route остаётся MockPort transport-кодом.
6. Сохранить существующую admin/session/CSRF/Origin boundary. Transport adapter
   принимает только check_id/version/operation_id, переводит typed errors в
   привычные HTTP коды, публикует status/summary через polling/SSE. При прежнем
   UX «установить» приложение может последовательно prepare → install, но не
   посылать shutdown до готовности worker.
7. В существующий graceful shutdown добавить manager.shutdown_requested;
   сохранить drain 30 с и pool.close deadline 15 с. Только после обоих вызвать
   finish_shutdown и вернуться из main. Прежние browser suppression/env policies
   остаются у MockPort; crate не открывает браузер.
8. Делегировать обычные CLI-команды рабочей версии через active_executable,
   чтобы version/build-info приложения не расходились с работающей версией.
9. Заменить application/updates orchestration и infrastructure worker/supervisor
   адаптерами после проверки parity; перенести/удалить дублирующий self_update
   только когда тесты проходят. Бизнес-transport/frontend не переписывать.

## Совместимость состояния

Wire v1 сохранён, но локальный `job.json`, BuildInfo и private runtime layout
нового crate **не** объявлены совместимыми с файлами MockPort. Нельзя слепо
десериализовать старое задание как новое: изменились поля compatibility, product,
candidate hash и передача signed context без URL/argv.

Перед переходом остановить все процессы обновления, проверить отсутствие
recovery_required/active jobs, закончить или восстановить старую операцию старым
бинарником. Затем использовать новый private updater subdirectory либо явно
написанный и проверенный одноразовый мигратор **только локального updater state**.
Пользовательские БД/config/session store не переименовывать и не пересоздавать.
Незавершённую операцию между реализациями не переносить.

## Обязательная проверка перед выпуском

- Подписанный переход двух настоящих сборок, повторный update, offline restart.
- SQLite/WAL, users/sessions/CSRF/config/cwd/env сохраняются; pool действительно
  закрывается до marker. Неизменность migration fingerprint проверяется preflight.
- Ошибки запуска/health, несовместимая migration, SIGKILL download/worker/supervisor,
  автоматический и ручной recovery, конкурирующие admin requests.
- Root-owned launcher, непривилегированный UID, PID 1/read-only root filesystem,
  штатный SIGTERM, реальный ENOSPC, forbidden standalone ownership/mount.
- Прежний UI корректно отображает prepared, reconnect, completed/rolled_back и
  recovery_required; не выводит URL tokens/argv/environment в diagnostics.

Лишь после этого можно решать вопрос tag/release 0.1.0 и публикации crates.io.
