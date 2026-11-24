# Статус 0.1.0 и ограничения выпуска

Cargo package подготовлен как 0.1.0, API экспериментален. `publish = false`
предотвращает случайный cargo publish. GitHub repository разрешено открыть
публично явным последующим указанием владельца в этой задаче. Публичный GitHub
не означает стабильный API или опубликованный crates.io package.

До tag/release/crates.io необходимо:

1. Повторно интегрировать crate в MockPort по mockport-migration.md и пройти
   настоящие прикладные E2E. Текущая работа использует независимый consumer.
2. Провести отдельный review diff, модели угроз, MIT provenance и dependency
   advisories, зафиксировать оставшиеся допущения.
3. Испытать целевые deployment/filesystem/platform combinations. Linux GNU/musl
   и x86_64/aarch64 должны иметь явную матрицу сборок, а не только host test.
4. Проверить package contents и rustdoc, назначить неизменный Git rev/tag, явно
   снять publish=false только в отдельном одобренном изменении.

Ограничения 0.1.0:

- Установка только Linux ELF64 x86_64/aarch64; клиент поддерживает все шесть
  target протокола v1. Windows/macOS не получают installation runtime.
- Readiness — заданный приложением fixed loopback HTTP route с nonce/version.
  Иные transports/callback plugin frameworks намеренно не добавлены.
- Нет data snapshots, migration execution, автоматической ротации/revocation,
  TUF/freshness, sudo/systemd integration, external-manager delegation или archive
  extraction. В External установка полностью принадлежит оператору/менеджеру.
- Нет переносимости незавершённого updater journal между старым MockPort и crate,
  гарантии стабильности локального journal/API или автоматической retention policy.
- Данные приложения неизменны для updater; безопасность действий запущенного
  подписанного приложения остаётся обязанностью издателя.

Наличие lock-файла обеспечивает повторяемое разрешение зависимостей, но не
обещает побайтно воспроизводимые release-бинарники на разных toolchain/системах.
