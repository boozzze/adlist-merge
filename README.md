# adlist-merge

Ежедневная сборка одного дедуплицированного списка доменов для AdGuard Home.

## Что внутри

`build.py` скачивает источники, оставляет только правила, которые AGH применяет на DNS-уровне
(`||domain^`, `@@||domain^`, hosts-строки), выкидывает косметику, path-правила, regex и wildcard-правила,
убирает дубли и пересечения между списками.

Публикуются два файла:

| Файл | Что это | Правил | Размер | Для кого |
|---|---|---:|---:|---|
| `fit.txt` | HaGeZi Pro + RU AdList + AWAvenue + Win/Office + Smart-TV | ~218 000 | ~5 МБ | роутеры на 256–512 МБ RAM |
| `full.txt` | всё: + AdGuard DNS filter, 1Hosts Lite, ShadowWhisperer Malware | ~406 000 | ~9.7 МБ | нормальное железо |

Ссылки (после первого запуска workflow):

```
https://github.com/<USER>/<REPO>/releases/latest/download/fit.txt
https://github.com/<USER>/<REPO>/releases/latest/download/full.txt
```

## Важно про память

`full.txt` на роутере с 402 МБ RAM (Xiaomi AX3600) **не поедет**: ~406k правил дают ~150 МБ RSS
и ~250 МБ на пике пересборки фильтров, что с учётом ~120 МБ невыгружаемого slab и sing-box
гарантирует OOM. Для такого железа — только `fit.txt`.

## Источники

- HaGeZi Pro — `filter_48.txt`
- AdGuard DNS filter — `filter_1.txt`
- 1Hosts Lite — `filter_24.txt`
- ShadowWhisperer Malware — `filter_42.txt`
- AWAvenue Ads Rule — `filter_53.txt`
- HaGeZi Windows/Office — `filter_63.txt`
- Smart-TV — `filter_7.txt`
- RU AdList: `adservers.txt`, `general_block.txt`, `thirdparty.txt`, исключения из `whitelist.txt`

Исключения (`@@`) берутся только из RU AdList: `@@` из разных списков конфликтуют и снимают
блокировки друг друга.

## Как работает

`.github/workflows/build.yml`:

- запуск по расписанию `0 3 * * *` UTC и вручную (`workflow_dispatch`);
- `python build.py` собирает `out/full.txt` и `out/fit.txt`;
- файлы заливаются в релиз с тегом `data` (`--clobber`), поэтому история репозитория не растёт.

AdGuard Home сам обновляет список раз в сутки (`filters_update_interval`), отдельный cron на роутере не нужен.

## Локальный запуск

```bash
python build.py
```
