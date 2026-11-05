# Исследование WFP и референсов (P2, предварительное)

Дата: 4 ноября 2026 года. Исследование выполнено чтением документации и закреплённых исходников; реальные фильтры, захват пакетов и перезагрузка не выполнялись. Поэтому G1 касается только лабораторного прототипа, а не доказанной защиты.

## Проверенные механизмы

| Вопрос | Что установлено | Что остаётся проверить на стенде |
| --- | --- | --- |
| Слои | `ALE_AUTH_CONNECT_V4/V6` и `ALE_AUTH_RECV_ACCEPT_V4/V6` поддерживают `ALE_APP_ID`, `FLAGS` и `IP_NEXTHOP_INTERFACE`. Последний имеет тип `FWP_UINT64` и означает интерфейс выхода после выбора next hop. [Условия по слоям](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer), [идентификаторы](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-). | Точные runtime metadata и классификация IPv4/IPv6 на целевой Windows. |
| AppID | `FwpmGetAppIdFromFileName0` возвращает `FWP_BYTE_BLOB*`, освобождать через `FwpmFreeMemory0`. [API](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0). | Упакованный Claude Desktop, launcher, помощники и смена пути. |
| Арбитраж | Внутри sublayer порядок по весу; обычный permit мягкий, filter block по умолчанию жёсткий. Чужой hard permit может помешать нашему block; максимальный вес одного sublayer не является всеобщим приоритетом. [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration). | Чужие providers и hard permit на стенде, фактический результат на CONNECT/RECV_ACCEPT. |
| Reauthorization | ALE flow содержит пакеты обоих направлений; повторная авторизация возможна при смене политики и интерфейса. На inbound ответе к outbound flow `IP_NEXTHOP_INTERFACE` может быть `FWP_EMPTY`; Microsoft прямо требует второй фильтр либо иной доступный interface condition. [ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization), [условия интерфейса](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers). | Смена исходящего маршрута у уже разрешённых TCP, connected UDP, SendTo; нельзя выводить безопасность из одной классификации. |
| Persistence | Явная WFP-транзакция атомарна для объектов одного engine handle; незавершённая транзакция прерывается при закрытии сессии. `PERSISTENT` и `BOOTTIME` несовместимы в одном фильтре. [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management), [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0). | Активность после reboot и до BFE; DISABLED flags; восстановление после crash. |
| serviceName | Документ [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management) утверждает, что provider без serviceName восстанавливается при старте BFE. Страницы [FWPM_PROVIDER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0) и [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0) в описании `DISABLED` противоречат этому. | Проверить flags и передачу до ручного запуска guard после reboot. Не связывать provider с чужой службой. |
| DNS | DNS часто выполняет системный resolver, поэтому AppID одного EXE не доказывает покрытие DNS. Это отмечено и в [Mullvad split tunneling](https://github.com/mullvad/mullvadvpn-app/blob/107f699278210f1d2dc39aaf5774537502e6e50b/docs/split-tunneling.md). | Уникальные имена, системный resolver, локальный proxy и реальные пакеты. |

### Уточнение кандидата политики

Пара `permit AppID + VPN next-hop` с весом 200 и `block AppID` с весом 100 на CONNECT-слоях остаётся только кандидатом для новых outbound классификаций. #вывод: при reauthorization inbound ответа `next-hop` бывает пустым, поэтому permit не совпадёт и block может разорвать допустимый поток. Это безопаснее утечки, но несовместимо с требованием нормальной работы. Второй permit по arrival interface без достаточных условий может открыть обход; добавлять его до анализа пакетных следов нельзя.

RECV_ACCEPT нельзя считать копией CONNECT: начальная авторизация входящего потока происходит там, и ответы такого потока тоже исходят. Строгий прототип должен блокировать входящие flow выбранного AppID, пока не доказано ограничение их ответов. Loopback по умолчанию запрещён. В случае нераспознанного LUID оставлять только блокировку, не выбирать интерфейс по alias.

Ни один из прочитанных источников не доказывает отсутствие первого прямого пакета у открытого потока при смене маршрута. G1 разрешает лишь подготовку прототипа для изолированного стенда. G3 остаётся закрытым.

## Код и лицензии референсов

SHA получены `git ls-remote ... HEAD` 4 ноября 2026 года. Файлы прочитаны в закреплённых ревизиях; код сторонних проектов в приложение не переносился.

| Проект, SHA, лицензия | Проверенный материал и вывод |
| --- | --- |
| [tailscale/wf](https://github.com/tailscale/wf/tree/6fbb0a674ee67f6c9b99eb7ce8a4330bb0145ec9) `6fbb0a6`, BSD-3-Clause | `firewall.go`, `compose.go`, `syscall.go`, `go.mod`: AppID, persistent, provider, sublayer, rules доступны; syscalls Begin/Commit/Abort есть, но публичного метода транзакции на `Session` нет. Использовать несколько публичных вызовов как атомарную операцию нельзя. |
| [Mullvad](https://github.com/mullvad/mullvadvpn-app/tree/107f699278210f1d2dc39aaf5774537502e6e50b) `107f699`, GPL-3.0 | `docs/security.md`, `docs/split-tunneling.md`: атомарные переходы, persistent blocking при выходе службы и отдельная проблема системного DNS. Это политика всего VPN, не доказательство per-EXE защиты. |
| [WireGuard for Windows](https://github.com/WireGuard/wireguard-windows/tree/6ece77bc487c8aa697e3c092197621c4f3e5ccb8) `6ece77b`, MIT | `tunnel/firewall/rules.go`, `blocker.go`: прямой WFP API, AppID сервиса, LUID и отдельные правила DNS. Схема защищает собственный туннель и не переносится механически на Claude. |
| [Amnezia client](https://github.com/amnezia-vpn/amnezia-client/tree/ac175c8a8147cfe56f98c8372ec17ea2ba00bb02) `ac175c8`, GPL-3.0 | `appSplitTunnelingController.cpp`: пользовательские режимы маршрутизации по приложениям; не подтверждает неизменность GUID/LUID или перехват DNS. |
| [AmneziaWG Windows](https://github.com/amnezia-vpn/amneziawg-windows-client/tree/800416d673d83ed90ede02ca2ccd3683fe107d12) `800416d`, MIT | README: Windows-клиент с Wintun. Данный backend нельзя приписывать всем профилям Amnezia без диагностики. |
| [gruskry/claude-vpn-guard](https://github.com/gruskry/claude-vpn-guard/tree/806d9489c8743363cbf64adf8f6284577adf13f8) `806d948`, лицензия не указана в GitHub API | `setup-firewall.ps1`: правила Windows Firewall по интерфейсам и восстановление DNS. Не доказательство WFP next-hop/re-authorization. |
| [tianhuojeff/claude-vpn-guard](https://github.com/tianhuojeff/claude-vpn-guard/tree/860452a04bd9d14416d18094ef6883f7922d0e0b) `860452a`, MIT | `src/Core/Wfp.cs`: persistent provider, транзакции, CONNECT правила и локальный proxy. Из просмотра кода не следует доказательство открытых потоков или inbound flow. |
| [ef1m03/kordon](https://github.com/ef1m03/kordon/tree/c1fa85d73b16a480a0063386f76321806c6d5484) `c1fa85d`, GitHub API: NOASSERTION | `README.en.md`: мониторинг IP и приостановка процессов; автор прямо признаёт окно между сменой сети и приостановкой. Это не замена WFP fail-closed. |
| [simplewall](https://github.com/henrypp/simplewall/tree/24bbd2ceb7daee9ef308e0b406be5eb039cb30a1) `24bbd2c`, GPL-3.0 | `src/wfp.c`: собственное управление WFP с более широкой областью и сложным жизненным циклом. Код не переносился. |

## G1

Решение: **условный проход для лабораторного прототипа**, без утверждения безопасности. Реализация должна явно выводить `UNVERIFIED`, не применять правила на host, не тестировать Claude. Перед G2 обязательны dry-run, probe, точный план WFP-объектов и работающее аварийное удаление. Если лаборатория обнаружит прямой пакет открытого потока либо непреодолимый hard permit, выбранный ALE-вариант прекращается; безопасная альтернатива потребует изолированной сетевой среды приложения или пересмотра требований.
