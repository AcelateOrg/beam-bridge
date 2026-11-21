# Ссылки beam://

Ссылка `beam://` целиком несёт профиль Beam: серверы, группы, брендинг, лимиты и
пресет маршрутизации. Её можно отдать из панели подписок, положить в кнопку на
сайте или кинуть в чат — Beam откроет окно «Добавить профиль?» и после
подтверждения добавит профиль.

## Формат

```
beam://import/<payload>
payload = base64url( gzip( JSON профиля ) )
```

- **JSON** — UTF-8, лучше без пробелов и переводов строк (короче ссылка).
- **gzip** — обычный gzip (RFC 1952), любой уровень. В нём есть CRC32: обрезанная
  ссылка даёт ошибку, а не битый профиль.
- **base64url** — алфавит `A–Z a–z 0–9 - _`, паддинг `=` можно не ставить.
  Обычный base64 (`+ /`) Beam тоже понимает, но в ссылках он ломается — не надо.

Другие формы, которые Beam принимает:

| Ссылка | Что делает |
| --- | --- |
| `beam://import/<payload>` | профиль из ссылки (основная форма) |
| `beam://import?data=<payload>` | то же самое |
| `beam://import?url=https://...` | добавить подписку по URL |

## Закодировать

**Node.js / TypeScript** (Remnawave и любые NestJS-сервисы):

```ts
import { gzipSync } from "node:zlib"

export function beamLink(profile: object): string {
    return "beam://import/" + gzipSync(JSON.stringify(profile), { level: 9 }).toString("base64url")
}
```

**Python:**

```python
import base64, gzip, json

def beam_link(profile: dict) -> str:
    raw = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode()
    return "beam://import/" + base64.urlsafe_b64encode(gzip.compress(raw, 9)).decode().rstrip("=")
```

**Go:**

```go
func BeamLink(profile any) (string, error) {
    raw, err := json.Marshal(profile)
    if err != nil {
        return "", err
    }
    var buf bytes.Buffer
    w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
    w.Write(raw)
    w.Close()
    return "beam://import/" + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}
```

Разные gzip-библиотеки дают разные байты, поэтому ссылки из Node, Python и Go не
совпадут посимвольно — это нормально. Проверяйте раскодированием (ниже).

## Проверить

В репозитории `beam-bridge` есть эталонная утилита — она читает ровно так же,
как Beam:

```
go run ./cmd/beamlink check   profile.json        # что Beam импортирует: группы и серверы
go run ./cmd/beamlink encode  profile.json        # JSON -> ссылка (+ размер)
go run ./cmd/beamlink decode  "beam://import/..." # ссылка -> JSON
```

`check` заранее показывает серверы, которые Beam не смог разобрать (их не будет в
списке), и предупреждает о значениях брендинга, которые будут отброшены.

## JSON профиля

Минимум — имя и серверы:

```json
{
  "name": "MyVPN",
  "links": ["vless://...#Германия", "vless://...#Нидерланды"]
}
```

Полный пример — [`examples/minimal.json`](examples/minimal.json).

### Поля

| Поле | Тип | | Что это |
| --- | --- | --- | --- |
| `name` | string | обязательно* | имя профиля в Beam. *Если есть `links`, по умолчанию берётся `provider`. |
| `provider` | string | | имя провайдера |
| `links` | string[] | обязательно** | серверы как share-ссылки и маркеры групп, см. ниже |
| `nodes` | object[] | обязательно** | серверы как готовые outbound'ы Xray (для тех, кто генерирует JSON сам) |
| `url` | string | | URL подписки: профиль будет сам обновляться с него |
| `updateIntervalHours` | number | | как часто обновлять с `url`, в часах |
| `branding` | object | | логотип, баннер, ссылки — см. ниже |
| `expiresAt` | number | | конец подписки, unix-время в секундах |
| `dataLimit` | number | | лимит трафика, байты |
| `dataUsed` | number | | израсходовано, байты |
| `proTunPreset` | object | | пресет маршрутизации ProTun — см. ниже |
| `proTunLocked` | bool | | запретить юзеру менять пресет |
| `version` | number | | `2`; можно не указывать |

** Нужны `links` или `nodes` (или оба). Профиль без единого сервера Beam не примет.

### `links`

Каждый элемент — одна строка, как в обычной подписке:

- share-ссылка сервера: `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`,
  `tuic://`, `wireguard://` и т.д. Имя сервера — фрагмент после `#`;
- маркер группы: строка вида `[Игровые]`, `【Игровые】` или `── Игровые ──`.
  Серверы ниже маркера попадают в эту группу. Иконка группы подбирается по
  названию (игровые, стриминг, быстрые, премиум, обход…).

Ссылки, которые Beam не смог разобрать, пропускаются. До 1000 элементов.

### `branding`

| Поле | Что это | Допустимо |
| --- | --- | --- |
| `iconUrl` | логотип профиля | `https://...` или `data:image/...;base64,...` |
| `bannerText` | текст баннера на карточке профиля | текст |
| `bannerUrl` | куда ведёт клик по баннеру | ссылка* |
| `bannerColor` | цвет баннера | `#rgb`, `#rrggbb`, `#rrggbbaa`, `rgb()/rgba()`, `hsl()/hsla()`, имя цвета |
| `bannerImage` | фон карточки профиля | только `https://...` (картинка в ссылке слишком тяжёлая) |
| `webPageUrl` | сайт провайдера | ссылка* |
| `supportUrl` | поддержка | ссылка* |
| `communityUrl` | канал / сообщество | ссылка* |

\* ссылка — `https://`, `http://`, `tg://` или `mailto:`.

Значения вне этих правил Beam молча отбрасывает (остальной профиль
импортируется).

**Логотип прямо в ссылке.** `iconUrl` может быть data-URI до 12 КБ целиком
(примерно 8 КБ картинки). Форматы: png, jpeg, webp, gif, svg. Оптимально — webp
64×64, это 1–3 КБ. Логотип по `https://` ссылку не утяжеляет, но тянется с
вашего сервера при каждом показе.

### `proTunPreset`

Граф маршрутизации в том же формате, что экспорт из редактора ProTun: `nodes`
(карточки) и `edges` (связи). Проще всего собрать пресет в Beam, экспортировать и
вставить как есть.

Карточка: `{ "id", "kind", "position": {"x","y"}, "items": [...] }`. Виды
(`kind`): условия — `apps`, `domains`, `ip_ranges`, `geoip`, `geosite`, `ports`,
`protocols`, `network`; назначения — `vpn`, `direct`, `block`; связь
`{ "id", "source", "target" }` ведёт от условия к назначению.

## Подписка в этом же формате

По `url` подписки можно отдавать тот же профиль: тело ответа — gzip от JSON
(без base64), или `BEAM` + байт `0x02` + gzip. Тогда при обновлении приедут и
серверы, и брендинг, и пресет. Лимиты и срок можно отдавать заголовком
`subscription-userinfo`, интервал — `profile-update-interval`, как в обычных
подписках.

Обычные подписки (список ссылок, base64, Xray JSON) Beam тоже понимает, так что
связка «`beam://` с брендингом и `url` → обычная подписка» тоже работает.

## Брендинг через HTTP-заголовки (Remnawave и другие панели)

Если подписка — обычный список ссылок, брендинг можно отдать заголовками
ответа. Beam читает их так же, как строки `#key: value` в теле:

| Заголовок | Что задаёт |
| --- | --- |
| `profile-title` | название профиля (можно `base64:...`) |
| `announce` | текст баннера (можно `base64:...`) |
| `support-url`, `profile-web-page-url`, `community-url` | кнопки поддержки, сайта, канала |
| `icon-url` | логотип (только `https`) |
| `banner-color`, `banner-image`, `banner-url` | цвет, фон и ссылка баннера |
| `Beam-Branding` | весь блок `branding` разом: base64 от JSON |

Приоритет: `branding` из самого профиля → `Beam-Branding` → отдельные заголовки.
Всё проходит те же проверки, что и брендинг в ссылке. Inline-логотип
(`data:`) в заголовок не кладите — прокси режут длинные заголовки, используйте
`https`-URL.

В Remnawave название, анонс и ссылки задаются в Subscription → Settings, а
логотип и цвета — правилом Response Rules для Beam:

```json
{
  "name": "Beam",
  "enabled": true,
  "operator": "AND",
  "conditions": [{ "headerName": "user-agent", "operator": "STARTS_WITH", "value": "BEAM/", "caseSensitive": false }],
  "responseType": "XRAY_BASE64",
  "responseModifications": {
    "headers": [
      { "key": "icon-url", "value": "https://example.com/logo.png" },
      { "key": "banner-color", "value": "#6C5CE7" }
    ]
  }
}
```

Кнопка на странице подписки (Subpage Builder): `"urlScheme": "beam://import/"`.

## Группы и карточки серверов

**Разделители.** Фейковый сервер с именем-разделителем Beam превращает в группу, а
все серверы ниже — в её содержимое. Узнаются: `⬇️ —— ДОМАШНИЕ —— ⬇️`, `━━ Игры ━━`,
`== VIP ==`, `[Игровые]`, `【VIP】`, `⬇️ Домашние ⬇️`. Имя чистится (`Домашние`), первое
эмодзи кроме стрелок становится иконкой группы (`🎮 —— Игры ——`, флаги тоже).
Линия без текста (`—————`) просто скрывается. Другие клиенты по-прежнему видят разделитель.

**Параметры хоста** — query-параметры share-ссылки, другие клиенты их игнорируют:

| Параметр | Что делает |
| --- | --- |
| `beam-group` | группа сервера (`🎮 Игровые`), до 40 символов; список `a,b` → первая |
| `beam-desc` | подпись под именем вместо протокола, до 60 |
| `beam-badge` | чип справа (`NEW`, `🔥`), до 16 |
| `beam-separator=1` | этот хост — разделитель, даже если имя не похоже |
| `beam-collapsed=1` | группа свёрнута по умолчанию |

Описание сервера в формате Happ (`#Имя?serverDescription=<base64>`) Beam тоже понимает.

**Remnawave:** хост → Опции → Маппер → Base64:

```json
[
  { "op": "set", "to": "beam-desc", "value": "Для игр · 10 Гбит" },
  { "op": "set", "to": "beam-badge", "value": "NEW" },
  { "op": "copy", "from": "$host.metadata.tags", "to": "beam-group" }
]
```

`copy` из `$host.clientOverrides.serverDescription` в `beam-desc` переносит «Описание
сервера» (Remnawave сам отдаёт его только Happ/FlClashX).

**Заголовки профиля:** `beam-node-subtitle: none` — убрать «VLESS / REALITY» со всех
карточек (описание остаётся); `beam-groups-collapsed: true` — все группы свёрнуты.

Проверить результат: `go run ./cmd/beamlink check profile.json` покажет группы,
подписи и бейджи.

## Ограничения длины

| Где | Сколько влезает |
| --- | --- |
| QR-код | ~2 КБ ссылки, читается уверенно до ~1.5 КБ |
| сообщение Telegram | 4096 символов |
| запуск из браузера / ОС | ~32 000 символов (командная строка Windows) |
| Beam | 256 КБ payload |

Для ориентира: профиль из трёх серверов с брендингом по `https` — около 600
символов. Каждый следующий vless-сервер добавляет примерно 100–150.

Если ссылка выходит длиннее, чем нужно для канала, отдавайте
`beam://import?url=<подписка>`.

## Безопасность

Ссылка не шифруется: у кого ссылка — у того серверы, как с `vless://`. Beam
никогда не импортирует профиль без подтверждения пользователя.
