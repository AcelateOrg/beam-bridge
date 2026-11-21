# Внутренний формат outbound ноды

`BeamNode.Outbound` хранится в sing-box-подобном виде: его читает редактор нод,
а `core/profile/xray_outbound.go` переводит в Xray при сборке конфига. Xray JSON
из подписки переводится в этот формат `core/infrastructure/subscription/xray_array.go`.
Перевод туда и обратно без потерь — это проверяет `core/profile/xray_roundtrip_test.go`.

## Общие поля

| Ключ | Xray |
|---|---|
| `type` | `protocol` (`direct` = `freedom`, только как хоп цепочки) |
| `server`, `server_port` | адрес и порт сервера (vnext / servers / peers) |
| `tag` | имя ноды при импорте; в конфиге тег = ID ноды |
| `tls{}` | `streamSettings.security` = tls / reality |
| `transport{}` | `streamSettings.network` и `<network>Settings` |
| `multiplex{enabled, concurrency, xudp_concurrency, xudp_proxy_udp443}` | `mux` |
| `sockopt{}` | `streamSettings.sockopt` как есть, кроме `dialerProxy` |
| `detour{}` | следующий хоп цепочки: вложенный outbound в этом же формате (`dialerProxy` / `proxySettings.tag`) |
| `beam{fragment, mux}` | настройки BEAM для ноды, в Xray не уходят |

## Протоколы

- **vless**: `uuid`, `flow`, `encryption`
- **vmess**: `uuid`, `alter_id`, `security`
- **trojan**: `password`, `flow`
- **shadowsocks**: `method`, `password`; `plugin`, `plugin_opts` сохраняются, но Xray их не поддерживает, и такая нода не собирается
- **hysteria2**: `password`, `up` / `down` (или `up_mbps` / `down_mbps`), `hop_ports`, `hop_interval`, `obfs{type: salamander, password}` → `finalmask.udp`
- **socks**, **http**: `username`, `password`, у http ещё `headers`
- **wireguard**: `private_key`, `local_address[]`, `peer_public_key`, `pre_shared_key`, `allowed_ips[]`, `keep_alive`, `mtu`, `reserved[]`; несколько peers — в `xray_settings.peers`
- **direct** (хоп): `domain_strategy`, `fragment{packets, length, interval, max_split}`, `noises[{type, packet, delay, apply_to}]`

## TLS

`enabled`, `server_name`, `insecure`, `alpn[]`, `utls{fingerprint}`, `min_version`,
`max_version`, `cipher_suites`, `curve_preferences`, `pinned_peer_cert_sha256`,
`verify_peer_cert_by_name`, `disable_system_root`, `enable_session_resumption`,
`ech{config_list, force_query}`.

REALITY: `reality{enabled, public_key, short_id, spider_x, mldsa65_verify}`.

## Транспорты

| `transport.type` | Поля |
|---|---|
| `ws` | `path`, `headers{Host}`, `heartbeat_period` |
| `grpc` | `service_name`, `authority`, `multi_mode`, `idle_timeout`, `health_check_timeout`, `permit_without_stream`, `initial_windows_size`, `user_agent` |
| `httpupgrade` | `path`, `host`, `headers` |
| `xhttp` | `path`, `host`, `mode`, `headers`, `extra{}` |
| `kcp` | `mtu`, `tti`, `uplink_capacity`, `downlink_capacity`, `congestion`, `read_buffer_size`, `write_buffer_size`, `header_type`, `seed` |
| `raw` | `header{}` (HTTP-маскировка tcp) |

## Остатки без потерь

Всё, что выше не названо, переносится как есть, ключами Xray:

| Ключ | Куда уходит |
|---|---|
| `tls.xray` | `tlsSettings` |
| `tls.reality.xray` | `realitySettings` |
| `transport.xray` | `<network>Settings` |
| `xray_stream` | `streamSettings` (например `finalmask`) |
| `xray_settings` | `settings` протокола |
| `xray_user` | пользователь в vnext / servers |
| `xray_outbound` | сам outbound (`sendThrough`, `targetStrategy`, ...) |
| `hysteria_xray` | `hysteriaSettings` |

Именованный ключ всегда важнее остатка с тем же смыслом.
