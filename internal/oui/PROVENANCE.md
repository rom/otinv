# Embedded IEEE MAC address registry

`table.txt.gz` maps a MAC address prefix to the organisation that
registered it, so that otinv can name the maker of a network card from an
address it observed. It is generated — do not edit it by hand:

```
make oui OUI_DIR=/path/to/ieee
```

| What | Value |
|------|-------|
| Generated | 2026-10-15 |
| Source | IEEE oui.txt and iab.txt as redistributed in netaddr 1.3.0 (PyPI, BSD), mirroring https://standards-oui.ieee.org/ |
| 24-bit assignments (MA-L) | 35084 |
| 36-bit assignments (IAB) | 4575 |
| Compressed size | 396221 bytes |

Input files, as read by `ouigen`:

| File | Assignments | SHA-256 |
|------|-------------|---------|
| `oui.txt` | 35087 | `b4a0fb3d904278790abbae1e5bd6a31f8cdcc8676c5efe513d0577d22e652d9d` |
| `iab.txt` | 4575 | `f69f6a315c2c653f3634c5be75c4c148822ed1c3098dd3d14420f53cad988814` |

3 lines repeat a prefix the registry already lists under another holder: the
oldest OUIs were occasionally shared, and a renamed holder is listed again
without the old line being withdrawn. The table keeps every name, joined
with " / ".

The registry is IEEE's own public listing. The 28-bit (MA-M) and 36-bit (MA-S)
registries are **not** included here: this build's source carries the MA-L and
IAB files only. A MAC from one of the shared blocks those registries are
carved out of therefore resolves to the block's holder — the IEEE Registration
Authority — rather than to a manufacturer, and the lookup reports it as a
shared block with no vendor instead of naming the IEEE.
