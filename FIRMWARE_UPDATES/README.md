# FIRMWARE_UPDATES

Storage location for the OTA firmware images served by the Fountain server.

* Drop files here as `*.bin`; the version is read from the file name (first
  dotted version), e.g. `fountain-2.1.0.bin`, `firmware-2.1.0.bin`,
  `esp32-2.1.0.bin` or `2.1.0.bin`.
* The server automatically picks the **newest** image (semantic comparison) and
  offers it to a device whose `current_version` is older (`ota_check`).
* For every image the server computes `size`, `crc32` and `sha256` and sends
  them **signed** (`ota_available`, scope=control) — so the verification data
  is server-attested (internal protocol addendum, section H).
* The binary is served over HTTP at `http://<PUBLIC_HOST>:<PUBLIC_PORT>/<file>.bin`.

Example:

```bash
cp build/fountain-2.1.0.bin FIRMWARE_UPDATES/
```
