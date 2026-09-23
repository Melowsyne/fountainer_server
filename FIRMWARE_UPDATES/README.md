# FIRMWARE_UPDATES

Storage location for the OTA firmware images of the Fountain server.

* Place the files as `*.bin`; the version is read from the file name
  (first dotted version), e.g. `fountain-2.1.0.bin`, `firmware-2.1.0.bin`,
  `esp32-2.1.0.bin` or `2.1.0.bin`.
* The server automatically selects the **newest** image (semantic comparison) and
  offers it to a device whose `current_version` is older (`ota_check`).
* For each image the server computes `size`, `crc32` and `sha256` and sends
  them **signed** (`ota_available`, scope=control) — this makes the verification
  data server-attested (addendum section H).
* The binary is served via HTTP at `http://<PUBLIC_HOST>:<PUBLIC_PORT>/<file>.bin`.

Example:

```bash
cp build/fountain-2.1.0.bin FIRMWARE_UPDATES/
```
