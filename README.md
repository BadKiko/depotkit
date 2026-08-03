# depotkit

Native C++ Steam CDN depot downloader. C ABI + small CLI.

Anonymous session, local manifests + depot keys, parallel chunk download, pause/cancel, Steam cell for nearby CDN.

Meant as a library you can embed (e.g. in a launcher plugin). Not a full Steam client and not a storefront.

## Status

v0.1 works on Windows (proven on real multi-depot downloads). Linux builds via CMake (libcurl + OpenSSL).

You bring manifests and depot keys from outside (Ryuu-style staging, etc.). Steam username login is out of scope for now. DLC is just more depots - pick which ones to pass in, no special API.

## Build

Needs CMake 3.20+, C++20. On Windows: Ninja + MinGW or MSVC. zlib/zstd are fetched if missing.

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Outputs: `build/depotkit-cli`, static `libdepotkit` (or shared with `-DDEPOTKIT_BUILD_SHARED=ON`).

Windows uses WinHTTP + BCrypt. Linux needs libcurl + OpenSSL.

## CLI

```text
depotkit-cli cell
depotkit-cli servers [-cell N]

depotkit-cli inspect -manifest <file> [-key <64hex>]

depotkit-cli download -app <id> -dir <out> \
  -depot <id> -manifest <file> -key <64hex> \
  [-jobs N] [-validate] [-cell N]

depotkit-cli download -app <id> -dir <out> \
  -keys depotkeys.txt -manifests-dir <staging> \
  [-jobs N] [-cell N]
```

`depotkeys.txt` lines:

```text
depotId;0123...64hexchars
```

Manifests in `-manifests-dir` should look like `123456_789.manifest`.

`-cell N` picks Steam content cell for nearby CDN. `0` / omit = read `CurrentCellID` from local Steam `config.vdf` when possible.

## Library

```c
#include <depotkit.h>

depotkit_request req = {0};
req.app_id = 480;
req.depots = depots;
req.depot_count = n;
req.install_dir = "out";
req.max_downloads = 64; /* 0 = default */
req.cell_id = 0;        /* auto */

depotkit_control *ctrl = depotkit_control_create();
depotkit_result r = depotkit_download(&req, on_progress, user, ctrl);
depotkit_control_destroy(ctrl);
```

Also: `depotkit_detect_cell_id()`, `depotkit_list_cdn_servers()`, pause/resume/cancel via `depotkit_control`.

Header: [`include/depotkit.h`](include/depotkit.h).

## Layout

```text
include/depotkit.h     public C ABI
src/                   library (manifest, crypto, http, steam session, engine)
tools/depotkit_cli.cpp CLI
tests/                 ctest
third_party/lzma/      vendored LZMA decoder
```

## License

MIT - see [LICENSE](LICENSE).

Protocol field layouts studied from public SteamRE/SteamKit docs (LGPL) - independent clean-room code, no SteamKit/DepotDownloader sources shipped. See [NOTICE](NOTICE).

Steam and related marks are trademarks of Valve Corporation.
