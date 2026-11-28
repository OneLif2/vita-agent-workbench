# Fixed-game MicroPython port source

This folder contains the port/bridge and the owner's original tic-tac-toe source.
The source matches the fixed script digest in `source/wb_game.h`:
`ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d`.
It exposes only the fixed game, not a Python REPL or an arbitrary module loader.

External upstream: MicroPython v1.25.0 commit
`f498a16c7db6d4b2de200b3e0856528dfe0613c3`:
https://github.com/micropython/micropython/tree/f498a16c7db6d4b2de200b3e0856528dfe0613c3

Neither the upstream archive nor any compiled library is bundled here. Review `rebuild.sh` before use:

```sh
VITASDK=/path/to/sdk sh rebuild.sh /absolute/path/to/micropython-COMMIT.tar.gz
```

The original MicroPython MIT/per-file notices remain applicable; see `LICENSES/MicroPython-MIT.txt`.
