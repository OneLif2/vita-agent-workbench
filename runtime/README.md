# Fixed-game MicroPython port source

This folder contains the port/bridge and the owner's original tic-tac-toe source.
The source matches the fixed script digest in `source/wb_game.h`:
`ec216ac6378407a863cdc52fd3bac41e6060fed4341a8436a06e16004f6a191d`.
It exposes only the fixed game, not a Python REPL or an arbitrary module loader.

External upstream: MicroPython v1.25.0 commit
`f498a16c7db6d4b2de200b3e0856528dfe0613c3`:
https://github.com/micropython/micropython/tree/f498a16c7db6d4b2de200b3e0856528dfe0613c3

The original supplied upstream archive had SHA-256
`77b0641c47213f41d14d71085cbca086e4ce87ae809c34ddb823c61ea820eca4`.
Neither that archive nor any compiled library is bundled here. The rebuild script
requires an exact checked upstream archive and an external VitaSDK, builds in a
fresh temporary directory, and does not contact a console. Review it before use:

```sh
VITASDK=/path/to/sdk sh rebuild.sh /absolute/path/to/micropython-COMMIT.tar.gz
```

The private reference library had SHA-256
`01418f28c0c7a2280fa87c12731908ce2789428f2c57cab46f966464caa3ef0c`.
The original MicroPython MIT/per-file notices remain applicable; see
`LICENSES/MicroPython-MIT.txt` and upstream. Original Workbench bridge/game source
is covered by the project Apache-2.0 grant, not a relicensing of MicroPython.
