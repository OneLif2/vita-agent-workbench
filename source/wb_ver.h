#ifndef WB_VER_H
#define WB_VER_H

/* Vita Agent Workbench - live update release.
 * 01.09 was a read-only SSH status terminal: one fixed command per arm,
 * two status reads, SSH off on disconnect. 01.10 adds the VitaShell style
 * VPK install path plus an in-process payload swap so the owner's SSH
 * connection survives the update. */

#define WB_VERSION      "02.06"
#define WB_BUILD_TAG    WB_VERSION "-live-safequery"
#define WB_PAYLOAD_ABI  3u
#define WB_PROTO        "wb10"

#define WB_TITLE_ID     "INAP00018"
#define WB_UPDATER_TITLE_ID "INAP00019"
#define WB_UPDATER_STAGE WB_ROOT "/stage/updater"
#define WB_TITLE        "Vita Agent Workbench"

/* Filesystem layout. Everything writable lives under WB_ROOT except the
 * owner supplied upload directory WB_INCOMING and device-local SSH identity. */
#define WB_ROOT         "ux0:data/INAP00018"
#define WB_LOG_PATH     WB_ROOT "/run.log"
#define WB_INSTALL_LOG  WB_ROOT "/install.log"
#define WB_PIN_PATH     WB_ROOT "/mac-public-pin.txt"
#define WB_PEER_PATH    WB_ROOT "/peer.txt"
#define WB_ADDR_PATH    WB_ROOT "/addr.txt"

#define WB_INCOMING     "ux0:/VITA-POC"
#define WB_STAGE_DIR    WB_ROOT "/stage/pkg"
#define WB_PAYLOAD_DIR  WB_ROOT "/payload"
#define WB_PAYLOAD_CUR  WB_PAYLOAD_DIR "/current.suprx"
#define WB_PAYLOAD_NEW  WB_PAYLOAD_DIR "/next.suprx"
#define WB_PAYLOAD_PREV WB_PAYLOAD_DIR "/previous.suprx"
#define WB_PAYLOAD_MARK WB_PAYLOAD_DIR "/loaded.txt"
#define WB_PAYLOAD_APP  "app0:workbench_payload.suprx"
#define WB_PENDING_PATH WB_ROOT "/pending-core.txt"

/* Owner facing SSH identity, unchanged from 01.09. */
#define WB_PORT         2222
#define WB_USER         "pi"
#define WB_DEFAULT_IP   "192.0.2.10"
#define WB_DEFAULT_MASK "255.255.255.0"
#define WB_DEFAULT_PEER "192.0.2.20"

/* Session budget: authentication is bounded, an armed connection is not. */
#define WB_AUTH_MS        90000u
#define WB_KEX_MS          8000u
#define WB_IDLE_MS      1800000u   /* 30 min per authenticated connection */
#define WB_INSTALL_MS    300000u   /* 5 min hard bound for one promote */
#define WB_UPLOAD_MAX  (192u*1024u*1024u)

#endif
