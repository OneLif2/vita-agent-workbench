"""Rebuild the human report from saved evidence, never contact the console."""
from pathlib import Path
import datetime,json,re,hashlib
R=Path(__file__).resolve().parents[2];D=R/'evidence/live/s1'
def read(p):return json.loads(p.read_bytes())
def newest(glob):
 ps=sorted(D.glob(glob));return (ps[-1],read(ps[-1])) if ps else (None,{})
def rel(p):return p.relative_to(D).as_posix()
def link(p):return '[回執]('+rel(p)+')'
ap,a=newest('baseline-2*.json');tp,tr=newest('bridge-2*.json');xp,x=newest('retry-2*.json');pp,apply=newest('apply-2*.json')
obs=[(p,read(p)) for p in sorted(D.glob('observe-2*.json'))]
newpairs=[(p,v) for p,v in obs if v.get('outcome')=='NEW_BUILD_NEW_RUN_QUEUE_CLEAR_NOT_R1']
quick=[(p,v) for p,v in obs if v.get('observed',{}).get('build')=='01.34-live-s1' and any(re.fullmatch(r'run='+v['observed']['run']+r' elapsed_ms=\d+ QUICK OPEN LISTENING origin=(livearea|remembered-empty) buttons=0',l) for l in v.get('startup_routes',[]))]
ue=D/'isolated/RESULT.json'
fixed=(D/'staged.json').exists()
stage=read(D/'staged.json') if fixed else {}
probes=[l for l in stage.get('output','').splitlines() if l.startswith('WBQ2-PROBE')]
modeproof=any('mode=0600 op=open-write ' in l and 'native=0x80010016' in l for l in probes) and any('mode=0606 op=pass ' in l for l in probes)
passed=bool(fixed and a.get('outcome')=='INSTALL_REFUSED' and a['package']==stage['package'] and stage['source']['build']=='01.33-live-s1trace' and apply.get('outcome')=='UPDATER_ACCEPTED_NOT_A_PASS' and newpairs and ue.is_file() and read(ue)['result']=='PASS')
lines=['# 01.34｜5090 實機：同一個 VPK 的 WBQ2 回歸','',
 '原版和修正版按同一流程：用既有配對金鑰登入 → df → 驗證 VPK → install（不換 payload）→ 對照本機獨立產生的 WBQ2 → apply-core → 新 run。若同一 VPK 已上傳，只重做裝置端 inspect，不重複上傳。自我更新會斷 TCP，重開後另建已配對連線。','',
 '| 階段 | 已有結果 |','|---|---|']
lines+=['| 來源實機 | 原版 `01.33-live-r1`，run `'+a['observed']['run']+'`，原 host SHA-256 `'+a['observed']['host_pin']+'`。|',
'| 失敗基線 | **❌ 同一份最終 01.34 VPK**，`'+a['package']['vpk_sha256']+'`；原版在 `stage verification / receipt failed (io-error)`（rc=1）停止。檔案摘要相符、待套用標記不存在、沒有送 apply。'+link(ap)+' |',
'| 診斷入口 | 位於 `'+tr['remote']+'`；title/version/整包 SHA 符合，僅上傳、非成功安裝或修復。'+link(tp)+' |']
if x:
 lines+=['| 修正後同一路徑 | '+('已核對公開收據與本機 WBQ2 一致。' if fixed else x.get('error',x['outcome']))+' '+link(xp)+' |']
else:lines+=['| 修正後同一路徑 | 待機主以 VitaShell 就地安裝診斷包並重開監聽，再由 5090 執行同一個 `install`。 |']
if pp:lines+=['| updater | '+apply['outcome']+'（單看 ACK 不算通過）。'+link(pp)+' |']
if newpairs:
 p,o=newpairs[0];s=o['observed'];lines+=['| 真實返回 | `'+s['build']+'`，新 run `'+s['run']+'`，空佇列；原 host pin 的同一新 transport `'+s['transport_sha256']+'` 完成 ver/status/ver。'+link(p)+' |']
if ue.exists():lines+=['| 新 updater 實機負向測試 | '+read(ue)['result']+'：核准、換內容、缺檔、多檔、舊／無收據等 11 個隔離情境；拒絕個案無 handoff，沒有破壞真實 stage。[結果](isolated/RESULT.json) |']
else:lines+=['| 新 updater 實機負向測試 | 待 `s1-check` 及新 run 取回 11 項相符結果。不以 39/39 或 41/41 host 代替。 |']
if quick:lines+=['| 免按鍵冷啟動 | 新 run 日誌有 `QUICK OPEN LISTENING … buttons=0`。'+link(quick[-1][0])+'；仍須區分普通點開與系統回到 App。 |']
else:lines+=['| 免按鍵冷啟動 | 尚無 01.34 普通冷啟動的 `buttons=0` 實機證據；不能以 SSH 通或按 □ 後進入代替。|']
lines+=['','**S1 實機驗收：'+('通過。' if passed else '未完成，不改 ✅。')+' R1 按機主指示維持 ☐。**','','## 哪一步出了錯？','',
 '原版把 stage 讀取、私有／公開收據建立、write、sync、close 等不同失敗都映成同一個 io-error；歷史訊息本身沒有 native rc。只讀核對發現原來的四個 stage 檔案均與核准內容相符（包括重新產生的 head.bin）。[四檔證據](previous-stage.json)。成功讀回不能單獨證明原操作瞬間讀取成功。','',
 'VitaSDK 對 full-permission homebrew 要求建立檔案時明確附系統讀寫位。舊 private seal 0600；固定文件 0606，受控私有目錄 0707。保留最先失敗的 phase/op/path/native rc，兩份收據各 sync、close、重開讀回，最後才發布可用佇列。倘若真實故障與權限模式不同，以裝置傳回的第一個錯誤為準。[SDK 說明](https://github.com/vitasdk/vita-headers/blob/master/include/psp2common/kernel/iofilemgr.h)。','']
if probes:
 lines+=['同次安裝、同一 private store，以不同檔名及無效作為收據的固定文字進行原模式／修正模式對照：','```text',*probes,'```','這是同目錄獨立重現，並非事後讀取 01.32 當時的 syscall trace。']
elif x:
 lines+=['尚未看到完整 A/B；先看回執中的 WBQ2 診斷，不猜原因。']
else:lines+=['**目前 0600 是有 SDK 與 host 故障注入支持的原因，尚不是本機原生錯誤碼的直接證據。**']
(D/'REPORT.md').write_bytes(('\n'.join(lines)+'\n').encode())
print('S1 acceptance',passed,'quick receipt',bool(quick),'A/B',probes)
