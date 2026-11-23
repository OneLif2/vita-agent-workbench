# WAKE-1：從 5090 核實返回的 WB 是哪個 run

這是**只讀驗收工具**，不是接收器、開機服務、啟動或關閉 App 的指令。它重用已驗收 01.78 的 `wbterm.paired_terminal()`：只連原本 WB 的已配對端點，開一條 PTY，依次送 `ver → status → ver`。它先對照既有 01.78 驗收記錄與 5090 的已儲存公鑰 pin，再檢查實際 SSH host key；不接受新 pin、不退回 FTP/SFTP/SSH exec，不重試。

在專案根目錄，採用既有已配對的 Python/Paramiko 環境：

1. 冷開驗收前（WB 正運行）：`python -B v1.79/wake-acceptance/verify.py before --live`。保存 stdout 所示的完整 `DEVICE-*.json` 路徑。這一步不關閉 WB。
2. 機主確認**已關閉** WB，不是在 LiveArea 暫停；接收器啟用與已授權啟動請求，須由另一份證據記錄。先記錄「請求與相應接收器回條」才檢查返回；不能叫機主手動重開來代替這一步。
3. 只讀檢查返回：`python -B v1.79/wake-acceptance/verify.py after --baseline "<步驟 1 的 DEVICE JSON>" --live`。

| 結果／Exit | 代表 |
|---|---|
| `PRECLOSE_WB_IDENTITY_OBSERVED` / 0 | 取得關閉前的版本、build、run、host pin、SSH transport、三條指令的逐條輸出。 |
| `NEW_RUN_ON_ORIGINAL_PIN_OBSERVED_NOT_PROOF_OF_WAKE` / 0 | 在另一條經原 pin 驗證的 SSH 上，讀到與 baseline 相同版本/build 但不同 run；**不等於遠端命令令它開啟**。 |
| `SAME_RUN_NOT_RELAUNCHED` / 3 | 回到同一 run，不能稱為重開。 |
| `INCONCLUSIVE` / 2 | 無法驗證：例如拒絕連線、pin/版本改變、傳輸或輸出不一致。沒有其他操作或 fallback。 |

歷史 `iterations/install-0178-saveprobe/r1/recovery-144132237537.json` 亦可作比較基準：同時核對固定 SHA-256、原 pin 及原 build。報告會註明「historical ... not a fresh close witness」，不能證明因此次關閉而產生了新 run。新驗收應優先使用當次 `before` 檔案。報告只建立在本機 `wake-acceptance/evidence`。

**完整 WAKE-1 要另外有的證據**：機主當次本機啟用、手動關 WB、此後未再本機開 WB；已配對 5090 發出的唯一 request ID；接收器可驗證的同一 request ID、允許動作及 Vita 平台回執；最後原指紋、新 run、同一 SSH 三條指令。缺接收器或對應回條，一律不判 PASS。本工具沒有讓使用者輸入「已啟用」就改為 PASS 的選項。

[16 項主機測試的逐項輸出](evidence/HOST-20261122T1452132411675Z.txt)，測試阻擋 socket；沒有連 Vita。涵蓋成功、同 run、連錯或變更 pin、連線改變、傳輸識別、build 轉版、輸出錯誤、拒絕/中斷及偽造標籤與內容不符。重跑：`python -B v1.79/wake-acceptance/test_verify.py`。
