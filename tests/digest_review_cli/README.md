# 5090：自動核對八組 WBQ2 摘要（唯讀）

用途：WBQ2 排程後、機主授權前，自動回答「目前機上要核准的內容，是否就是本次選中的發行包？」。不輸入按鍵、不授權、不交接，亦不判定更新已安裝。「八組」是同一個 SHA-256 的八段，不是八個獨立雜湊。

在本版本的 `bin` 資料夾，用 `wb review-digest --vpk LOCAL_VPK --sha256 TRUSTED_RELEASE_SHA256 --stage LOCAL_STAGE_CONFIRMED_JSON --json`。完整 VPK SHA-256 取自獨立可信的本地發行紀錄，不要從 Vita 回覆抄成預期值。預期 WBQ2 由 native helper 從 VPK 重建，包含產生的 head.bin，不直接用壓縮包的雜湊代替。

以原主機釘選和 staging 回條的來源 run 連一條新的互動 SSH，兩次 `ver → status → ver`，並在核對前後重查 pending。只讀、不會自動配對，不會降級換用 FTP、SFTP 或 SSH exec。

| 結果 | 可推論 | 不可推論 |
|---|---|---|
| `MATCH / LOCAL_REVIEW_MODEL` | 來源核心 ≥01.81：本地 manifest、機上 pending、與機主本機審核畫面共用的八組資料均相符，標題、目標版本、總 bytes 及來源 run 吻合。 | 不是螢幕擷取、不是實際已顯示／已看過、不等於授權。 |
| `MATCH / PAIRED_PENDING_ONLY` | 來源 01.80：本地 manifest 與已配對 SSH 的即時 pending 相符。 | 舊核心沒有 review-model 指令；不得聲稱核對了畫面模型。 |
| 其他狀態或非零 exit | 不可憑本次檢查繼續；核對來源、配對、佇列與本機版本，保留回條。 | 沒有自動重試、強制升級或重新發出授權。 |

離線測試：`python -B tests/digest_review_cli/run.py`。案例包括逐組竄改、stage／run／釘選更換、回覆截斷、原生本機 receipt 計算和真正 wbterm 解析器的分段 PTY 回覆。測試不連 Vita。
