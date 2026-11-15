# 安裝與最小權限

## 現況與目標

目前 TLS 工具是工程部署流程，不是一鍵安裝器。以下是要交付的安全 UX，
尚未完成的步驟不得在介面或文件宣稱已自動化。

1. Windows 使用 CurrentUser 身份儲存區；Mac 使用登入使用者的 Keychain。
   每個端點的私鑰本機產生且不匯出，不共用發行包中的測試身份。
2. 第一次連線雙端確認配對身份。發現 LAN 裝置不代表信任該裝置；
   憑證釘選、期限、撤銷與授權都必須通過。
3. Mac 畫面需要螢幕錄製，鍵鼠控制另需輔助使用。這是作業系統同意，
   不是取得 root；不能靜默繞過或承諾完全無提示。
4. 預設 view-only；interactive 必須明確選擇並由 Mac 授予。
   Agent SSH 的權限獨立，不因桌面配對而得到任意 shell 或 sudo。
5. 自動啟動使用登入後 LaunchAgent，不要求系統級 daemon；
   FileVault 解鎖、尚未登入桌面不在無人值守承諾內。
6. 不加入系統根信任、不關閉防火牆、不對所有程式開放 Keychain 私鑰，
   不要求停用 Gatekeeper／UAC。需要額外權限時逐項解釋與確認。

## 現有工程入口

### 雙端確認實作邊界

採用「Windows 輸入 IP → 雙端核對配對資訊 → Mac 本機允許 → 保存後一鍵連線」。
`core/pairing_consent.hpp` 是兩端共用的本機確認狀態邏輯，不是已完成的配對網路協議。
只有本機 UI 可以提供 local approval；遠端確認必須先由平台 adapter 驗證。
同一個不可變 transcript binding 必須包含雙端公鑰、角色、新鮮 nonce 與通道綁定；
不能拿 IP、裝置名稱或未驗證的 JSON 當作 binding／信任證據。

- 單次確認視窗最多 120 秒，使用 monotonic clock；取消、拒絕、逾時及錯誤不可復活。
- 雙端同意只到 ready-to-persist；只有本機安全儲存完成才可顯示 paired。
- 保存期間取消／逾時，adapter 必須清除 staging，不可啟用部分身份。
- 配對不授予 Agent shell，亦不取代桌面 capability、TLS pin／期限／撤銷檢查。

尚未接上首次連線的安全 bootstrap、native identity enrollment、Mac 確認 UI、
durable staging rollback 與 launcher。因此目前一般使用者首次配對仍未完成，
不能把這個狀態機或既有 authenticated NodePairingService 當成完成品。
新增 listener／更新 Mac 安裝版前仍須另外確認；現有身份及串流不受影響。

- Windows：`Initialize-LanPilotAuthority.ps1`、`New-LanPilotWindowsIdentity.ps1`、
  `Update-LanPilotTrustBundle.ps1`、`Start-LanPilotTls.ps1`。
- Mac：`prepare-tls-identity.sh`、`import-tls-identity.sh`、
  `LanPilot-Authorize.command`、`check-tls-resources.sh`、`install-tls-service.sh`。
- `New-LanPilotLaunchAgent.ps1` 產生待驗證設定；安裝器只允許固定結構，
  拒絕既有服務覆寫及不安全檔案權限。

腳本依賴 PowerShell／OpenSSL／平台工具的部分，尚未隨安裝器完全封裝。
不建議一般使用者手動組合參數；先完成精靈與更新生命週期再發布。

## 產品檔案配置

Windows 正式安裝必須只在桌面建立一個 `LanPilot.lnk`。修復腳本、憑證檔、
撤銷資料、測試 bundle 與日誌都不得放在桌面。固定配置如下：

- 程式：`%LOCALAPPDATA%\Programs\LanPilot`
- 連線設定：`%LOCALAPPDATA%\LanPilot\connections`
- 公開信任資料與身份 metadata：`%LOCALAPPDATA%\LanPilot\identity`
- 維護狀態與可回復備份：`%LOCALAPPDATA%\LanPilot\maintenance`
- 有界診斷日誌：`%LOCALAPPDATA%\LanPilot\logs`

Windows 私鑰仍由 CurrentUser 憑證庫／CNG 持有，Mac 私鑰仍由使用者 Keychain
持有；上述目錄不得出現可匯出的端點私鑰。舊版 `tls-desktop.json` 只允許在
本機首次啟動時遷移到 `connections/default.json`，原檔必須先備份到 maintenance，
不得散落到桌面。首次配對仍需雙端確認；記住 IP 不代表自動信任新裝置。

## 必測的拒絕路徑

錯誤或過期身份、錯誤 pin、缺少有效撤銷證據、未授權控制、重播與
sequence gap、跨 session ACK、異常斷線、資料不完整、更新下載中斷。
失敗時保留可回復設定，不能改成明文或放寬驗證。
