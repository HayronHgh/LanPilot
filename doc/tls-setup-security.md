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

- Windows：`Initialize-LanPilotAuthority.ps1`、`New-LanPilotWindowsIdentity.ps1`、
  `Update-LanPilotTrustBundle.ps1`、`Start-LanPilotTls.ps1`。
- Mac：`prepare-tls-identity.sh`、`import-tls-identity.sh`、
  `LanPilot-Authorize.command`、`check-tls-resources.sh`、`install-tls-service.sh`。
- `New-LanPilotLaunchAgent.ps1` 產生待驗證設定；安裝器只允許固定結構，
  拒絕既有服務覆寫及不安全檔案權限。

腳本依賴 PowerShell／OpenSSL／平台工具的部分，尚未隨安裝器完全封裝。
不建議一般使用者手動組合參數；先完成精靈與更新生命週期再發布。

## 必測的拒絕路徑

錯誤或過期身份、錯誤 pin、缺少有效撤銷證據、未授權控制、重播與
sequence gap、跨 session ACK、異常斷線、資料不完整、更新下載中斷。
失敗時保留可回復設定，不能改成明文或放寬驗證。
