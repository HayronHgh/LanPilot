# LanPilot

Windows-to-Mac 遠端桌面。此指南獨立於開發文件，可在離線安裝包中閱讀。
目前套件仍在驗收；沒有 release 版本／checksum 與授權資訊的本機 staging
目錄不是正式發布包。Windows 與 Mac 請使用各自平台的套件。

## Mac

1. 系統設定 → 一般 → 共享 → 遠端登入，只允許自己的帳號。
2. 解壓 Mac 套件；在終端機進入解壓根目錄，執行：

   ```sh
   sh ./bin/install-desktop-preview.sh "$PWD/bin/rwn-desktop-agent"
   ```

3. 在隱私權與安全性中授予螢幕錄製權限。控制鍵鼠另需輔助使用權限。
   macOS 若要求重啟程式，斷開連線後再連線。

安裝位置：`~/.local/libexec/remoteworkspacenode/rwn-desktop-agent`。
保持 Mac 登入桌面。遠端登入服務隨開機啟動；agent 依連線啟停，
不繞過 FileVault、鎖屏、睡眠或權限提示。

## Windows

先準備 OpenSSH Client，將 SSH 公鑰授權給 Mac 帳號，私鑰保留在 Windows。
核对 Mac 主機指紋並手動測試：

```powershell
ssh -i C:\path\to\id_ed25519 mac-user@mac-address
```

Viewer 不會提示輸入密碼或私鑰 passphrase，必須先確認非互動式金鑰登入可用。
不要關閉主機指紋檢查，也不要將私鑰放進套件。

進入 Windows 解壓根目錄：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\Install-DesktopPreview.ps1
```

開啟桌面 Remote Workspace 捷徑，填入 Mac 位址、帳號、私鑰及 agent 完整路徑。
新設定預設 View only；需要鍵鼠控制時明確選擇 Control keyboard and mouse。

### 實驗版獨立 TLS 啟動器（非預設）

套件另附 `bin/Start-LanPilotTls.ps1` 與 `TlsConnectionSettings.psm1`。
只有兩端均部署相容的 LPA1 握手版本、並已完成憑證配對時才使用。
可直接執行 TLS 啟動器，或在安裝時明確指定 `-Transport tls`，讓同一個捷徑指向它；
未指定時仍使用 SSH。這不會建立金鑰、安裝 CA、修改防火牆或啟動 Mac 服務。

TLS 設定保存於 `%LOCALAPPDATA%\LanPilot\tls-desktop.json`，與 SSH 設定分開；
預設 view-only/H.264。`-ConnectImmediately` 使用已存設定，`-ValidateOnly` 僅檢查設定格式，
不等於憑證驗證或連線成功。解除安裝保留 TLS 設定，亦不移除憑證或 SSH 金鑰。
正式憑證配置與自動啟動服務尚未整合，此入口不是一鍵部署完成的宣告。
預設 H.264 低延遲模式與 Fit 等比例置中。縮放不會提高 Mac 原始解析度。
緊急退出：Ctrl+Alt+Shift+F12。

## 更新與移除

更新前關閉 Viewer。Windows 重新執行 installer，預設保留既有連線設定；
Mac 重新執行上述 installer。更新 agent 後可能需要重新確認 macOS 權限。

Windows：執行套件中的 `bin/Uninstall-DesktopPreview.ps1`，預設保留設定。
Mac：執行 `sh ./bin/uninstall-desktop-preview.sh`。
SSH 金鑰、系統遠端登入與 macOS 權限不會隨程式移除而自動刪除／關閉。

## 出問題時

- 連不上：先測 SSH，確認位址、使用者、金鑰與已信任的主機指紋。
- 黑畫面：確認 Mac 已登入且 agent 有螢幕錄製權限。
- 能看不能控制：確認 Control 模式與輔助使用權限。
- 視窗放大但畫面不放大：測試程式可能用了1:1；一般啟動器使用 Fit。

專案：https://github.com/HayronHgh/LanPilot
