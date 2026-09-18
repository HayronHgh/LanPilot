# LanPilot

在區域網路上，從 Windows 操作 Mac。使用原生擷取、硬體 H.264 編解碼與 D3D11
顯示，並研究用無損矩形更新改善文字畫質與小範圍操作延遲。

目前支援 **Windows 用戶端 → macOS 桌面**；其他方向尚未實作。
C++23／CMake，連線走 SSH，不需要自架轉發服務。

## 版本

| 版本線 | 畫面路徑 | 定位 |
| --- | --- | --- |
| v0.1 | 低延遲 H.264 | 正式版目標，完成安裝與穩定性驗收後發布 |
| v0.2 beta | 自研無損 RECT + H.264 fallback | 驗證小範圍更新的畫質與延遲 |

**尚無可下載的正式版本。** RECT 的局部量測有改善，但未證明所有工作負載都更快。
發布條件見 [發布清單](doc/public-releases.md)。

## 安裝兩端

以下命令適用於打包後的目錄。發布前，請依 [封裝文件](doc/public-guide.md)
建置對應平台的程式；Windows 執行檔不能直接放到 Mac 使用。

### Mac

1. 「系統設定 → 一般 → 共享」開啟「遠端登入」，只允許要使用的帳號。
2. 解壓 Mac 套件，在終端機進入套件根目錄，執行：

   ```sh
   sh ./bin/install-desktop-preview.sh "$PWD/bin/rwn-desktop-agent"
   ```

3. 首次連線時，在「隱私權與安全性」允許 agent 的螢幕錄製權限；控制鍵鼠另需
   「輔助使用」權限。若系統要求，關閉連線後重新連線。

agent 安裝在 `~/.local/libexec/remoteworkspacenode/rwn-desktop-agent`。
遠端登入服務隨開機啟動，agent 依 SSH 連線啟停。Mac 需要登入桌面；
LanPilot 不繞過 FileVault、鎖屏或權限提示。

### Windows

需要 OpenSSH Client，以及已授權到 Mac 帳號的 SSH 金鑰。
先用 PowerShell 連線，核對 Mac 主機指紋後才信任它：

```powershell
ssh -i C:\path\to\id_ed25519 mac-user@mac-address
```

應能以金鑰登入；Viewer 不提供互動式密碼或 passphrase 提示。
不要把私鑰放進專案或分享出去。

解壓 Windows 套件，在 PowerShell 進入套件根目錄：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\Install-DesktopPreview.ps1
```

開啟桌面的 **Remote Workspace** 捷徑（品牌調整中），填入 Mac 位址、帳號、
私鑰位置與 agent 路徑，再選「View only」或「Control keyboard and mouse」。
畫面預設等比例縮放、置中，不拉伸。緊急退出：**Ctrl+Alt+Shift+F12**。

更多設定與移除方式見 [安裝說明](doc/desktop-preview-install.md)。

## 怎麼運作

```text
Mac ScreenCaptureKit → VideoToolbox H.264 → SSH → Media Foundation → D3D11
Windows 鍵鼠事件      → SSH 控制通道       → Mac 原生事件
```

v0.2 beta 增加 Metal-owned exact framebuffer、snapshot／RECT 交易、世代檢查與
commit ACK。不是完整 VNC/RFB 實作，也不移除 H.264 回退。
ACK 表示畫面狀態已提交，不代表螢幕已完成顯示。

## 開發

需要 CMake 3.25+、支援 C++23 的編譯器及對應平台 SDK。

```sh
cmake -S . -B build/dev
cmake --build build/dev --config Release
ctest --test-dir build/dev -C Release --output-on-failure
```

流程單元、安全測試、GPU 探針與人工驗收分開記錄。軟體 pipeline timing 不等於
physical input-to-photon，不用局部解碼耗時宣稱整體延遲。

- [貢獻與 commit 規範](CONTRIBUTING.md)
- [使用與開發指南](doc/public-guide.md)

## 授權

個人非商業使用免費；商業使用需事先取得作者 **HayronHgh** 的書面授權。
公司業務或個人接案用途也屬商業使用。詳見 [LICENSE](LICENSE)。
這是原始碼公開（source-available）專案，並非允許任意商業使用的開源授權。
