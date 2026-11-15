# LanPilot 使用與封裝指南

- 最新架構與安裝入口：[README](../README.md)。
- 既有配對自用版：[個人安裝器](personal-installers.md)。
- 開發與發布驗收：[目前狀態](product-status.md)、[收斂清單](release-convergence.md)。
- 套件內離線說明：[套件 README](../packaging/DESKTOP-README.md)。

## 產品安裝包

先在目標平台完成 configure、build 與 CTest。Mac 使用 universal2；命令見
[README](../README.md)。產品版本為 0.3.0；版本號不代表簽章或公開發布驗收已通過。

```sh
# Windows：建置離線圖形安裝器
cmake --build build/dev --config Release --target LanPilot-Setup --parallel 4

# macOS：建置原生 Installer 套件
cmake --build build/dev --config Release --target lanpilot-macos-installer --parallel 4

# 在各自平台建置後，輸出到全新 staging 目錄
cmake --install build/dev --config Release --component desktop --prefix /absolute/new-stage
```

Windows prefix 請使用如 `C:/LanPilot-stage`。這只是產生套件，不會安裝或
啟動任何服務。輸出恰好三個檔案：

| 平台 | 唯一安裝入口 | 隨附檔案 |
| --- | --- | --- |
| Windows | `LanPilot-Setup.exe` | `README.md`、`LICENSE` |
| Mac | `LanPilot-macOS-UNSIGNED.pkg` | `README.md`、`LICENSE` |

Windows 執行檔已內嵌所需 runtime 與腳本，不需另開 PowerShell。
Mac 未簽章套件是驗證產物；不關閉原生 app 的 publisher gate，也不替代目前
已能運作的自用服務。既有配對請走個人安裝器路線，不直接用未簽章原生 app
覆蓋它。正式簽章／公證仍屬公開發布的獨立門檻。

`lanpilot-desktop-package-workflow` 會實際建置和 staging，檢查只有上述產品檔案，
且相容工具仍可單獨打包。它不執行安裝、不讀取配對或私鑰、不操作遠端桌面。
發布資產另須記錄對應來源 commit、平台架構與每個產物的 SHA-256。

## 明確選用的相容與工程套件

```sh
cmake --install build/dev --config Release --component desktop-compat --prefix /absolute/compat-stage
```

這個元件保留 `bin/` 中的舊 CLI、安裝腳本與明確選用的 SSH 路徑，供維護者使用。
它不複製圖形安裝器。H.264 本身仍在最新 runtime 中，不必安裝舊版才能使用。

沒有指定 component 的 install／CPack 是完整工程套件，含 node、broker、probe
等開發工具；不要拿來當一般使用者的桌面下載包，也不要直接分享 `out/`。

## 最新連線架構

畫面與控制使用兩條 TLS TCP socket，共屬一個桌面 Session。SSH 是獨立按需的
工作環境入口；只有明確選用舊 SSH 相容路徑時，畫面與控制才走 SSH。
目前沒有公開 relay／網際網路穿透服務。

更新保留已選的畫面模式、配對與權限；不得把 Exact-only 連線改回 H.264。
螢幕錄製／輔助使用仍由 macOS 本機授權，view-only、control 與剪貼簿同意各自
保留語意，不改 TCC 或放寬 TLS 驗證。
