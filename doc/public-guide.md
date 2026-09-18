# LanPilot 使用與開發指南

- 首次使用：[雙端安裝](desktop-preview-install.md)。
- 發布前驗收：[發布清單](public-releases.md)。
- 開發環境：[README](../README.md)、[貢獻規範](../CONTRIBUTING.md)。
- 打包後的離線指南：[套件 README](../packaging/DESKTOP-README.md)。

## 精簡安裝包

先在目標平台完成 CMake configure、build 與 CTest，再輸出至一個全新目錄：

```sh
cmake --install build/dev --config Release --component desktop --prefix /absolute/new-stage
```

Windows 請將 prefix 換成如 `C:/LanPilot-stage` 的完整路徑。此命令只是產生
套件內容，不會安裝到使用者環境。macOS 產出 agent，Windows 產出 Viewer。
一般的無 component install 是完整工程套件，不應當作桌面產品發布。

檔案清單檢查不等於完成簽章、相依授權、乾淨環境安裝或雙機驗收。
正式資產必須附上清楚版本、來源及 SHA-256，不提供來歷不明的執行檔。

## 設計範圍

v0.1 使用 H.264；v0.2 beta 引入自研 RECT 交易與 H.264 回退。
重點是小 UI 更新的 byte-exact 畫質與延遲，不是重新實作視訊壓縮器。
SSH 同時提供影像與反向控制通道；沒有公開 relay 或網際網路穿透服務。

連線需要使用者授予 macOS 桌面權限。程式不應修改 TCC 資料庫或默認開放
遠端輸入；view-only 與 control 必須保持明確區別。
