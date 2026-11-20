# 遠端桌面使用問題紀錄（2026-11-20）

使用者回報四個問題：部分按鍵送不出去（E、D 已確認）、剪貼簿沒有同步、Mac 的聲音沒有傳到
Windows、動畫畫面比 AnyDesk 差。本文依原始碼逐一判斷原因，並區分「已在程式中確認」和
「尚待實測」。

| # | 問題 | 原因狀態 | 優先 |
| --- | --- | --- | --- |
| 1 | E、D 等按鍵送不出去 | 已實作修正（2026-11-20）：旗標由 Agent 狀態推導、按鍵狀態自動對齊；待實機驗收 | 高 |
| 2 | 剪貼簿沒有過去 | 已確認：預設關閉、重連後關閉、只同步啟用後的新複製 | 高（修改小） |
| 3 | 沒有聲音 | 已實作音訊通道（2026-11-20），待實機驗收 | 中 |
| 4 | 動畫輸給 AnyDesk | 已確認：目前連線設定是 `exact-only` 無損未壓縮模式 | 高 |

## 1. 按鍵送不出去（E、D）

### 使用者觀察（2026-11-20）與最可能原因

按 D 時，Mac 會跳出「聽寫」。macOS 15 之後的 🌐/Fn 快捷鍵正好是：

| 組合鍵 | 系統功能 |
| --- | --- |
| 🌐+D | 開始聽寫 |
| 🌐+E | 表情符號與符號 |
| 🌐+F / A / C / N / H / Q … | 全螢幕、Dock、控制中心、通知中心、顯示桌面、快速備忘錄… |

所以 E、D 不是沒有送到 Mac，而是 **Mac 收到的按鍵事件帶著 Fn（`kCGEventFlagMaskSecondaryFn`）
旗標**，被系統當成 🌐 快捷鍵攔走了。其他「送不出去」的字母很可能也是同一個原因。

程式中的對應狀況：`MacosInputBackend::raw_key` 用 `CGEventCreateKeyboardEvent(nullptr, …)`
建立事件，**完全沒有呼叫 `CGEventSetFlags`**，也沒有自己的 event source。事件的修飾鍵旗標
因此沿用系統合併後的狀態。Agent 會送出方向鍵、F1–F12、Home/End/Page 這類按鍵，macOS 會
自動替它們加上 SecondaryFn 旗標；這個旗標可能就這樣殘留到後面的字母上，等於「Fn 卡住」。

修正（已實作）：

- `MacosInputBackend` 自己追蹤 Shift/Control/Option/Command（左右分開）的按下狀態。
  每個鍵盤事件、滑鼠移動、按鍵、滾輪事件都用 `CGEventSetFlags` 明確設定旗標，
  包含硬體會帶的左右側 device bit。只有方向鍵、F1–F20、Help/Home/End/PageUp/PageDown/
  Forward Delete 才加 SecondaryFn；數字鍵盤和方向鍵加 NumericPad；字母、數字、符號一律不加。
  Caps Lock 只沿用系統目前的 AlphaShift 狀態。
- 驗收（待實機）：遠端逐鍵按 A–Z，聽寫、表情符號、Dock 等面板都不會跳出；中間穿插方向鍵和 F 鍵後再測一次。

### 核心需求：卡頓後鍵盤狀態要自動回復

使用者指出，真正的問題是**卡頓時修飾鍵狀態切換不正確，而且之後不會自己恢復**。只修 Fn 旗標
不夠：卡頓時任何「放開」事件都可能遺失，Shift、Command、Fn 就會一直留在按下狀態，
直到使用者自己再按一次那個鍵。

目前狀態有三個破口：

| 位置 | 現況 | 卡頓時的後果 |
| --- | --- | --- |
| Windows hook | LL hook 跑在 UI 執行緒 | 執行緒忙碌時 hook 逾時，Windows 不再把按鍵交給 hook，key-up 不會送出 |
| 控制協定 | 只有「單次事件」和 `release_all_input`（只在失焦或重連時送） | 沒有機制定期比對兩端的狀態 |
| Mac agent | `InputReceiver::release_stuck_keys` 已經寫好，但**正式程式沒有任何地方呼叫** | 按鍵卡住後永遠不會自動放開 |

實作（2026-11-20）：與 AnyDesk 類似的狀態同步，**以 Viewer 觀察到的按鍵狀態為準，定期對齊**。

1. **Viewer 補回 hook 漏掉的鍵。** 擷取中 hook 會吃掉所有按鍵，所以若有 `WM_KEYDOWN/UP`、
   `WM_SYSKEYDOWN/UP` 送到視窗，代表 hook 逾時漏接（UI 執行緒卡頓）。視窗程序會用同一套
   mapping 把它轉送給 Mac，並重新安裝 hook（Windows 在多次逾時後可能靜默移除 hook）。
   不用 `GetAsyncKeyState`：被 LL hook 吃掉的按鍵不會更新 async 狀態，無法分辨「按著」和「已放開」。
2. **Viewer 每 250 ms 回報狀態。** `held_keys` 記錄 Viewer 觀察到的按下集合（即使入列失敗也照實記錄），
   以新的 `ReverseControlType::keyboard_state`（32 bytes，每個 HID usage 一個 bit）送出。
   它和按鍵事件在同一執行緒、同一個 reliable 佇列中，順序不會亂。失焦或 `release_all` 時清空。
3. **Agent 只做「放開」方向的修正。** `InputReceiver::reconcile_keys` 放開快照中沒有的鍵，
   並刷新仍被確認的鍵的按住時間；**不合成按下**，避免卡頓後重複打字。
4. **修飾鍵旗標由 Agent 的狀態算出**（見上方修正），所以對齊之後下一個字母的旗標立即正確。
5. **最後保險。** 收過 `keyboard_state` 之後，Agent 每處理一則控制訊息就檢查一次：
   超過 5 秒沒有被快照確認的鍵會自動放開。按住時間改用 Agent 本機時鐘記錄
   （原本用 Viewer 的時間戳，跨主機比較沒有意義，`release_stuck_keys` 也從未被呼叫）。

舊版 Viewer 不會送 `keyboard_state`，Agent 也就不會啟用第 5 點；舊版 Agent 不認得新訊息，
所以 Viewer 和 Agent 需要一起更新。

驗收：

- 單元測試（已通過，Windows CTest 25/25）：遺失 key-up 後送狀態快照，Agent 放開該鍵；
  快照不產生按下；不同主機的時間戳不影響卡鍵判斷；格式錯誤的快照被拒絕。
  Mac 旗標推導需要在 macOS 上編譯（GitHub CI）並實機驗收。
- 實機（待做）：人為讓 Viewer UI 卡住約 1 秒（例如拖動視窗時按住 Shift 再放開），恢復後 250 ms 內，
  Mac 上的 Shift 要自動放開；接著打 A–Z，不能出現大寫或系統快捷鍵。

### 已排除

兩端的鍵碼對照表都正確，所以不是表格寫錯：

- Windows：`map_windows_raw_keyboard_to_hid_usage` 把 `'A'..'Z'` 轉成 HID `0x04+n`，
  所以 D 是 `0x07`、E 是 `0x08`（`platform/windows/src/desktop_runtime.cpp`）。
- Mac：`hid_usage_to_key_code` 把 `0x07` 轉成 `kVK_ANSI_D (0x02)`，`0x08` 轉成
  `kVK_ANSI_E (0x0e)`（`platform/macos/src/desktop_runtime.mm`）。
- Agent 的 `validate_input_event` 和 `InputReceiver` 不會依鍵值過濾（`desktop/src/desktop.cpp`）。

### 初步分析（保留作紀錄，已由上方的原因與實作取代）

#### 可能原因（依可能性排序）

1. **鍵盤 hook 跑在 UI 執行緒，可能逾時。** `FocusedKeyboardCapture` 的 `WH_KEYBOARD_LL`
   hook 裝在視窗所在的執行緒（`viewer/main.cpp`）。執行緒忙碌時，hook 回應若超過
   `LowLevelHooksTimeout`，Windows 會略過這個 hook，該鍵就交給本機處理，不會送到 Mac。
   連續逾時時，Windows 還可能直接移除 hook，而且不會通知程式。E、D 是最常打的字母，
   最容易被注意到。
2. **reliable 佇列滿了。** 按鍵走上限 256 的 reliable 佇列。佇列滿時，
   `enqueue_input_safely` 只會把錯誤寫進標題列狀態，那個按鍵就丟掉了。
3. **Mac 的修飾鍵卡住。** 如果 Win/Cmd 的放開事件遺失，Mac 會把 E、D 當成 Cmd+E、Cmd+D
   快捷鍵，看起來就像「沒有打出字」。`CGEventCreateKeyboardEvent(nullptr, …)` 沒有指定
   event source，會沿用系統目前的修飾鍵狀態。

#### 診斷步驟

- 加入只在本機啟用的按鍵計數診斷模式（只記 HID usage 的次數，不記內容）。分三個階段計數：
  Viewer hook 收到、加入佇列、Agent 送出 `CGEventPost`。逐一按 A–Z，就能看出在哪個階段遺失。
- Mac 端同時開啟「鍵盤檢視器」，觀察 E、D 有沒有被當成帶 Cmd 的組合鍵。
- 記錄問題發生時 Viewer 標題列的狀態訊息，確認是否出現佇列滿的錯誤。

#### 修正方向

- 把 LL hook 移到專用執行緒，配自己的 message loop。hook callback 只做轉換和不會阻塞的
  入列，不碰 UI。
- 佇列滿時不要靜默丟鍵：改成合併處理或回報明確狀態。按鍵放開事件絕不能丟。
- Mac 端改用 `CGEventSourceCreate(kCGEventSourceStateHIDSystemState)` 建立事件，
  並依 Agent 自己追蹤的修飾鍵狀態明確設定 `CGEventSetFlags`。
- 新增 A–Z、數字、符號的按鍵矩陣驗收測試，作為發版門檻。

## 2. 剪貼簿沒有同步

### 已確認原因

1. **預設關閉，而且不會記住設定。** `packaging/windows/Start-LanPilotTls.ps1` 的
   「Sync new text copies while connected」核取方塊預設是 `Checked=$false`，也沒有存進
   連線設定檔。沒有勾選就不會傳 `--clipboard text`，Viewer 也就不會啟用同步。
2. **自動重連後會被關掉。** `viewer/main.cpp` 中是
   `clipboard_enabled = options.text_clipboard && !resumed`。只要斷線自動重連過一次，
   剪貼簿同步就變成關閉。
3. **只同步啟用之後的新複製。** `desktop/include/rwn/desktop/text_clipboard.hpp` 明確寫著
   「No initial clipboard read」。連線前已經複製的內容不會傳過去。
4. **範圍有限。** 只支援純文字，上限 32 KiB；圖片、檔案、RTF 都不支援。另外必須是
   interactive 模式才能使用。

（Mac 端 agent 已經帶 `--clipboard-text` 啟動，所以 Mac 那邊有授權，問題出在 Windows 沒有開。）

### 修正方向

- 第一步（小修改）：把剪貼簿偏好存進 `connections\default.json`，已配對的個人裝置預設開啟。
  同一組配對自動重連後保持原本的狀態，不要重設成關閉。
- 啟用時提供一次「同步目前剪貼簿」，標題列持續顯示 `Clipboard ON/OFF`。
- 第二步：支援圖片（PNG，設大小上限）。檔案複製另外走既有的 SSH/檔案傳輸通道，
  不要塞進 control socket。

## 3. 沒有聲音

### 已確認原因

桌面工作階段目前**沒有音訊通道**。TLS 工作階段只定義兩種通道：
`TcpChannel { visual = 1, control = 2 }`（`transport/include/rwn/transport/channel_session.hpp`）。
Agent 的 `TlsPreviewSession` 也只接受這兩條 socket。

需要的元件大部分已經存在，只是還沒接起來：

- `audio/`：wire format、`AudioJitterBuffer`、PLC，以及 `DynamicOpusCodec`（需要明確指定 libopus 路徑）。
- Mac：`MacosSystemAudioCapture`（ScreenCaptureKit 系統聲音，48 kHz 立體聲）。
- Windows：`WindowsAudioPlayback`（WASAPI shared-mode）。
- 還缺：安裝包沒有附 libopus、沒有兩台機器的實測證據（見 `doc/audio-runtime.md`）。

### 實作（2026-11-20）

1. **第三條 TLS 通道 `TcpChannel::audio = 3`，由 Viewer 發起。** 雙通道 admission 完成後，
   Viewer 用同一組憑證設定再連一次同一個 port，送出 `ChannelHello{audio, session, generation}`。
   Mac 只在 admission 後 10 秒內保留 listener，接受一條音訊連線；
   `audio_channel_admissible` 要求同一個 session、generation、同一張已驗證的用戶端憑證，
   而且 session 尚未過期。音訊不佔用 `TcpChannelSession` 的桌面通道位置。
   音訊用獨立的 socket，不會被大張畫面堵住（避免 TCP head-of-line blocking）。
2. **未壓縮 PCM，不需要 libopus。** 每個 frame 20 ms、48 kHz、立體聲、16-bit，
   固定 3,872 bytes（32-byte `RWA1` 標頭加樣本），約 1.5 Mbit/s，在區網內可以接受。
   Mac 使用既有的 `MacosSystemAudioCapture`（ScreenCaptureKit 系統聲音），
   沿用已經授予的螢幕錄影權限。
3. **Windows 播放。** 預先緩衝 3 個 frame（60 ms），佇列上限 8 個 frame（160 ms），
   超過就丟最舊的，避免兩端時鐘漂移讓延遲越積越多；以 `WindowsAudioPlayback`（WASAPI）播放。
4. **音訊只是盡力而為。** 舊版 Agent、沒有輸出裝置、音訊連線中斷，都只會讓聲音停止，
   不會中斷桌面工作階段。舊版 Viewer 不會連音訊通道，Agent 等 10 秒後就關閉 listener。
5. Probe 模式會輸出 `audio_frames=N`，用來實機確認有收到聲音。

尚未完成：

- 實機驗收：兩台機器播放測試音，確認聲音、延遲、斷音次數。
- 靜音開關、Opus 壓縮（遠端或 Wi-Fi 頻寬不足時才需要）、影音同步量測。

## 4. 動畫比 AnyDesk 差

### 已確認原因

目前實際使用的連線設定 `connections\default.json` 是 `"visual": "exact-only"`。這個模式：

- 傳的是**未壓縮的 BGRA 像素**。一張 1920×1080 完整快照約 8.3 MB，過去量到每張的傳輸時間
  p50 約 54 ms（`doc/NEXT_SESSION_HANDOFF.md`）。
- 全螢幕動畫超過範圍時，會重送一張完整快照，**不會改用 H.264**
  （`docs/LOSSLESS_DESKTOP_ARCHITECTURE.md` §6）。
- 理論上限：8.3 MB × 8 ≈ 66 Mbit/張。即使在有線 Gigabit 網路上，全畫面變動時也只能約 15 FPS；
  Wi-Fi 會更低。

AnyDesk 用的是有損編碼，加上自適應位元率和幀率，動畫時犧牲一點畫質來維持流暢。
本專案的 H.264 路徑過去實測約 58 FPS。

### 修正方向

1. **立即可試：** 把連線設定的 `visual` 改成 `h264-only`，用同一段動畫和 AnyDesk 比較。
   這只需要改設定；文字畫面的清晰度會比 exact 模式差一點。
2. **混合模式（主要方向）：** 動態時用 H.264 低延遲編碼，畫面靜止約 200–500 ms 後，
   再補送一次無損的 exact 更新（build-to-lossless）。這樣動畫流暢，文字最後仍然是無損的。
3. exact 路徑加上壓縮（LZ4 或 zstd fast）、捲動或搬移偵測（COPY_RECT）、SOLID_RECT，
   降低文字畫面的流量。
4. H.264：VideoToolbox real-time / low-latency 模式、依頻寬自適應位元率、固定 60 FPS 擷取和 frame pacing。
5. 量測：與 AnyDesk 播放同一段動畫，記錄 FPS、幀間隔 p95、輸入到畫面延遲和頻寬。
   沒有量測資料前，不宣稱已經追上。

## 建議順序

1. 按鍵狀態自動回復（已實作，待實機驗收）。
2. 音訊通道（已實作，待實機驗收）。
3. 剪貼簿第一步（修改小、確認度高）。
4. 動畫：先試 `h264-only`，再做混合模式（使用者決定先不做）。
