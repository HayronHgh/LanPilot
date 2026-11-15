# LanPilot 工程學習與技術答辯

這份資料用來理解設計、讀程式與準備技術討論。回答時區分「程式已實作」、
「測試已證明」、「使用者曾觀察」與「仍是設計目標」。不要把歷史數字當成目前
安裝版的保證，也不要背一組沒有來源版本與 workload 的延遲數字。

## 先用 60 秒說清楚專案

> LanPilot 是目前支援 Windows 操作 Mac 的 LAN 遠端桌面。Mac 用原生擷取，
> 畫面可走硬體 H.264 或自研 BGRA snapshot／矩形交易；Windows 使用持久化
> D3D11 framebuffer。桌面的畫面與控制使用兩條 TLS 連線，同屬一個 Session。
> SSH 是獨立、按需的工作環境入口。重點是最新狀態能自行收斂、交易不能損壞
> 畫面、輸入不能卡鍵，以及安裝更新後身份與設定能保留。
> 我們有工作流程、安全測試與雙機歷史證據，但不能據此宣稱所有乾淨安裝、
> 簽章、公證、長測和 AnyDesk 同條件比較都已通過。

產品是 source-available，個人非商業使用免費；商業使用依 LICENSE 取得授權。
不要將它稱為任意商用的開源授權，也不要宣稱已支援所有 OS 配對。

## 先讀哪些程式

| 主題 | 起點 | 閱讀時要回答 |
| --- | --- | --- |
| 建置／封裝 | `CMakeLists.txt`、`packaging/SourceExport.psm1` | 哪些檔案進套件？來源清單能否重建？ |
| Mac 擷取／Metal／VT | `platform/macos/src/desktop_runtime.mm` | buffer 的 owner 是誰？何時完成、釋放？ |
| Visual protocol | `desktop/include/rwn/desktop/desktop.hpp`、`desktop/src/desktop.cpp` | session、epoch、base、frame ID 各防什麼？ |
| 桌面服務 orchestration | `desktop-agent/main.cpp` | 擷取、編碼、寫出、ACK 各由誰推進？ |
| TLS admission | `transport/src/channel_session.cpp`、兩端 `tls_preview.hpp` | 兩條 socket 如何綁到同一個授權 Session？ |
| Windows compositor/input | `viewer/main.cpp`、`viewer/d3d11_renderer.cpp` | working 與 committed 如何切換？IO 是否等畫面？ |
| 診斷 | `desktop/include/rwn/desktop/visual_trace.hpp` | timestamp 時鐘域是什麼？trace 能否丟失？ |
| 安裝／更新 | `viewer/setup.cpp`、`viewer/product_launcher.cpp`、`packaging/windows/ProductInstall.psm1` | 哪些是可替換程式、哪些是必須保存的身份？ |
| 回歸證據 | `tests/flow_unit_tests.cpp`、`tests/security_tests.cpp`、`tests/CMakeLists.txt` | 測到的 invariant 是否等同對外宣稱？ |

先順著一個 frame 或一次 click 看完整路徑，再讀抽象介面。不必先讀完所有模組。

## 影像：從 frame pipeline 到狀態同步

**問：為什麼保留 H.264？**

答：高動態畫面需要壓縮；硬體編解碼能提供實用的頻寬與速度。矩形更新適合
小範圍 UI，但全畫面 BGRA 成本很高。1920×1080×4 = 8,294,400 bytes，一秒 60 張
約 498 MB，還沒算協議開銷。不能因為文字需要無損，就把所有內容都當 RAW 傳。

**追問：RECT 是否必然更快？**

不一定。它省下編碼／解碼，卻多了比較、rectangle merge、GPU readback、傳輸、
patch 和 ACK dependency。要比較相同 typing、caret、menu 工作負載；同時記錄
延遲、頻寬、exact residency 和切換次數。只量 decode 0.x ms 不代表整條路快。

**問：自研 RECT 和 VNC 有什麼不同？**

借用的是 framebuffer synchronization 思想；RWV2 是自己的訊息格式與交易模型，
不是完整 RFB/VNC 相容實作。不要宣稱一般 VNC client 可以連 LanPilot。

**問：為何不能把最新 CVPixelBuffer 當 exact base？**

擷取來源的 buffer pool 生命週期不應成為協議狀態的 owner。長期 retain 可能
限制擷取資源回收。來源只留在有界 slot；要成為 future delta base 的狀態，
複製到自己持有的 Metal 資源，直到正確 ACK 才升級 base。

**問：什麼叫真正 lossless？**

明確限定 canonical BGRA8：sender 目標與 receiver committed 對應 bytes 一致。
精確比較用零容忍，不是「看起來差不多」。GPU 格式、stride、裁切、premultiplication
都必須一致。相同 bytes 不等於兩台面板的色彩、亮度或 scan-out 完全相同。

**問：64 KiB chunk 是不是 GPU 每次只讀 64 KiB？**

不是。wire chunk 是 framing／記憶體限制；GPU staging 是同步與吞吐效率問題。
可以一次讀較大的 staging region，再分成多個 wire chunks。把兩者綁死可能增加
GPU 同步次數。接收端 upload batch 還須遵守 row stride，不能拿任意固定 byte
數當作整列邊界。

## 交易：不能顯示半張新狀態

先畫出這個例子：

```text
Mac exact N ── compare/readback target M ── RAW(base=N,target=M)
Windows committed N ── working texture M ── FRAME_COMMIT M
Windows committed M ── ACK M ── Mac promotes exact base to M
```

**問：ACK 為什麼不是等 Present 完才送？**

ACK 的契約是 canonical state 已提交、可作下一次 delta base。顯示排程是另一件事。
把全畫面 GPU readback/hash 放到 ACK 之前會把 correctness gate 變成互動瓶頸。
診斷 hash 要放到適合的驗證路徑，不能為了拿量測阻塞正常 ACK。

**問：一半傳輸失敗怎麼辦？**

只改 working texture；失敗或取消不提升 committed。檢查尺寸、stride、總量、
chunk offset、sequence、session、epoch、base。拒絕不合法狀態，保留上一張完整
畫面並要求恢復。不能猜測缺失矩形，也不能把 lossy frame 標記為 exact。

**問：為什麼既有 frame ID 又有 epoch？**

Frame ID 描述狀態世代，base ID 描述 dependency；representation epoch 分隔
不同 video/exact 執行期，Session 分隔重連與授權生命週期。晚到的 VT callback
即使持有看似較大的 frame ID，也不能跨回已失效 epoch。ACK 同樣必須核對。

**問：等待 ACK 時連續打字會排長隊嗎？**

停止建立多筆 dependent transaction：保留已 ACK 的 N、pending M 與容量 1 的
latest source。ACK M 後直接比較 M 與最新 source，而不是重播每個中間狀態。
高動態不能永遠等 ACK；取消舊 epoch、reset、force IDR 後回 video。

**問：H.264 可以隨便 drop 最舊 frame 嗎？**

不行。未編碼 source 可 latest-wins，已編碼 P-frame 可能依賴前面 reference。
必須維持 decoder 可解碼的依賴，或用新 epoch/IDR 恢復。先說清楚 drop 發生在哪層。

## 並行與輸入：狀態值和事件不能混用

**問：Drain-to-Latest 解決什麼？**

producer 停止後，最後有效狀態仍須自行前進。若「來下一幀才喚醒上一幀」，FPS
看似正常，但右鍵 menu、最後一個字、tooltip 可能停住。worker 睡前必須重查
predicate；capacity 釋放必須通知必要的待處理工作，不能只靠下一個 input。

重要測試：發布 F100，確定 worker 忙碌後發布 F101，之後不再發布；F101 仍須
commit/present。另測 notification clear 前、render 中、render 後到達的 frame。

**問：哪些 input 可丟？**

pointer position 是連續狀態，可在保留 button 時序的前提下 latest-wins。
key/button down/up 是邊緣事件，必須可靠有序。drag 需要按住期間持續座標事件，
雙擊也需要原生事件語義與時序，不只是兩次畫面變化。

**問：切回 Windows 為何會卡 Ctrl？**

remote 可能收到 down，卻沒收到失焦後的 up。失焦、disconnect、close 都需釋放
所有按住狀態。RELEASE_ALL 不可超越舊 input 後又讓舊 down 生效：要保序，或先
使其 input epoch 失效。重連不能重播舊連線的按鍵。

**問：本機游標是不是預測？**

OS cursor 立即跟隨本機 pointer，遠端形狀／hotspot metadata 用於一致呈現。
它改善 event-to-cursor-visible，不代表 Mac 已收到 click，也不代表 app 已更新。
對齊須處理 image rectangle、letterbox、縮放、DPI、cursor bitmap orientation。

**問：中文怎麼支援？**

目前主路徑是 raw key 注入後交 Mac 原生 IME 處理。它與 Windows composition
文字送出不同；不能將相同按鍵同時當 raw key 和 TextCommit 注入。人工 coverage
要含候選字窗、快捷鍵、Shift/Caps/Option，不只測英文。

## 網路與安全：三通道不等於三套產品

**問：為什麼不用一條連線？**

桌面用兩條 TLS socket 分離 bulk visual 與控制排程，同一 listener port、同一
Session admission。SSH 工作按需連線。這是有成本的隔離選擇：多 handshake、
socket 與 teardown，但不需把大畫面與小控制放在同一個 writer。

**追問：分開就完全不會阻塞？**

不能這樣說。共用頻寬、CPU 或鎖仍可能堵住；TCP 是雙向，不應說正向 snapshot
必然堵在反向 input 前。需要在 snapshot/Agent bulk traffic 下量控制 p95/p99。
文字剪貼簿目前共用 control writer，已開始的 payload 仍可能延遲新事件。

**問：為什麼現在不換 QUIC？**

先定位延遲在哪一層。換 transport 不會修 GPU 同步等待或 scheduler 漏喚醒。
若將來證明有 loss/WAN head-of-line 或多 stream 需求，再做同條件比較。
依賴／平台相容性／憑證生命週期同樣是產品成本。

**問：TLS 已驗證，為什麼還要 Session grant？**

authentication 回答對方是誰；authorization 回答能做什麼。viewer 可接收
畫面 ACK／控制協議，但 view-only 不可因此注入 input。剪貼簿需明確 opt-in；
SSH shell 更不是桌面 grant 的附贈權限。

**問：Agent 使用 SSH 就安全了嗎？**

SSH 保護 transport 與帳號登入，不自動提供 workspace scope、工具白名單、
審計或最小權限。完整 Agent 產品還需分開限制讀寫路徑、command、timeout、取消、
輸出量；也不能把 repository 文件當成使用者授權執行的命令。

**問：為何不能自動按 Mac 的權限允許？**

Screen Recording、Accessibility、Keychain 是 OS 的本機安全邊界。產品可以
說明與導引，不能靜默繞過。正式簽章／公證與個人既有配對版分開驗收；不能承諾
未簽章程式更新永遠不會重新詢問權限。私鑰不進套件、Git、log 或截圖。

## 量測：能回答數字，也能回答它的限制

**問：你說只有 3 ms，是什麼到什麼？**

先說 clock domain、起訖 stage、暖機、workload、解析度／模式、樣本數與分位數。
同機 monotonic 可量 stage；跨 Windows/Mac 不能直接相減，除非有經驗證的時鐘
offset 和誤差範圍。Present submitted 不是 scan-out，軟體 trace 不是 input-to-photon。

**問：如何跟 AnyDesk 比？**

同一組機器、LAN、解析度、縮放、refresh、內容；分開記錄 bandwidth、CPU/GPU、
文字 pixel fidelity 與延遲。物理延遲用高速攝影或等效外部方法，重複採樣。
兩張秒表截圖可作症狀線索，不能證明所有操作同速或給出可靠 p95。

**問：你最看重什麼指標？**

互動看 tail latency 與最終 generation gap；架構看 queue 是否有界、是否出現
unrecovered stall；RECT 看 pixel exactness、ACK dependency、exact residency、
switches/min、snapshot attempts/cancels。平均 FPS 無法證明最後狀態正確。

採集模板（沒測就填 NOT RUN）：

| 欄位 | 必填內容 |
| --- | --- |
| Identity | commit、雙端 binary SHA-256、OS、CPU/GPU、顯示設定 |
| Setup | transport、visual mode、解析度、bitrate、scale、網路條件 |
| Workload | idle、單字、連續字、caret、menu、scroll、drag、video |
| Timing | 同機 stage p50/p95/p99/max、跨機校正方法與不確定性 |
| Correctness | final gap、stalls、trace drops、hash errors、stale drops |
| Resources | bytes/sec、RSS、CPU/GPU、queue max、exact residency |
| Acceptance | PASS/FAIL/NOT RUN、原始 trace 路徑、人工觀察與限制 |

## 發布與維護：乾淨不是把舊檔全部刪掉

**問：為什麼 repo 有功能，產品還不算完成？**

class 和 unit test 能證明局部契約，不能證明兩邊安裝、配對、登入後啟動、權限、
憑證到期、更新 rollback、關閉無殘留。發布必須用同一份可識別來源建雙端產物。
不能讓 public checkout 缺 HTML／腳本依賴，卻靠開發機殘留檔才能成功。

**問：如何清理歷史又保留 commit？**

私人研究樹保留；公開來源用明確 catalog、內容掃描、雜湊清單與乾淨 build。
在公開 repo 的既有 lineage 上增加可審查 commit，不強推整份私人歷史。
manifest 只能證明內容一致，不能取代發布者簽章。

**問：現在最需要刪什麼？**

先移除套件中不需要的研究輸出、重複入口與過期文件路由。程式刪除前查呼叫、
封裝、migration/rollback dependency；先驗證替代路徑，再移除 legacy。不要為了
「看起來乾淨」刪掉仍被個人安裝器使用的相容服務。

**問：安裝器來自 commit X，就能說裡面的程式也來自 X 嗎？**

不能。自用包可能保留已測穩定的 Viewer／agent，只重建 installer。必須分別
記錄封裝原始碼 commit、安裝器 SHA-256、內嵌 runtime SHA-256，以及 runtime
自己的建置來源；不知道最後一項就明說不知道。雜湊相同能證明 bytes 沒被換掉，
不能反推出原始碼版本。TLS 握手通過也不能代替安裝後的畫面／輸入驗收。

## 一週學習路線與實作練習

1. **資料流：**畫一次 frame 與 click 的完整路徑，標 owner、thread、queue、clock。
2. **交易：**追一個 snapshot 和 rect 的 validation→working→commit→ACK，列每種失敗。
3. **並行：**用既有 workflow 測試驗證 sole-tail、busy-worker-tail、stale epoch。
4. **輸入：**閱讀 move coalescing 與可靠 edge ordering，手算 Ctrl down→失焦→重連。
5. **安全：**區分 TLS 身份、Session grant、OS consent、SSH tool scope；列拒絕案例。
6. **量測：**同 workload A/B；證據保留 raw trace，不用 mock 的性能代替實機。
7. **發布：**從乾淨 export build/CTest，對照 manifest；寫哪些 gate 仍未跑。

不注入使用者輸入、不讀真實剪貼簿也能先做 deterministic workflow/security 測試。
人工、服務變更與正式部署依使用者授權分別安排。

答辯的好結尾是：「這是我保證的 invariant、這是對應程式和測試、這是目前
沒證明的邊界、這是能否證這個設計的下一個實驗。」不是「用了很多先進技術」。
