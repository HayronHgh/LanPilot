# Contributing

Build and verify each change from the authoritative project root:

```powershell
.\build.ps1 -Test
```

Do not commit `build/`, `out/`, caches, certificates, keys, `.env` files, or secrets.

Each reviewable phase unit must pass its relevant build and tests before commit. Commit messages use Conventional Commits with a real module scope and Chinese summary:

```text
<operation>(<scope>): <中文說明>
```

Use `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `ci`, or `chore`; use actual scopes such as `session`, `sync`, `build`, `artifact`, `security`, `desktop`, `agent`, or `doc`.

Examples:

```text
feat(ui): 加入等比例置中的視窗縮放
fix(input): 保留滑鼠按下前的移動順序
test(desktop): 驗證快照中斷不改寫已提交畫面
docs(doc): 說明雙端安裝與權限設定
```

One commit should explain one reviewable change. Its body should record the
observed problem, why this approach was chosen, commands run and known limits.
Do not manufacture commit dates, rewrite existing history to disguise development,
or use vague messages such as "finish everything". Review generated changes like
any other code; authors remain responsible for correctness and attribution.

Performance claims need workload, hardware, resolution, configuration and sample
counts. Distinguish host-local spans from end-to-end latency, and unit tests from
real-host acceptance. Do not describe beta RECT results as a universal speedup.

Release lines: v0.1 is the H.264 release; v0.2 beta introduces custom RECT with
H.264 fallback. No release tag should be created until its exact source and binary
lineage and relevant gates are verified.
