# EvoAgent PR Reviewer

- 审查统一 diff，输出结构化问题、修复建议和测试建议
- GitHub `pull_request` webhook（`opened`、`reopened`、`synchronize`）
- `agentic` 运行模式：Lead、Security、Correctness/Reliability、Critic
- SQLite 保存任务状态、执行轨迹和最终报告
- JSON API 与 Markdown 报告
- webhook HMAC-SHA256 签名校验，以及可选的 GitHub PR 评论回写
- Web 管理台、任务 Dashboard 与 Prometheus 指标
- Agentic 模式包含 Lead 主 Agent，以及 Security、Correctness/Reliability、Critic 三个从子Agent
- LLM unified patch、AST/CST、沙箱前后测试对比与仅 Draft PR 的修复闭环
- PostgreSQL、Redis 生产模式
- 失败案例回流、提示词评测、版本激活与回滚
- 自研 Agent Runtime、持久化 checkpoint、执行预算与任务断点续跑
- 带 Tool Registry、参数 Schema 校验和结构化 Observation 的 Agent Loop
- 确认反馈的租户/仓库隔离记忆、检索与过期清理
- Redis Streams ACK、Worker 租约、指数退避重试和死信队列
- Webhook delivery 幂等、重放时间窗与评论 upsert
- 用户登录、RBAC、租户/仓库隔离和不可变管理审计
- 动态 Skill manifest 校验、签名校验和隔离进程沙箱
- 自动修复后的编译/测试门禁、灰度发布与影子流量
- OpenTelemetry Trace、Prometheus 指标和持久化告警

## 快速开始

项目使用 Python 3.11。先安装锁定范围内的运行依赖，并在同一个 PowerShell 窗口中配置本地管理员：

```powershell
python -m pip install -r requirements.txt

$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:EVOAGENT_AUTH_REQUIRED = 'true'
$env:EVOAGENT_AUTH_SECRET = [Convert]::ToBase64String($bytes)
$env:EVOAGENT_BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD = '<替换为至少 10 个字符的密码>'

python -m evoagent
```

不要直接使用示例占位符作为密码或密钥。环境变量只对当前 PowerShell 及其子进程生效；修改配置后需要停止并重新启动 EvoAgent。服务可以在未配置模型时启动并提供健康检查，但提交审查前必须按下方“模型配置”章节配置模型。

Bootstrap 管理员只在用户名尚不存在时创建；已有同名用户的密码不会在重启时被覆盖。

服务默认监听 `127.0.0.1:8080`。启动后打开 `http://127.0.0.1:8080/`，前端会在业务 API 返回未授权状态后显示登录层。登录状态保存在当前浏览器的 `localStorage` 中；需要重新登录时可以点击退出，或清除站点数据。

API 调用需要先登录并携带 Bearer Token：

```powershell
$session = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/auth/login `
  -ContentType 'application/json' `
  -Body (@{username='admin'; password='<你的密码>'} | ConvertTo-Json)
$headers = @{Authorization="Bearer $($session.access_token)"}
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/reviews `
  -Headers $headers `
  -ContentType 'application/json' `
  -Body (@{
    repository = 'demo/api'
    pull_request = 12
    mode = 'agentic'
    diff = "diff --git a/app.py b/app.py`n--- a/app.py`n+++ b/app.py`n@@ -1 +1,2 @@`n+password = 'secret'`n+eval(user_input)"
  } | ConvertTo-Json)
```

查询任务：

```powershell
Invoke-RestMethod -Headers $headers http://127.0.0.1:8080/v1/tasks/<task-id>
Invoke-WebRequest -Headers $headers http://127.0.0.1:8080/v1/tasks/<task-id>/report
```

运行测试：

```powershell
python -m unittest discover -s tests -v
```

## 模型配置

DeepSeek 官方 API（按 Token 计费）：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'deepseek'
$env:EVOAGENT_DEEPSEEK_API_KEY = '<deepseek-api-key>'
python -m evoagent
```

通过 OpenRouter 使用有速率限制、可用性可能变化的 DeepSeek 免费模型：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'openrouter-deepseek-free'
$env:EVOAGENT_OPENROUTER_API_KEY = '<openrouter-api-key>'
python -m evoagent
```

如果指定的免费 DeepSeek 版本下线，可将 `EVOAGENT_LLM_MODEL` 改为 OpenRouter 当前提供的其他 `:free` 模型，或把 Provider 改为 `openrouter-free` 让免费路由自动选择可用模型。

任意其他 OpenAI Chat Completions 兼容端点使用 `custom`：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'custom'
$env:EVOAGENT_LLM_BASE_URL = 'https://example.com/v1'
$env:EVOAGENT_LLM_API_KEY = '<token>'
$env:EVOAGENT_LLM_MODEL = '<model-name>'
```

密钥只通过环境变量读取，不要提交到仓库。

### 结论分层与仓库上下文

Agentic 审查把输出分成两层，避免模型猜测污染正式指标或直接发布到 PR：

- `findings`：可以发布的正式结论。确定性 Scanner 命中会被保护；普通 LLM 新发现必须同时满足 Lead 选择、Critic 的四项核验、仓库上下文可用，并引用仓库工具产生的证据。
- `suggestions`：值得人工复核、但证据尚不完整的模型建议。它们会保留在 JSON 报告和协作审计中，但不会写入 GitHub 审查评论，也不会计入正式 Finding 指标。

建议区不能用“是否命中原始答案”直接判定对错。评测支持独立的 `suggestion_judgments`，每条判定为 `required`（数据集漏标的必修问题）、`optional`（正确但非阻塞）、`invalid`（事实错误）或 `duplicate`（重复结论）。报告同时给出建议效用率、人工判定覆盖率、干扰率和未判定数量；覆盖率不足时不得只引用效用率作结论。

判定文件格式见 `examples/suggestion_judgments.example.json`；复制后需将示例案例 ID 和位置替换为待评报告中的真实值。已有模型报告应使用专用的缓存重评分脚本，它不会创建模型客户端，也不会再次调用 API：

```powershell
python scripts/rescore_agentic_report.py pr_diff_100.jsonl output/agentic-evaluation/model-report.json --judgments output/agentic-evaluation/model-report-judgments.json --output output/agentic-evaluation/model-report-adjudicated.json
```

`run_full_agentic_batch.py --cached-only` 也会在缓存缺少任何选中案例时直接失败，避免标签修订改变抽样集合后意外产生新的模型调用。

只提交 unified diff 时，模型能够分析新增行，但无法证明跨文件调用关系。若要审查隐藏逻辑、调用方和测试影响，需要同时传入服务进程可读取的绝对仓库路径：

```json
{
  "repository": "owner/repository",
  "repository_root": "D:\\work\\repository",
  "mode": "agentic",
  "diff": "<unified diff>"
}
```

Docker 部署时，`repository_root` 必须是容器内路径，并且对应仓库应以只读卷挂载。当前受控 100 条数据集只包含 diff、不包含完整 checkout，因此模型新增结论会进入 `suggestions`；这类实验能验证执行链和增量价值，不能证明跨仓库语义审查能力。

### 人工确认后的 v2 基线

`pr_diff_100_v2.jsonl` 不覆盖原始 v1。它由 `benchmarks/adjudications/deepseek-v4-flash-10.confirmed.json` 生成，将人工确认的 5 条漏标问题加入必修答案，同时保留 3 条 optional。来源哈希、新增标签和生成结果记录在 `benchmarks/pr_diff_100_v2.manifest.json`。

```powershell
python scripts/promote_suggestion_judgments.py pr_diff_100.jsonl benchmarks/adjudications/deepseek-v4-flash-10.confirmed.json --output pr_diff_100_v2.jsonl --manifest benchmarks/pr_diff_100_v2.manifest.json
python scripts/run_rule_evaluation.py pr_diff_100_v2.jsonl --rules 14 --output output/agentic-evaluation/rules-14-pr-diff-100-v2.json
python scripts/rescore_agentic_report.py pr_diff_100_v2.jsonl output/agentic-evaluation/deepseek-v4-flash-10-suggestion-metrics.json --judgments benchmarks/adjudications/deepseek-v4-flash-10.confirmed.json --output output/agentic-evaluation/deepseek-v4-flash-10-v2-confirmed.json
```

| v2 实验 | 案例 | Precision | Recall | F1 | 高风险召回 | 干净准确率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 6 条确定性规则 | 100 | 100% | 55.56% | 71.43% | 66.67% | 100% |
| 14 条确定性规则 | 100 | 100% | 73.33% | 84.61% | 75.00% | 100% |
| DeepSeek 四角色正式 Finding（缓存 10 条） | 10 | 66.67% | 40.00% | 50.00% | 33.33% | 100% |

同一 10 条中的 12 条建议经人工确认后，建议效用率为 75%，Finding 与经确认建议的综合必修召回率为 100%。这个综合召回率包含人工 Gate，不能表述为“模型自动发布召回率”。机器可读结果见 `benchmarks/pr_diff_100_v2_baselines.json`。

真实 PR 的下一阶段必须为每条 manifest 提供人工 `expected_findings`，并把 `repository_root` 指向已经 checkout 到该 PR **head SHA** 的绝对路径，格式见 `benchmarks/real_pr_manifest.example.jsonl`。导入器会向 GitHub 核对 SHA，路径错、分支错或 checkout 缺失都会拒绝生成评测集：

```powershell
python scripts/import_github_pr_dataset.py benchmarks/real-pr-10.manifest.jsonl output/real-pr-10.jsonl --limit 10 --require-checkout
python scripts/run_real_pr_benchmark.py output/real-pr-10.jsonl --minimum 10
```

正式对照实验应对同一批案例分别移除和保留 `repository_root`，比较“仅 Diff”与“Diff + 完整仓库 + 四角色工具”的召回、误报、成本和延迟，不能用两批不同 PR 横向比较。

### 公开 Review 证据的 10 PR 诊断集

`benchmarks/real_pr_review_labels.jsonl` 绑定了 10 个公开 Python 仓库中的成员/协作者 Review 评论、评论发生时的 commit、变更行和人工 CWE 分类。checkout、导入与门禁命令如下：

```powershell
python scripts/prepare_review_checkouts.py benchmarks/real_pr_review_labels.jsonl --cache-root output/real-pr-repositories --checkout-root output/real-pr-checkouts
python scripts/import_github_review_dataset.py benchmarks/real_pr_review_labels.jsonl output/real-pr-reviewed-10.jsonl --checkout-root output/real-pr-checkouts
python scripts/run_real_pr_benchmark.py output/real-pr-reviewed-10.jsonl --minimum 10
```

匿名 GitHub API 达到限额时，可以复用之前已经核验过的证据；本地 HEAD、base commit、路径、行号和 diff 仍会重新校验：

```powershell
python scripts/import_github_review_dataset.py benchmarks/real_pr_review_labels.jsonl output/real-pr-reviewed-10-v2.jsonl --checkout-root output/real-pr-checkouts --reuse-evidence-from output/real-pr-reviewed-10.jsonl
```

这批标签的完整性是 `targeted-review-comments`：每条标签证明一个 Reviewer 确实指出的问题，但不声称穷举 PR 中全部问题。因此未命中的额外 Finding 计入 `formal_unjudged_findings`，人工判定前不能称为误报，也不能用它估计 Precision。

首轮 DeepSeek 四角色诊断执行成功率为 100%，目标 Review 召回 1/10；14 条规则为 0/10。对 Sphinx #14366 做同案例修复前后对照时，Worker 原本找到了问题但 Critic 因缺乏可执行证据拒绝；加入固定、无网络、不可执行任意代码的 URL 规范化探针后，系统在第 405 行发布了有证据的 Finding，命中公开 Review。这个单例对照证明语义探针有效，但不是 10 条全量重跑结果。机器可读的诊断摘要见 `benchmarks/real_pr_review_pilot.json`。

当前剩余瓶颈已经可以区分：任务分解层会强制所有生产源码至少交给 Correctness Worker；对于 SQLModel `model_dump()` 与 `Field(exclude=True)` 这类第三方库语义，模型即使读到正确源码仍可能判断错误，下一阶段需要版本化 Agent Skill 或管理员配置的回归测试，而不是继续放宽发布门禁。

项目启动时会自动读取项目根目录的 `.env`，也兼容 `evoagent/.env`；系统环境变量优先于 `.env` 文件。推荐将以下内容写入根目录 `.env`（该文件已被 `.gitignore` 忽略）：

```env
EVOAGENT_LLM_PROVIDER=deepseek
EVOAGENT_DEEPSEEK_API_KEY=你的真实APIKey
```

## GitHub Webhook

项目使用“GitHub 仓库 Webhook + 公网转发 + fine-grained PAT”接收 PR 事件，不需要创建或安装 GitHub App：

```text
GitHub Pull request 事件
        │
        ▼
https://<公网域名>/webhooks/github
        │  公网转发
        ▼
http://127.0.0.1:8080/webhooks/github
        │
        ▼
EvoAgent 创建异步审查任务
```

### 1. 配置 EvoAgent

先生成一个 Webhook Secret，并根据需要配置 GitHub fine-grained personal access token：

```powershell
$webhookBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($webhookBytes)
$env:EVOAGENT_GITHUB_WEBHOOK_SECRET = [Convert]::ToBase64String($webhookBytes)

# 私有仓库、PR 评论回写或自动修复需要；只审查公开仓库且不回写时可以不配置。
$env:EVOAGENT_GITHUB_TOKEN = '<GitHub fine-grained PAT>'

# 默认关闭。设为 true 后，审查完成时更新或创建 PR 评论。
$env:EVOAGENT_AUTO_POST_REVIEW = 'true'

python -m evoagent
```

Webhook Secret 用于验证 GitHub 请求头中的 HMAC-SHA256 签名，不能与登录用的 `EVOAGENT_AUTH_SECRET` 混用。Webhook 请求不携带管理台 Bearer Token；`/webhooks/github` 使用签名而不是用户登录进行认证。

fine-grained PAT 只授权需要接入的仓库，并按功能授予最小权限：

- 读取私有仓库 PR Diff：`Contents: Read`、`Pull requests: Read`；
- 回写审查评论：`Pull requests: Read and write`；
- 创建自动修复分支和提交：`Contents: Read and write`、`Pull requests: Read and write`。

只接收 Webhook 但不访问私有仓库、不回写评论且不执行自动修复时，可以不设置 PAT。密钥必须在启动 EvoAgent 前设置，修改后需要重启服务。

### 2. 建立公网转发

GitHub 无法访问 `127.0.0.1`，需要把公网 HTTPS 地址转发到本地 `http://127.0.0.1:8080`。任选一种已安装的转发工具，例如：

```powershell
# Cloudflare Quick Tunnel
cloudflared tunnel --url http://127.0.0.1:8080

# 或 ngrok
ngrok http 8080
```

命令启动后会显示一个形如 `https://example.trycloudflare.com` 或 `https://example.ngrok-free.app` 的公网 HTTPS 地址。保持 EvoAgent 和转发进程同时运行。临时公网地址通常会在转发工具重启后变化，变化后必须同步更新 GitHub Webhook 的 Payload URL。

上述快捷转发会把 8080 端口上的管理台和 API 一并暴露到公网，因此必须保持 `EVOAGENT_AUTH_REQUIRED=true`，并使用强管理员密码和随机 `EVOAGENT_AUTH_SECRET`。长期部署建议通过反向代理只公开 `/webhooks/github`（以及按需公开 `/health`），不要向公网暴露整个管理台。

### 3. 在 GitHub 仓库中添加 Webhook

进入目标仓库的 **Settings → Webhooks → Add webhook**，填写：

- **Payload URL**：`https://<公网域名>/webhooks/github`；
- **Content type**：`application/json`；
- **Secret**：与 `EVOAGENT_GITHUB_WEBHOOK_SECRET` 完全相同；
- **SSL verification**：保持启用；
- **Which events would you like to trigger this webhook?**：选择 **Let me select individual events**，只勾选 **Pull requests**；
- **Active**：保持勾选。

EvoAgent 会处理 `opened`、`reopened` 和 `synchronize` 三种 PR 动作；其他 `pull_request` 动作会正常接收但被忽略。服务会根据 payload 中的 `diff_url` 下载 Diff，并异步创建审查任务。

### 4. 验证连接

先确认本地服务和公网地址都能访问健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
Invoke-RestMethod https://<公网域名>/health
```

然后新建 PR、重新打开 PR，或向 PR 推送一次提交。在 GitHub 的 **Settings → Webhooks → Recent Deliveries** 中应看到 `/webhooks/github` 返回 `202`；管理台的任务中心随后会出现对应审查任务。如果失败，优先检查公网转发进程是否仍在运行、Payload URL 是否包含 `/webhooks/github`、Secret 是否一致，以及 PAT 是否有目标仓库权限。

默认只在管理台保存结果。只有 `EVOAGENT_AUTO_POST_REVIEW=true` 时才会向 PR 回写评论。

自动修复只覆盖可确定安全的规则，例如调试输出、`shell=True` 和硬编码 Python 凭据；结果始终提交到新的 `evoagent/fix-pr-*` 分支，不直接修改源分支。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `POST` | `/v1/auth/login` | 登录并获取租户绑定的短期 Bearer Token |
| `POST` | `/v1/reviews` | 创建同步审查任务 |
| `POST` | `/v1/reviews?async=true` | 创建异步审查任务 |
| `GET` | `/v1/tasks/{id}` | 获取状态、轨迹和报告 |
| `GET` | `/v1/tasks/{id}/report` | 获取 Markdown 报告 |
| `GET` | `/v1/tasks/{id}/feedback` | 获取该已完成任务的反馈历史 |
| `POST` | `/v1/tasks/{id}/fix` | 创建自动修复分支和提交 |
| `POST` | `/v1/tasks/{id}/feedback` | 回流误报、漏报或坏修复 |
| `POST` | `/v1/tasks/{id}/cancel` | 请求取消任务 |
| `POST` | `/v1/tasks/{id}/resume` | 从最近 checkpoint 续跑任务 |
| `POST` | `/webhooks/github` | 接收 GitHub PR webhook |
| `POST` | `/v1/skills/reload` | 动态重新加载 Skill |
| `POST` | `/v1/evolution/auto` | 从失败案例生成并评测提示词版本 |
| `POST` | `/v1/evolution/propose` | 评测指定提示词候选版本 |
| `GET/POST` | `/v1/evaluation/cases` | 查询或增加版本化评测样本 |
| `GET` | `/v1/evolution/status` | 查询模型与评测门禁就绪状态 |
| `GET` | `/v1/evolution/runs` | 查询持久化的新旧版本评测记录 |
| `POST` | `/v1/skills/{name}/versions/{version}/activate` | 激活或回滚版本 |
| `POST` | `/v1/skill-evolution/auto` | 从确认反馈生成、回放并门禁 Skill 候选 |
| `POST` | `/v1/skill-evolution/propose` | 评测指定 Agent Skill `SKILL.md` artifact |
| `GET` | `/v1/skill-evolution/status?skill_name={name}` | 查询 Skill 门禁与激活版本 |
| `GET` | `/v1/skill-evolution/runs` | 查询 Skill 进化运行与指标 |
| `GET` | `/v1/skill-evolution/{name}/versions` | 查询 Skill artifact 版本链 |
| `POST` | `/v1/skill-evolution/{name}/versions/{version}/activate` | 激活或回滚 Skill artifact |
| `GET` | `/metrics` | Prometheus 文本指标 |
| `GET` | `/api/alerts` | 查询租户告警 |
| `GET` | `/api/audit` | 查询租户审计日志 |
| `GET` | `/api/queue/dead-letters` | 查询死信任务 |
| `POST` | `/v1/queue/dead-letters/replay` | 重放死信任务 |
| `GET/POST` | `/api/deployments/llm-review`、`/v1/deployments/llm-review` | 查询或配置灰度/影子发布 |

`POST /v1/reviews` 的 `diff` 最大默认 1 MiB；单任务默认最多 8 步、120 秒。可通过环境变量调整，详见 `.env.example`。

## 架构

```text
HTTP / GitHub Webhook
        │
        ▼
 ReviewService ── TaskStore(SQLite / PostgreSQL)
        │
        ▼
 ReviewHarness (EvoAgent Runtime / checkpoint / resume / budget / trace)
        │
        ├── DiffParser
        ├── Redis Streams / ACK / lease / retry / DLQ
        └── ModeRouter（agentic only）
              ├── Lead：动态委派、返工请求、Critic 调度和最终综合
              ├── Security Worker：输入/权限/敏感数据/危险调用链
              ├── Correctness/Reliability Worker：状态/异常/并发/资源/兼容性
              ├── Critic Worker：由 Lead 委派的盲审、反例与证据挑战
              └── Gates
```
