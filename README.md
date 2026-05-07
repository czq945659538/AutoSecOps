# 🚀 AutoOps Security

> 自动化运维与代码安全扫描平台 — 集 CI/CD 安全检查、依赖审计、密钥扫描、容器镜像检测于一体的 DevSecOps 工具链。

## 📌 目录

- [特性](#-特性)
- [架构](#-架构)
- [快速开始](#-快速开始)
- [目录结构](#-目录结构)
- [配置说明](#-配置说明)
- [模块详解](#-模块详解)
- [CI/CD 集成](#-cicd-集成)
- [安全扫描规则](#-安全扫描规则)
- [贡献指南](#-贡献指南)
- [许可证](#-许可证)

---

## ✨ 特性

| 模块 | 功能 |
|------|------|
| **SAST** | 静态代码安全分析，支持 Python / Go / Java / Node.js |
| **依赖审计** | 自动扫描依赖漏洞（CVE），对接 OSV / GitHub Advisory Database |
| **密钥扫描** | 检测代码中泄露的 API Key、Token、密码、私钥等敏感信息 |
| **容器安全** | Docker 镜像漏洞扫描，支持 Trivy / Grype |
| **Secret 管理** | 与 Vault / AWS Secrets Manager 集成，密钥轮换 |
| **合规检查** | CIS Docker / Kubernetes 基线检查 |
| **告警通知** | 支持钉钉、飞书、Slack、Email 多渠道通知 |
| **报告生成** | 输出 HTML/JSON/Markdown 格式安全报告 |

---

## 🏗 架构

```
┌─────────────────────────────────────────────────────────┐
│                    Web UI / CLI                         │
├──────────┬──────────┬──────────┬──────────┬────────────┤
│  SAST   │  Dep Audit│ Secret   │ Container│ Compliance  │
│ Scanner │  (CVE)    │ Scanner  │ Scanner  │ Checker    │
├──────────┴──────────┴──────────┴──────────┴────────────┤
│                    Core Engine                          │
│            (Task Queue · Rule Engine · DB)             │
├─────────────────────────────────────────────────────────┤
│     Trivy · Grype · Semgrep · Gitleaks · osv-scanner    │
└─────────────────────────────────────────────────────────┘
```

---

## 🏃 快速开始

### 环境要求

| 依赖 | 版本要求 |
|------|----------|
| Python | ≥ 3.10 |
| Docker | ≥ 24.0 |
| Go | ≥ 1.21 (可选) |
| Node.js | ≥ 18 (可选) |

### 安装

```bash
# 克隆仓库
git clone https://github.com/your-org/autoops-security.git
cd autoops-security

# 一键安装（推荐）
make install

# 或手动安装依赖
pip install -r requirements.txt

# 验证安装
python -m autoops --version
```

### 启动服务

```bash
# 启动 Web UI
make run

# 或使用 Docker 启动
docker compose up -d

# 浏览器访问
open http://localhost:8080
```

### 首次扫描

```bash
# 扫描本地项目
autoops scan ./your-project --type python

# 扫描 Docker 镜像
autoops scan --image your-app:latest

# 全量扫描（含合规）
autoops scan ./your-project --full
```

---

## 📂 目录结构

```
autoops-security/
├── autoops/                  # 核心引擎
│   ├── __init__.py
│   ├── cli.py                # 命令行入口
│   ├── scanner/              # 扫描器模块
│   │   ├── sast.py           # 静态分析
│   │   ├── dependency.py     # 依赖审计
│   │   ├── secret.py         # 密钥扫描
│   │   ├── container.py      # 容器扫描
│   │   └── compliance.py     # 合规检查
│   ├── engine/               # 扫描引擎核心
│   │   ├── rules/            # 安全规则库
│   │   ├── plugins/          # 插件扩展
│   │   └── report.py         # 报告生成
│   ├── notifier/             # 通知模块
│   │   ├── dingtalk.py
│   │   ├── feishu.py
│   │   ├── slack.py
│   │   └── email.py
│   └── storage/              # 数据存储
│       ├── db.py
│       └── cache.py
├── configs/                  # 配置文件
│   ├── scanner.yaml          # 扫描器配置
│   ├── rules/                 # 规则目录
│   │   ├── python.yaml
│   │   ├── go.yaml
│   │   └── secrets.yaml
│   └── notify.yaml           # 通知渠道配置
├── web/                      # Web UI
│   ├── app.py
│   ├── static/
│   └── templates/
├── tests/                    # 测试用例
├── docs/                     # 文档
├── scripts/                  # 辅助脚本
├── Makefile
├── requirements.txt
├── docker-compose.yml
└── README.md
```

---

## ⚙️ 配置说明

### scanner.yaml — 扫描器配置

```yaml
scanner:
  sast:
    enabled: true
    languages:
      - python
      - go
      - javascript
    rulesets:
      - autoops-security/python-security
      - autoops-security/go-security
    severity_threshold: medium   # low / medium / high / critical

  dependency:
    enabled: true
    sources:
      - osv
      - github_advisory
    fail_on: critical           # 扫描到何种级别时失败

  secret:
    enabled: true
    detectors:
      - aws_access_key
      - github_token
      - private_key
      - api_key
    exclude_paths:
      - "**/*.test.py"
      - "**/node_modules/**"

  container:
    enabled: true
    scanner: trivy              # trivy / grype
    image: your-registry/app:latest
   severity_threshold: high
```

### notify.yaml — 通知渠道配置

```yaml
notify:
  dingtalk:
    webhook: https://oapi.dingtalk.com/robot/send?access_token=xxx
    secret: xxx                 # 签名密钥（可选）

  feishu:
    webhook: https://open.feishu.cn/open-apis/bot/v2/hook/xxx

  email:
    smtp_host: smtp.example.com
    smtp_port: 465
    from: security@example.com
    to:
      - oncall@example.com
    cc:
      - lead@example.com
```

### 环境变量

| 变量名 | 说明 | 必填 |
|--------|------|------|
| `AUTOOPS_DB_URL` | PostgreSQL 连接串 | 否（默认 SQLite） |
| `AUTOOPS_REDIS_URL` | Redis 连接串 | 否 |
| `DINGTALK_WEBHOOK` | 钉钉机器人 Webhook | 启用钉钉时必填 |
| `FEISHU_WEBHOOK` | 飞书机器人 Webhook | 启用飞书时必填 |
| `VAULT_ADDR` | Vault 服务地址 | 使用 Vault 时必填 |
| `AWS_REGION` | AWS 区域 | 使用 AWS Secrets 时必填 |

---

## 📦 模块详解

### 1. SAST — 静态代码分析

```bash
autoops scan --type sast --rules autoops-security/python-security
```

**检测类型：**

| 规则 ID | 描述 | 严重级别 |
|---------|------|----------|
| `PY001` | SQL 注入 | Critical |
| `PY002` | 命令注入 | Critical |
| `PY003` | 反序列化漏洞 | High |
| `PY004` | 硬编码密码 | High |
| `PY005` | 不安全的随机数 | Medium |
| `PY006` | Path Traversal | High |
| `GO001` | 内存逃逸 | High |
| `GO002` | 整数溢出 | Medium |

### 2. 依赖审计

```bash
autoops scan --type dependency --fail-on critical
```

自动生成 `requirements.txt` / `go.mod` / `package.json` 的依赖树，对接 OSV API 查询 CVE。

**输出示例：**

```
✗ [CRITICAL] django@3.2.10  CVE-2023-36053
  Package: django
  Fixed in: 3.2.19 / 4.1.5 / 4.2.1
  => Upgrade to django>=4.2.1

✗ [HIGH] requests@2.28.0  CVE-2023-32681
  Package: requests
  Fixed in: 2.31.0
  => Upgrade to requests>=2.31.0
```

### 3. 密钥扫描

```bash
autoops scan --type secret --exclude "**/*.test.py"
```

基于 [Gitleaks](https://github.com/gitleaks/gitleaks) 规则，支持检测：

- AWS Access Key / Secret Key
- GitHub Token / PAT
- SSH Private Key
- API Key（Generic）
- Slack Token
- 数据库连接串
- JWT Secret

### 4. 容器安全

```bash
autoops scan --type container --image your-app:latest --scanner trivy
```

使用 Trivy 或 Grype 扫描镜像层，检测：

- 操作系统包漏洞（CVE）
- 应用程序依赖漏洞
- Kubernetes Secret 配置
- Dockerfile 最佳实践

### 5. 合规检查

```bash
autoops scan --type compliance --benchmark cis-docker
```

支持的合规基准：

| 基准 | 说明 |
|------|------|
| `cis-docker` | CIS Docker 1.13+ |
| `cis-k8s` | CIS Kubernetes 1.6+ |
| `pcidss` | PCI DSS 合规检查 |

---

## 🔄 CI/CD 集成

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AutoOps Security Scan
        uses: your-org/autoops-action@v1
        with:
          scan_types: 'sast,dependency,secret'
          fail_on: 'critical'
          dingtalk_webhook: ${{ secrets.DINGTALK_WEBHOOK }}

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: autoops-reports/
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

autoops-scan:
  stage: security
  image: autoops/security-scanner:latest
  script:
    - autoops scan ./ --type sast,dependency,secret --fail-on critical
  artifacts:
    paths:
      - autoops-reports/
    expire_in: 7 days
  only:
    - main
    - develop
    - merge_requests
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'autoops scan ./ --full --fail-on high'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'autoops-reports/**'
                    emailext (
                        subject: "Security Scan Report: ${currentBuild.result}",
                        body: "See attached report",
                        to: 'oncall@example.com'
                    )
                }
            }
        }
    }
}
```

---

## 🔒 安全扫描规则

### 自定义规则示例（Python）

```yaml
# configs/rules/python-security.yaml
rules:
  - id: SQL_INJECTION
    pattern: '(execute|cursor\.execute)\s*\([^)]*\%s[^)]*\)'
    severity: critical
    message: |
      Potential SQL injection detected.
      Use parameterized queries instead of string formatting.
    reference: 'CWE-89: SQL Injection'
    fix: |
      # Wrong
      db.execute(f"SELECT * FROM users WHERE id = {user_id}")

      # Correct
      db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### 密钥检测规则

```yaml
# configs/rules/secrets.yaml
rules:
  - id: AWS_ACCESS_KEY
    regex: '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
    severity: critical

  - id: GITHUB_TOKEN
    regex: 'gh[pousr]_[A-Za-z0-9_]{36,251}'
    severity: critical

  - id: PRIVATE_KEY
    regex: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    severity: critical
```

---

## 🧪 测试

```bash
# 运行所有测试
make test

# 运行带覆盖率报告
make test-cov

# 仅运行单元测试
pytest tests/unit/ -v

# 仅运行集成测试
pytest tests/integration/ -v
```

---

## 📊 报告示例

扫描完成后，默认在 `autoops-reports/` 目录生成：

```
autoops-reports/
├── 2025-06-01_14-30-00/
│   ├── summary.json        # 汇总数据
│   ├── sast_report.json   # SAST 详细结果
│   ├── dep_report.json    # 依赖审计结果
│   ├── secret_report.json # 密钥扫描结果
│   ├── container.json     # 容器扫描结果
│   └── report.html        # HTML 报告（可下载）
```

---

## 🤝 贡献指南

1. **Fork 本仓库**，创建特性分支
   ```bash
   git checkout -b feat/your-feature
   ```

2. **遵循编码规范**（使用 `make lint` 检查）
   ```bash
   make lint    # 代码风格检查
   make fmt     # 自动格式化
   ```

3. **编写测试**
   ```bash
   pytest tests/ -v --cov=autoops
   ```

4. **提交前自检**
   ```bash
   make pre-commit   # 运行 pre-commit hooks
   ```

5. **提交 Pull Request**，描述改动内容和相关 Issue

---

## 📄 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源许可。

---

## 🔗 相关资源

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Database](https://cwe.mitre.org/)
- [OSV - Open Source Vulnerabilities](https://osv.dev/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)

---

> ⚠️ **免责声明**：本工具仅作为安全辅助检查手段，不能替代人工代码审计。对于因使用本工具造成的任何直接或间接损失，作者不承担任何责任。请定期进行人工安全审计，并确保遵循所在行业的合规要求。
