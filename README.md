# 🛡️ Intelligent Vulnerability Assessment Assistant (Pro)

**智能漏洞研判助理 Pro** 是一款基于 **LLM (大语言模型)**、**CISA KEV 威胁情报** 和 **SSVC 决策模型** 的自动化安全运营工具。旨在帮助 SecOps 团队将耗时的漏洞情报分析工作缩短至秒级，并生成标准化的决策报告。

---

## ✨ 核心功能 (Features)

- **🤖 AI 驱动研判**: 集成 OpenAI / DeepSeek 接口，自动分析 CVE 描述并进行风险定级。
- **🚨 CISA KEV 集成**: 自动拉取 CISA "已知被利用漏洞" 数据库，命中即强制标记为 **P0 (Critical)**。
- **🌐 实时联网增强**: 内置联网搜索 (RAG)，自动检索最新的 PoC、Exploit 和 CVSS 评分，解决模型知识滞后问题。
- **📊 SSVC 标准化**: 基于 *Stakeholder-Specific Vulnerability Categorization* 模型，将漏洞分为 P0-P3 四个响应等级。
- **📑 HTML 报告生成**: 一键生成美观、可交互的 HTML 研判报告，支持邮件分发。
- **🔌 模型兼容性**: 完美支持 OpenAI (GPT-4o) 和 DeepSeek (V3) 等兼容 OpenAI 协议的模型。

---

## 🚀 快速开始 (Quick Start)

### 1. 环境准备

确保您的环境安装了 Python 3.8+。

```bash
git clone https://github.com/your-username/vuln-assessment-assistant.git
cd vuln-assessment-assistant

# 创建虚拟环境 (可选但推荐)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 运行应用

```bash
streamlit run app_advanced.py
```

### 3. 系统配置

启动后，在浏览器侧边栏进行配置：

*   **API Key**: 输入您的 OpenAI 或 DeepSeek API Key。
*   **Base URL**: 
    *   DeepSeek: `https://api.deepseek.com`
    *   OpenAI: `https://api.openai.com/v1`
*   **Model**: 
    *   DeepSeek: `deepseek-chat`
    *   OpenAI: `gpt-4o`

---

## 🛠️ 研判标准 (Triage Logic)

本系统遵循以下 **SSVC** 简化决策树：

| 等级 | 标签 | 判定条件 (满足其一) | 响应时效 (SLA) |
| :--- | :--- | :--- | :--- |
| **P0** | **紧急 (Critical)** | ✅ **CISA KEV 命中** <br> ✅ 在野利用 (In the Wild) <br> ✅ 核心资产 + 无需交互 RCE | **24 小时** |
| **P1** | **高危 (High)** | 🔸 需要交互的 RCE <br> 🔸 开发者工具/组件漏洞 <br> 🔸 高危但无公开 PoC | **7 天** |
| **P2** | **中危 (Medium)** | 🔹 特定环境限制 (如仅 Windows) <br> 🔹 需要本地访问权限 | **30 天** |
| **P3** | **低危 (Low)** | ⚪️ 理论漏洞 <br> ⚪️ 难以利用 | **按需** |

---

## 📂 项目结构

```text
├── app_advanced.py      # Streamlit 主程序 (包含核心 Agent 逻辑)
├── template.html        # Jinja2 报告模板 (HTML/CSS)
├── requirements.txt     # 项目依赖
├── README.md            # 项目文档
```

---

## 🖼️ 截图示例

> <img width="2546" height="1245" alt="image" src="https://github.com/user-attachments/assets/efe3aa2c-3bdd-4348-b584-492785da2688" />

---

## 🤝 贡献 (Contributing)
欢迎提交 Issue 和 Pull Request！
1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📄 许可证
Distributed under the MIT License.

