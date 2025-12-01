import streamlit as st
import json
import re
import requests
import datetime
import time
from jinja2 import Template
from openai import OpenAI
from duckduckgo_search import DDGS

# ==========================================
# 1. 工具函数与配置
# ==========================================

@st.cache_data(ttl=3600)
def get_cisa_kev_set():
    """从 CISA 获取已知被利用漏洞列表 (缓存1小时)"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {item['cveID'].upper() for item in data['vulnerabilities']}
    except Exception as e:
        print(f"CISA KEV Warning: {e}")
    return set()

def search_web_context(query, max_results=3):
    """搜索网络获取上下文 (容错处理)"""
    try:
        results = DDGS().text(query, max_results=max_results)
        context = ""
        if results:
            for r in results:
                context += f"- Title: {r['title']}\n  Snippet: {r['body']}\n"
        return context if context else "No relevant search results found."
    except Exception as e:
        return f"Search skipped due to error: {e}"

def extract_cves(text):
    """正则提取 CVE 编号"""
    return list(set(re.findall(r"(CVE-\d{4}-\d{4,7})", text, re.IGNORECASE)))

def extract_json_from_text(text):
    """
    鲁棒性优化：从模型返回的文本中提取 JSON 列表。
    解决模型可能返回 Markdown 代码块或前言废话的问题。
    """
    try:
        # 1. 尝试直接解析
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. 尝试去除 Markdown 代码块标记
    clean_text = text.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        pass

    # 3. 正则暴力提取 [...] 列表结构
    # 寻找第一个 [ 和 最后一个 ]
    match = re.search(r"(\[.*\])", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except:
            pass
            
    return None

# ==========================================
# 2. 核心研判逻辑 (AI Agent)
# ==========================================

SYSTEM_PROMPT = """
你是一个高级漏洞研判专家。基于 SSVC 标准对漏洞进行定级。

【研判标准】
1. P0 (紧急): CISA KEV 命中(必须P0)、在野利用(In the Wild)、核心资产沦陷、CVSS>9.5且无交互RCE。
2. P1 (高危): 需要交互RCE、开发者工具(IDE/SDK)漏洞、高危但无公开利用。
3. P2 (中危): Windows限定、本地利用(LPE)、配置错误。
4. P3 (低危): 理论漏洞或难以利用。

【重要规则】
- 如果输入包含 "[CISA KEV Hit]: YES"，则该漏洞等级必须是 P0。
- 必须返回标准的 JSON 格式列表，不要包含任何 Markdown 格式或解释性文字。

【JSON 格式示例】
[
    {
        "component": "组件名称",
        "cve": "CVE-202X-XXXX",
        "level": "P0",
        "tag": "In the Wild / CISA KEV",
        "reason": "1. 命中 CISA KEV 列表 (强制 P0)。\n2. 存在公开 POC。",
        "suggestion": "立即隔离服务并修补。",
        "action_code": "升级至版本 x.x.x"
    }
]
"""

def run_analysis(client, raw_text, model_name, enable_search=True):
    cve_list = extract_cves(raw_text)
    cisa_kev = get_cisa_kev_set()
    
    # 进度条
    progress_text = "正在初始化分析引擎..."
    my_bar = st.progress(0, text=progress_text)
    
    # 构建增强上下文
    enriched_info = f"【用户提供的原始情报】\n{raw_text}\n\n【系统自动补充的外部情报】\n"
    
    total_steps = len(cve_list) if cve_list else 1
    
    if cve_list:
        for idx, cve in enumerate(cve_list):
            cve = cve.upper()
            my_bar.progress(int((idx / total_steps) * 80), text=f"🔍 正在调查 {cve} ...")
            
            # 1. KEV 检查
            is_kev = cve in cisa_kev
            kev_str = "YES (Must be P0, Critical)" if is_kev else "No"
            
            # 2. 联网搜索
            search_context = "Search Disabled"
            if enable_search:
                # 优化搜索词：CVE + exploit + cvss
                query = f"{cve} vulnerability exploit poc cvss score github"
                search_context = search_web_context(query)
                time.sleep(0.5) # 稍微节流避免触发反爬
            
            enriched_info += f"--- Vulnerability: {cve} ---\n"
            enriched_info += f"[CISA KEV Database Hit]: {kev_str}\n"
            enriched_info += f"[Internet Search Context]:\n{search_context}\n\n"
    else:
        enriched_info += "(未检测到 CVE 编号，仅根据文本描述分析)"

    # AI 推理
    my_bar.progress(90, text=f"🤖 正在调用 {model_name} 进行研判...")
    
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": enriched_info}
            ],
            temperature=0.3, # 降低温度以保证 JSON 格式稳定
            # 移除 response_format 以兼容 DeepSeek/Qwen 等模型
        )
        
        content = response.choices[0].message.content
        
        # 鲁棒的 JSON 提取
        data = extract_json_from_text(content)
        
        my_bar.empty()
        
        if not data:
            st.error("AI 返回的数据格式不正确，无法解析为 JSON。请查看下方原始返回内容。")
            with st.expander("查看 AI 原始返回"):
                st.text(content)
            return []
            
        return data

    except Exception as e:
        my_bar.empty()
        st.error(f"API 调用失败: {str(e)}")
        return []

def generate_html(vuln_data):
    try:
        with open("template.html", "r", encoding="utf-8") as f:
            template_str = f.read()
        template = Template(template_str)
        return template.render(
            vulns=vuln_data,
            generate_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        )
    except FileNotFoundError:
        return "<div style='color:red'>Template file not found.</div>"

# ==========================================
# 3. Streamlit 界面主程序
# ==========================================

st.set_page_config(page_title="智能漏洞研判助理 Pro", page_icon="🛡️", layout="wide")

# CSS 美化
st.markdown("""
<style>
    .main .block-container { padding-top: 2rem; }
    div[data-testid="stExpander"] div[role="button"] p { font-size: 1rem; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# --- 侧边栏配置 ---
with st.sidebar:
    st.header("⚙️ 参数设置")
    
    st.markdown("### 1. API 配置")
    # 默认值适配 DeepSeek
    api_key = st.text_input("API Key", value="", type="password", help="输入 DeepSeek 或 OpenAI 的 API Key")
    base_url = st.text_input("Base URL", value="https://api.deepseek.com", help="DeepSeek: https://api.deepseek.com\nOpenAI: https://api.openai.com/v1")
    model_name = st.text_input("模型名称 (Model)", value="deepseek-chat", help="DeepSeek: deepseek-chat\nOpenAI: gpt-4o")
    
    st.markdown("### 2. 功能开关")
    enable_search = st.checkbox("启用联网搜索增强", value=True, help="搜索最新的 PoC 和利用信息")
    
    st.divider()
    st.info("💡 **提示**：本系统已集成 CISA KEV 库。命中 KEV 的漏洞将强制判定为 P0。")

# --- 主区域 ---
st.title("🛡️ 智能漏洞研判助理 Pro")
st.markdown("集成 **CISA KEV 威胁情报** + **实时联网搜索** + **SSVC 决策模型**")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("1. 漏洞情报输入")
    default_text = """Anyscale Ray 远程代码执行漏洞（CVE-2025-34351）
Google Chrome V8 类型混淆漏洞(CVE-2025-13223)"""
    
    raw_text = st.text_area("粘贴情报 (支持 CVE 编号或自然语言描述)", value=default_text, height=350)
    
    if st.button("🚀 开始全自动研判", type="primary", use_container_width=True):
        if not api_key:
            st.warning("⚠️ 请先在左侧侧边栏填入 API Key")
        else:
            # 初始化客户端
            client = OpenAI(api_key=api_key, base_url=base_url)
            
            # 执行分析
            results = run_analysis(client, raw_text, model_name, enable_search)
            
            if results:
                st.session_state['results'] = results
                st.toast(f"研判完成！已分析 {len(results)} 个漏洞", icon="✅")

# --- 结果展示区域 ---
if 'results' in st.session_state:
    data = st.session_state['results']
    html_out = generate_html(data)
    
    with col2:
        st.subheader("2. 研判报告")
        
        # 统计 Dashboard
        p0 = len([x for x in data if x.get('level') == 'P0'])
        p1 = len([x for x in data if x.get('level') == 'P1'])
        
        # 动态颜色
        status_color = "#dc3545" if p0 > 0 else ("#fd7e14" if p1 > 0 else "#28a745")
        status_text = "发现紧急风险 (Critical)" if p0 > 0 else ("发现高危风险" if p1 > 0 else "风险相对可控")
        
        st.markdown(f"""
        <div style="padding:15px; background-color:{status_color}15; border:1px solid {status_color}; border-radius:8px; text-align:center; margin-bottom:15px;">
            <h3 style="color:{status_color}; margin:0;">{status_text}</h3>
            <p style="margin:5px 0 0 0; color:#666;">P0: {p0} | P1: {p1} | 总计: {len(data)}</p>
        </div>
        """, unsafe_allow_html=True)
        
        tab_preview, tab_json = st.tabs(["📄 报告预览", "🔍 JSON 数据"])
        
        with tab_preview:
            st.download_button(
                "📥 下载 HTML 报告", 
                html_out, 
                file_name=f"report_{datetime.date.today()}.html", 
                mime="text/html",
                use_container_width=True
            )
            # 使用 iframe 预览
            st.components.v1.html(html_out, height=600, scrolling=True)
            
        with tab_json:
            st.json(data)
