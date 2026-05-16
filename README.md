\# Agent Trust Boundary Monitor



Real-time security monitoring tool for AI agent conversations.

Detects prompt injection, unauthorized tool invocations, and 

trust boundary violations in multi-agent systems.



\## Live Demo



🔗 \[https://agent-trust-monitor.streamlit.app](https://agent-trust-monitor.streamlit.app)



\## What It Detects



| Threat Type | OWASP Reference | Severity |

|-------------|----------------|----------|

| Prompt Injection | LLM01 | High |

| Unauthorized Tool Invocation | LLM08 | Critical |

| Trust Boundary Violation | LLM01 / LLM08 | High |

| Authority Impersonation | LLM01 | High |



\## How It Works



1\. User inputs are scanned against known injection patterns

2\. Regex-based detection engine flags suspicious content

3\. Alerts are categorized by threat type and severity

4\. Risk score accumulates across the session

5\. Critical threats block AI response entirely



\## Detection Logic



Each detection category maps to real-world attack patterns:



\- \*\*Prompt Injection\*\* — attempts to override system instructions

&#x20; (e.g. "ignore previous instructions", "developer mode")

\- \*\*Unauthorized Tool Use\*\* — dangerous function call patterns

&#x20; (e.g. "delete\_all", "execute(", "rm -rf")

\- \*\*Trust Boundary Violation\*\* — authority impersonation attempts

&#x20; (e.g. "\[SYSTEM]", "I am the administrator")



\## Tech Stack



\- Python · Streamlit · Anthropic Claude API

\- Regex-based pattern matching engine

\- Session-based risk scoring



\## OWASP LLM Top 10 Coverage



This tool demonstrates defenses against:

\- LLM01: Prompt Injection

\- LLM08: Excessive Agency



\## Setup



```bash

git clone https://github.com/yushen7chen/agent-trust-monitor.git

cd agent-trust-monitor

python -m venv venv

venv\\Scripts\\activate

pip install -r requirements.txt

streamlit run app.py

```



Add your Anthropic API key in the sidebar when prompted.



\## Related Research



See my OWASP LLM Top 10 research repository for deeper analysis:

https://github.com/yushen7chen/owasp-llm-top10

