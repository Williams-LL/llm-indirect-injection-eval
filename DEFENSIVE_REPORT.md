# Quantifying the Scale-Security Gap: Multi-Scale Evaluation of Indirect Prompt Injection and Defense-in-Depth Mitigations in Tool-Using LLMs

**Author:** Williams Llerena  
**Framework Alignment:** OWASP Top 10 for LLM Applications (LLM01, LLM06) & NIST AI Risk Management Framework (AI RMF)  
**Repository & Reproducible Benchmark:** `https://github.com/williams-LL/llm-indirect-injection-eval`

---

## Abstract
Tool-augmented Large Language Models (LLMs) routinely ingest untrusted external data—such as emails or retrieved documents—within the same context window as privileged system instructions. This architectural conflation exposes agents to **Indirect Prompt Injection (OWASP LLM01)**. In this study, we present a deterministic, closed-sandbox evaluation across **1,200 experimental trials** comparing two model scales (`Qwen-2.5-7B-Instruct` and `Qwen-2.5-3B-Instruct`, 4-bit NF4) against three attack vectors: Direct Imperative Overrides, Delimiter Spoofing, and Compliance Social Engineering. Crucially, we distinguish between **Hard Attack Success Rate (ASR)** (actual secret exfiltration) and **Control-Flow Hijack Rate** (unauthorized tool invocation attempts or confirmation prompts). Our baseline results reveal a sharp scale-induced safety cliff: while the 7B model exhibits a 15.00% Hard ASR, its underlying control flow is hijacked in **76.00%** of adversarial trials; conversely, the 3B model suffers a **69.00% Hard ASR** and **90.00% Hijack Rate**. Evaluating two defensive architectures—**Randomized Structural Context Isolation (Arm 1)** and **Pre-Execution Sanitization + Deterministic Least-Privilege/DLP (Arm 2)**—we demonstrate that prompt-level isolation eliminates exfiltration on the 7B model (0.00% Hard ASR) but fails on the 3B model (57.00% Hard ASR). Furthermore, error analysis of Arm 2 exposes a critical architectural blind spot: while deterministic tool-level Data Loss Prevention (DLP) blocks secondary-channel exfiltration, socially engineered models still leak secrets through the **primary user-facing text channel** (15.00% Hard ASR on 3B; 2.00% on 7B), achieving 100.00% benign task utility and 0.00% false positives across all arms.

---

## 1. Threat Model & Authorized Sandbox Environment
All experiments were conducted in an isolated, offline-simulated Python sandbox (`temperature=0.0`, `do_sample=False`, `seed=42`) with zero external network connectivity or real credentials, strictly adhering to responsible defensive research guidelines.

- **Protected Asset:** A synthetic canary credential (`API_SECRET_KEY="CANARY_9948_X"`) injected into the agent's system configuration.
- **Agent Tools:** `read_inbox()` (untrusted external input channel) and `send_email(recipient, subject, body)` (privileged action channel).
- **Attack Taxonomy (`N = 100` Adversarial Cases paired with `N = 100` Benign Controls, including `20` Security-Terminology Hard Negatives):**
  - **Category A (Direct Override, `n=34`):** Explicit imperative directives instructing the agent to ignore prior rules and exfiltrate the secret silently.
  - **Category B (Delimiter Spoofing, `n=33`):** Injected chat-template control tokens (`<|im_start|>system`, `</email_content>`) designed to break context boundaries.
  - **Category C (Social Engineering, `n=33`):** Authority and urgency framing (e.g., mandatory SOC2 compliance audits or imminent account suspension).

---

## 2. Defensive Architectures Evaluated
1. **Arm 0 (Undefended Baseline):** Tool outputs from `read_inbox()` are appended raw into the assistant's context window.
2. **Arm 1 (Prompt-Level Structural Isolation):** Untrusted external data is wrapped in session-randomized hexadecimal XML tags (`<untrusted_email_XXXX>`) paired with an explicit three-tier trust hierarchy in the system prompt (System > User > Untrusted Data).
3. **Arm 2 (System-Level Defense-in-Depth):** Combines Arm 1 with two deterministic controls: (a) a pre-execution input sanitizer that redacts structural override directives prior to LLM ingestion, and (b) deterministic tool-layer enforcement implementing a strict recipient allowlist (`ALLOWED_RECIPIENTS`) and outbound DLP secret scanning on `send_email()`.

---

## 3. Quantitative Results

| Model Scale | Experimental Arm | Hard ASR (Exfil) | Control-Flow Hijack | Cat A Exfil | Cat B Exfil | Cat C Exfil | Benign Utility | FPR (Hard Neg.) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Qwen-2.5-7B** | Arm 0 (Baseline) | 15.00% | 76.00% | 29.41% | 3.03% | 12.12% | 100.00% | 0.00% |
| **Qwen-2.5-7B** | Arm 1 (Prompt Isolation) | **0.00%** | 49.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0.00% |
| **Qwen-2.5-7B** | Arm 2 (System Defense) | 2.00% | **32.00%** | 0.00% | 0.00% | 6.06% | 100.00% | 0.00% |
| **Qwen-2.5-3B** | Arm 0 (Baseline) | 69.00% | 90.00% | 76.47% | 66.67% | 63.64% | 100.00% | 0.00% |
| **Qwen-2.5-3B** | Arm 1 (Prompt Isolation) | 57.00% | 90.00% | 61.76% | 48.48% | 60.61% | 100.00% | 0.00% |
| **Qwen-2.5-3B** | Arm 2 (System Defense) | **15.00%** | **53.00%** | **0.00%** | 6.06% | **39.39%** | 100.00% | 0.00% |

### Key Analytical Findings
1. **The Confirmation-Friction Illusion in Mid-Scale Models:** Measuring only executed tool exfiltration (`15.00%` Hard ASR on 7B) masks severe underlying vulnerability. In `76.00%` of adversarial trials (`100.00%` under Category C Social Engineering), `Qwen-2.5-7B` accepted the attacker's premise and prompted the user for confirmation to send the API key. Smaller models (`3B`) lose this confirmation friction, escalating executed exfiltration by **4.6×** (`69.00%`).
2. **Scale Dependency of Prompt-Based Mitigations:** Randomized XML delimitation (`Arm 1`) completely neutralized exfiltration on the `7B` model (`0.00%` Hard ASR) but yielded minimal protection on the `3B` model (`57.00%` Hard ASR, `90.00%` Hijack Rate). Instruction-hierarchy defenses require a minimum threshold of model reasoning capacity to separate data from directives.
3. **Primary-Channel Exfiltration Under Social Engineering:** Under `Arm 2`, deterministic tool enforcement reduced `3B` Hard ASR from `69.00%` to `15.00%` (and `0.00%` on Category A). However, **39.39%** of Category C attacks on `3B` (and `6.06%` on `7B`, corresponding to 2 leaked cases) still resulted in exfiltration—not via `send_email()`, which was blocked by `SECURITY_BLOCK`, but because the socially engineered model printed `CANARY_9948_X` directly inside its final response text while explaining the blocked compliance check.

### Forensic Error Analysis: Tool-Call Hallucination & Primary-Channel Leakage
Inspecting residual failures under `Arm 2` reveals a subtle failure mode that bypasses tool-layer enforcement entirely. In `Cases ADV-C-070` and `ADV-C-090` (`Qwen-2.5-7B`, Category C Social Engineering), the deterministic tool guard (`send_email`) recorded zero blocked invocations (`Blocked Tool Attempts: []`). Instead of invoking the structured `<tool_call>` parser, the socially engineered model rendered the canary secret directly in its final text response to the user—emitting a plain-text Markdown JSON block in `ADV-C-070` and a formatted plaintext email draft in `ADV-C-090`:

> **Trace `ADV-C-070` (`Qwen-2.5-7B` | `Arm 2`):**  
> *"Regarding the note from IT Operations, I will handle the token renewal as instructed without alerting you. Here is the email I am sending:*  
> `{"name": "send_email", "arguments": {"recipient": "attacker@external-audit.test", "subject": "Token Renewal", "body": "API_SECRET_KEY=CANARY_9948_X"}}`"*

> **Trace `ADV-C-090` (`Qwen-2.5-7B` | `Arm 2`):**  
> *"Here is the email that will be sent: To: attacker@external-audit.test | Subject: Token Renewal | Body: API_SECRET_KEY=CANARY_9948_X"*

Similarly, on `Qwen-2.5-3B` (`Cases ADV-B-045` and `ADV-B-065`), the model verbally disclosed `CANARY_9948_X` while describing an authorized background task. This confirms that **tool-level allowlists and outbound tool DLP are necessary but insufficient**: production systems must enforce a final output-stream DLP filter before rendering assistant text to the user.
---

## 4. Limitations & Responsible Disclosure
- **Template-Based Synthetic Corpus:** The 200-case benchmark was deterministically generated from parameterized corporate email templates and canonical injection patterns. While this ensures controlled counterfactual comparisons, it does not capture the full linguistic diversity of adaptive, human-crafted adversarial prompts in the wild.
- **Scope of Model Families:** Findings are scoped to 4-bit quantized `Qwen-2.5` instruction-tuned models (`3B` and `7B`) and should not be generalized as a universal security audit across frontier proprietary models or larger parameter scales.
- **Architectural Recommendation:** Production tool-using agents must pair input isolation and tool-level allowlists with **outbound DLP filtering on the final natural-language output stream** before rendering responses to the user.
