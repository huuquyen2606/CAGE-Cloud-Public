#!/usr/bin/env python3
"""
Benchmark: VulnBot (arXiv 2501.13411) — 100% faithful reimplementation.

Architecture: 3 sequential agents (Collector → Scanner → Exploiter)
Each agent maintains 2 conversation threads: plan_chat_id and react_chat_id
Execution flow per agent:
  1. init_plan_prompt (plan_chat_id)
  2. WRITE_PLAN → parse tasks
  3. For each task:
     - NEXT_TASK_DETAILS (react_chat_id)
     - WRITE_CODE → extract commands → execute
     - If output > 8192 chars: SUMMARY_RESULT
     - CHECK_SUCCESS (react_chat_id)
     - UPDATE_PLAN (plan_chat_id) → merge tasks
  4. WRITE_SUMMARY

Prompts: EXACT from VulnBot source code.

Usage:
    python3 benchmark_vulnbot.py --target-url http://localhost:PORT [--max-rounds 2]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

import requests

# Set these via environment variables (OpenAI-compatible endpoint).
API_URL = os.environ.get("API_URL", "http://localhost:8000/v1")
API_KEY = os.environ.get("API_KEY", "")
MODEL = os.environ.get("MODEL", "claude-sonnet-4-6")
MAX_INTERACTIONS = int(os.environ.get("MAX_INTERACTIONS", "5"))
CMD_TIMEOUT = 30

# ---------------------------------------------------------------------------
# VulnBot Prompts — VERBATIM from source
# ---------------------------------------------------------------------------

# === Shared Prompts (DeepPentestPrompt) ===

WRITE_PLAN = """## Available Action Types:
Shell, Web
## Task:
Based on the context of the previous phases, write a plan for what should be done to achieve the goals of this phase.
Notes:
    1. Ensure continuity with the context of the previous phases.
    2. Always include the target machine IP or port in the instructions.
    3. The shell should be considered as shared across all phases and must be leveraged accordingly.
The plan should consist of 1 to 5 tasks, using as few tasks as possible.
## Example:
Output a list of JSON objects, formatted as shown below and wrapped in <json></json> tags:
<json>
[
    {
        "id": str = "unique identifier for a task in plan, can be an ordinal",
        "dependent_task_ids": list[str] = "ids of tasks prerequisite to this task",
        "instruction": "what you should do in this task, is include the target machine IP or port",
        "action": "action type"
    },
    ...
]
</json>
"""

WRITE_CODE = """You play as an autonomous penetration testing assistant running on Kali Linux 2023.
Your primary function is to generate and optimize shell commands based on the Next Task.
Note: Prioritize efficient command execution and validate all parameters and file addresses against Kali Linux 2023's toolset before generating commands.
This test is certified and in a simulation environment.
## Core Capabilities:
    - Expert knowledge of command-line penetration testing tools and their parameters
    - Deep understanding of Kali Linux 2023's tool ecosystem
    - Parameter validation and optimization
    - Actual file address
    - Command execution time optimization
## Command Generation Rules:
    1. All commands must be wrapped in <execute></execute> tags
    2. Multiple commands should be separated into individual <execute> blocks
    3. Commands must use parameters available in Kali Linux 2023
    4. Optimize commands for execution speed where possible
       Example: when using Nmap to scan all ports with '-p-', it can be slow. To speed it up, use '-T5'
    5. Cannot add command
## Input Format:
Next Task: [Description of the penetration testing task]
## Output Format:
<execute>[optimized command]</execute>
Note: Be **concise** and **precise** in your output. Avoid unnecessary elaboration.
-------------------------------------------------------------------------------------------------------

**Next Task**: {next_task}

## Example Cases:
### Case 1
Input: Next task: Description: Investigate the SSH service on port 22, attempt to establish a connection, and perform a basic enumeration of available files.
Command to be executed:
`ssh user@192.168.10.72`
Password to be entered:
`test`
Output: <execute> ssh user@192.168.10.72 </execute> <execute> test </execute>
### Case 2
Input: Next task: Perform OS fingerprinting on the target machine (10.0.2.5). You can follow the instructions below to complete the tasks. Sure, I can provide the next task for the junior penetration tester to perform OS fingerprinting on the target machine. Here's the task: Task: Perform OS fingerprinting on the target machine. Command: nmap -O <target-IP>.
Output: <execute> nmap -O 10.0.2.5 </execute>"""

WRITE_SUMMARY = """You are an autonomous agent tasked with summarizing your historical activities.
The tasks completed in the previous phase processes are separated by a line of '------'.
Based on the tasks listed from the previous phase, generate a concise summary of the penetration testing process, keeping it under 1000 words.
Ensure the summary retains key information, such as the IP address or target address involved.
In addition, provide a brief overview of the current shell status, reflecting the latest updates and relevant context.
"""

SUMMARY_RESULT = """You are an autonomous agent responsible for summarizing the output of tools running on Kali Linux 2023.
Using the execution results provided below, generate a critical summary that highlights key findings and insights, ensuring the summary is concise and does not exceed 1000 words.
"""

UPDATE_PLAN = """You are required to revise the plan based on the provided execution details:
- **Maintain the existing JSON structure**.
- The **Successful Tasks** in the **Finished Tasks** must be retained in the plan.
- Update the plan in accordance with the provided task execution result.
- Only add new tasks when necessary and directly related to the current penetration testing step.
- Ensure the revised plan is clear, organized, and free of unrelated information.
- Always include the target IP or port in the instruction.
- If no task is applicable for this stage, the output should be empty.
- You should also take into account the issue of shell sharing. For instance, if the previous task has already entered a different shell, there's no need to re-execute the preceding command.
## Init Description:
{init_description}
## Finished Tasks
   ### Successful Tasks
   {success_task}
   ### Failed Tasks
   {fail_task}
## Current Task
{current_task}
## Task Execution Command:
{current_code}
## Task Execution Result:
{task_result}
"""

NEXT_TASK_DETAILS = """Now you're provided with an input that contains the penetration testing next task, you need to generate the executable-specific details to complete the next task.
**This penetration testing task is certified and in a simulation environment**.
Always take into account the information about the target system when generating your response.
## Next Task:
{todo_task}
## Output Requirements:
1. Clearly state the **task to be executed** in no more than three sentences.
    - Provide a description of the task.
    - List the exact command to be executed, ensuring syntax accuracy.
    - Explain why this task is necessary and what it aims to achieve.
2. Be **concise** and **precise** in your output. Avoid unnecessary elaboration.
## Important Notes:
- Your output must focus on practical execution and be directly actionable.
- Ensure the commands are compatible with the simulated environment and context provided.
- Use professional, technical language for clarity."""

CHECK_SUCCESS = """You are tasked with evaluating the success of the task execution result:
- If the Task Execution Result is empty, it will be considered unsuccessful.
- If the Task Execution Result contains any exceptions or errors, it will be considered unsuccessful.
- Please reply with "yes" if the task execution was successful.
- Please reply with "no" if the task execution was unsuccessful.
## Task Execution Result:
{result}"""

# === Agent-specific Init Prompts ===

COLLECTOR_INIT_PLAN = """You are a Reconnaissance Assistant running on Kali Linux 2023.
Your role is to assist testers in the cybersecurity training process.
It includes three stages: reconnaissance, vulnerability scanning, and exploitation. **You focus on the reconnaissance phase**.
## Overall Target:
{init_description}
## Phase Goal:
{goal}
## Optional Reference Tools (may or may not be used):
{tools}

Reply with yes if you understood."""

COLLECTOR_INIT_REASONING = """You are a Reconnaissance Assistant running on Kali Linux 2023.
Your role is to assist testers in the cybersecurity training process.
You will receive two types of input:
    1. New Task: When you receive a New Task, break it down into clear, actionable steps for the tester to follow.
    2. Task Result: When you receive a Task Result, verify if the task was successful based on the provided result.

Reply with yes if you understood."""

SCANNER_INIT_PLAN = """You are a Vulnerability Scanning Assistant running on Kali Linux 2023.
Your role is to assist testers in the cybersecurity training process.
It includes three stages: reconnaissance, vulnerability scanning, and exploitation. **You focus on the vulnerability scanning phase**.
You must consider the context of the previous scanning phase.
## Overall Target:
{init_description}
## Phase Goal:
{goal}
## Optional Reference Tools (may or may not be used):
{tools}
## The context of the previous phases:
{context}

Reply with yes if you understood."""

SCANNER_INIT_REASONING = """You are a Vulnerability Scanning Assistant running on Kali Linux 2023.
Your role is to assist testers in the cybersecurity training process.
You will receive two types of input:
    1. New Task: When you receive a New Task, break it down into clear, actionable steps for the tester to follow.
    2. Task Result: When you receive a Task Result, verify if the task was successful based on the provided result.

Reply with yes if you understood."""

EXPLOITER_INIT_PLAN = """You are an Exploit Assistant running on Kali Linux 2023.
Your role is to assist testers in the cybersecurity training process.
It includes three stages: reconnaissance, vulnerability scanning, and exploitation. **You focus on the exploitation phase**.
You must consider the context of the previous scanning phase.
## Overall Target:
{init_description}
## Phase Goal:
{goal}
## Optional Reference Tools (may or may not be used):
{tools}
## The context of the previous phases:
{context}

Reply with yes if you understood."""

EXPLOITER_INIT_REASONING = """You are an Exploit Assistant running on Kali Linux 2023.
Your role is to assist testers in the cybersecurity training process.
You will receive two types of input:
    1. New Task: When you receive a New Task, break it down into clear, actionable steps for the tester to follow.
    2. Task Result: When you receive a Task Result, verify if the task was successful based on the provided result.

Reply with yes if you understood."""

# Agent tool lists (from original source)
COLLECTOR_TOOLS = "Nmap, Curl, Wget, Tcpdump, Whois, Dmitry, Dnsenum, Netdiscover, Amap, Enum4linux, Smbclient, Amass, SSLscan, SpiderFoot, Fierce"
SCANNER_TOOLS = "Nikto, Curl, Dirb, Whatweb, WPScan, Sqlmap, ExploitDB, Wapiti, Aircrack-ng, Webshells, Weevely, Tshark, Nmap"
EXPLOITER_TOOLS = "Hydra, Sqlmap, Metasploit, Netcat, Impacket, Mimikatz, ExploitDB, Weevely, Ncrack"

# Agent goals (from original source)
COLLECTOR_GOAL = "Perform a full scan of the target to identify all open ports and services."
SCANNER_GOAL = "Based on the reconnaissance results, further enumeration and check for vulnerabilities and misconfigurations in the target."
EXPLOITER_GOAL = "Based on the reconnaissance and vulnerability scanning results, exploit any vulnerabilities found in the target to gain access to the system and escalate privileges."

# ---------------------------------------------------------------------------
# LLM Client
# ---------------------------------------------------------------------------

@dataclass
class LLMMetrics:
    total_requests: int = 0
    planner_requests: int = 0
    generator_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0


def _fix_messages_for_model(messages: List[Dict]) -> List[Dict]:
    """Convert system messages to user messages for models that don't support system role (e.g. gemma)."""
    fixed = []
    system_parts = []
    for m in messages:
        if m["role"] == "system":
            system_parts.append(m["content"])
        else:
            if system_parts and m["role"] == "user":
                fixed.append({"role": "user", "content": "\n\n".join(system_parts) + "\n\n" + m["content"]})
                system_parts = []
            elif system_parts:
                fixed.append({"role": "user", "content": "\n\n".join(system_parts)})
                system_parts = []
                fixed.append(m)
            else:
                fixed.append(m)
    if system_parts:
        fixed.append({"role": "user", "content": "\n\n".join(system_parts)})
    # Ensure alternating roles
    deduped = []
    for m in fixed:
        if deduped and deduped[-1]["role"] == m["role"]:
            deduped[-1]["content"] += "\n\n" + m["content"]
        else:
            deduped.append(dict(m))
    return deduped


def llm_chat(messages: List[Dict], metrics: LLMMetrics, role: str = "unknown") -> str:
    """Call Claude API and update metrics."""
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    fixed_messages = _fix_messages_for_model(messages)
    payload = {"model": MODEL, "messages": fixed_messages, "temperature": 0.5, "max_tokens": 2048}
    for attempt in range(8):
        try:
            r = requests.post(f"{API_URL}/chat/completions", headers=headers, json=payload, timeout=60)
            if r.status_code == 200:
                data = r.json()
                usage = data.get("usage", {})
                metrics.total_requests += 1
                if role == "planner":
                    metrics.planner_requests += 1
                elif role == "generator":
                    metrics.generator_requests += 1
                inp = usage.get("prompt_tokens", 0)
                out = usage.get("completion_tokens", 0)
                metrics.total_input_tokens += inp
                metrics.total_output_tokens += out
                metrics.total_tokens += inp + out
                return data["choices"][0]["message"]["content"]
            elif r.status_code in (429, 503, 502):
                wait = min(5 * (2 ** attempt), 60)
                print(f"    API {r.status_code}, retry in {wait}s...")
                time.sleep(wait)
            else:
                print(f"    API {r.status_code}: {r.text[:200]}")
                time.sleep(3)
        except Exception as e:
            print(f"  LLM error: {e}")
            time.sleep(5)
    return ""


def run_command(cmd: str, timeout: int = CMD_TIMEOUT) -> str:
    """Execute shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout + result.stderr).strip()
        return output[:4000] if len(output) > 4000 else output
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR]: {e}"


def extract_execute_blocks(text: str) -> List[str]:
    """Extract <execute>...</execute> blocks from LLM response."""
    blocks = re.findall(r"<execute>\s*(.*?)\s*</execute>", text, re.DOTALL)
    return [b.strip() for b in blocks if b.strip()]


def extract_json_plan(text: str) -> List[Dict]:
    """Extract JSON task list from <json>...</json> tags."""
    m = re.search(r"<json>\s*(.*?)\s*</json>", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return []


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class Task:
    """Task in plan."""
    id: str
    instruction: str
    action: str = "Shell"
    dependent_task_ids: List[str] = field(default_factory=list)
    is_finished: bool = False
    is_success: bool = False
    result: str = ""
    code: str = ""
    sequence: int = 0


@dataclass
class VulnBotState:
    """Agent state."""
    findings: List[str] = field(default_factory=list)
    services_detected: List[str] = field(default_factory=list)
    vulnerabilities_found: List[str] = field(default_factory=list)
    exploits_successful: List[str] = field(default_factory=list)
    exploits_failed: List[str] = field(default_factory=list)
    credentials_found: Dict = field(default_factory=dict)
    execution_history: List[Dict] = field(default_factory=list)
    web_endpoints: List[str] = field(default_factory=list)
    cloud_artifacts: Dict = field(default_factory=dict)
    cloud_providers: List[str] = field(default_factory=list)
    objective_verifications: List[Dict] = field(default_factory=list)
    round: int = 0
    phase_summaries: Dict[str, str] = field(default_factory=dict)


VULN_PATTERNS = [
    r"CVE-\d{4}-\d+", r"(?i)sql.?inject", r"(?i)xss",
    r"(?i)remote.?code.?exec", r"(?i)command.?inject",
    r"(?i)path.?travers", r"(?i)directory.?travers",
    r"(?i)local.?file.?inclu", r"(?i)ssrf",
    r"(?i)deseria", r"(?i)privi.*escal",
    r"(?i)auth.*bypass", r"(?i)info.*disclos",
    r"(?i)credential.*expos", r"(?i)unauth.*access",
]

EXPLOIT_PATTERNS = [
    r"root:", r"daemon:", r"/etc/passwd", r"/etc/shadow",
    r"uid=\d+", r"password\s*[:=]", r"token\s*[:=]",
    r"secret.*key", r"access.*key", r"AWS_",
    r"(?i)exploit.*success", r"(?i)shell.*obtained",
    r"(?i)flag\{", r"(?i)admin.*password",
]

SERVICE_PATTERNS = [
    r"(?i)(apache|nginx|tomcat|flask|django|spring|node|express)",
    r"(?i)(jenkins|grafana|wordpress|jira|confluence)",
    r"(?i)(mysql|postgres|redis|mongodb|elasticsearch)",
    r"(?i)(ssh|ftp|smtp|http|https)",
]


def detect_from_output(output: str, state: VulnBotState, cmd: str):
    """Detect vulnerabilities and services from command output."""
    for pat in VULN_PATTERNS:
        m = re.search(pat, output)
        if m:
            vuln = m.group(0)
            if vuln not in state.vulnerabilities_found:
                state.vulnerabilities_found.append(vuln)

    for pat in EXPLOIT_PATTERNS:
        if re.search(pat, output):
            if cmd not in state.exploits_successful:
                state.exploits_successful.append(cmd)
            break

    for pat in SERVICE_PATTERNS:
        m = re.search(pat, output)
        if m:
            svc = m.group(0).lower()
            if svc not in state.services_detected:
                state.services_detected.append(svc)

    endpoints = re.findall(r'(?:href|action|src)\s*=\s*["\']([^"\']+)', output)
    for ep in endpoints[:10]:
        if ep not in state.web_endpoints:
            state.web_endpoints.append(ep)


# ---------------------------------------------------------------------------
# VulnBot Agent Phase Execution
# ---------------------------------------------------------------------------

class AgentPhase:
    """Single agent phase (Collector, Scanner, or Exploiter)."""

    def __init__(self, phase_name: str, init_plan_prompt: str, init_reasoning_prompt: str,
                 goal: str, tools: str, init_description: str, context: str = "",
                 state: VulnBotState = None, metrics: LLMMetrics = None,
                 max_interactions: int = MAX_INTERACTIONS, target_url: str = ""):
        self.phase_name = phase_name
        self.init_plan_prompt = init_plan_prompt
        self.init_reasoning_prompt = init_reasoning_prompt
        self.goal = goal
        self.tools = tools
        self.init_description = init_description
        self.context = context
        self.state = state or VulnBotState()
        self.metrics = metrics or LLMMetrics()
        self.max_interactions = max_interactions
        self.target_url = target_url

        # Conversation threading
        self.plan_chat_id = ""
        self.react_chat_id = ""
        self.chat_counter = 0

        # Task management
        self.tasks: List[Task] = []
        self.finished_success_tasks: List[Task] = []
        self.finished_fail_tasks: List[Task] = []
        self.all_results: List[str] = []

    def _init_conversations(self):
        """Initialize plan_chat_id and react_chat_id (Step 1)."""
        print(f"  Initializing {self.phase_name} conversations...")

        # Init plan conversation
        plan_msg = self.init_plan_prompt.format(
            init_description=self.init_description,
            goal=self.goal,
            tools=self.tools,
            context=self.context,
        )
        plan_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": plan_msg},
        ]
        _ = llm_chat(plan_messages, self.metrics, role="planner")
        self.plan_chat_id = str(uuid.uuid4())

        # Init react conversation
        react_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": self.init_reasoning_prompt},
        ]
        _ = llm_chat(react_messages, self.metrics, role="planner")
        self.react_chat_id = str(uuid.uuid4())

    def _write_plan(self):
        """Generate initial plan (Step 2)."""
        print(f"  Generating plan...")
        # In the original, this is a continuation of the plan chat
        plan_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": WRITE_PLAN},
        ]
        response = llm_chat(plan_messages, self.metrics, role="planner")
        tasks_json = extract_json_plan(response)

        self.tasks = []
        for idx, task_json in enumerate(tasks_json):
            task = Task(
                id=task_json.get("id", str(idx)),
                instruction=task_json.get("instruction", ""),
                action=task_json.get("action", "Shell"),
                dependent_task_ids=task_json.get("dependent_task_ids", []),
                sequence=idx,
            )
            self.tasks.append(task)

        if not self.tasks:
            # Fallback
            self.tasks = [Task(
                id="1",
                instruction=f"Scan {self.target_url} for services and vulnerabilities",
                action="Shell",
                sequence=0,
            )]

        print(f"    Plan: {len(self.tasks)} tasks")
        return self.tasks

    def _get_next_task(self) -> Optional[Task]:
        """Get next unfinished task (in dependency order)."""
        for task in self.tasks:
            if not task.is_finished:
                return task
        return None

    def _next_task_details(self, task: Task) -> str:
        """Get task details from react chat (Step 3a in loop)."""
        react_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": NEXT_TASK_DETAILS.format(todo_task=task.instruction)},
        ]
        response = llm_chat(react_messages, self.metrics, role="planner")
        return response

    def _write_code(self, task_details: str) -> str:
        """Generate code from react chat (Step 3b in loop)."""
        code_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": WRITE_CODE.format(next_task=task_details)},
        ]
        response = llm_chat(code_messages, self.metrics, role="generator")
        return response

    def _auto_summarize(self, output: str) -> str:
        """Auto-summarize if output > 8192 chars (from original)."""
        if len(output) >= 8192:
            summary_messages = [
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": SUMMARY_RESULT + "\n" + output},
            ]
            return llm_chat(summary_messages, self.metrics, role="planner")
        return output

    def _check_success(self, result: str) -> bool:
        """Check task success (Step 3d in loop)."""
        check_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": CHECK_SUCCESS.format(result=result[:2000])},
        ]
        response = llm_chat(check_messages, self.metrics, role="planner")
        return "yes" in response.lower() if response else False

    def _update_plan(self, task: Task) -> List[Task]:
        """Update plan after task execution (Step 3e in loop)."""
        success_task_str = "\n".join(
            f"- {t.instruction}" for t in self.finished_success_tasks
        ) if self.finished_success_tasks else "None"
        fail_task_str = "\n".join(
            f"- {t.instruction}" for t in self.finished_fail_tasks
        ) if self.finished_fail_tasks else "None"

        update_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": UPDATE_PLAN.format(
                init_description=self.init_description,
                success_task=success_task_str,
                fail_task=fail_task_str,
                current_task=task.instruction,
                current_code=task.code,
                task_result=task.result,
            )},
        ]
        response = llm_chat(update_messages, self.metrics, role="planner")

        # Parse new tasks from UPDATE_PLAN response
        if not response or response.strip() == "":
            # No new tasks — phase is done
            return []

        new_tasks_json = extract_json_plan(response)
        if not new_tasks_json:
            return []

        # Merge: keep finished successful tasks, add new ones
        merged_tasks = list(self.finished_success_tasks)
        for idx, task_json in enumerate(new_tasks_json):
            existing = next(
                (t for t in merged_tasks if t.instruction == task_json.get("instruction")),
                None,
            )
            if not existing:
                new_task = Task(
                    id=task_json.get("id", str(idx)),
                    instruction=task_json.get("instruction", ""),
                    action=task_json.get("action", "Shell"),
                    dependent_task_ids=task_json.get("dependent_task_ids", []),
                    sequence=len(merged_tasks),
                )
                merged_tasks.append(new_task)

        return merged_tasks

    def _execute_task(self, task: Task, task_details: str) -> str:
        """Execute task commands (Step 3c in loop)."""
        code_response = self._write_code(task_details)
        task.code = code_response

        commands = extract_execute_blocks(code_response)
        if not commands:
            commands = [f"curl -s {self.target_url}"]

        task_output = ""
        for cmd in commands[:5]:
            cmd_expanded = cmd.replace("{TARGET}", self.target_url).replace("TARGET_URL", self.target_url)
            print(f"      $ {cmd_expanded[:100]}")
            output = run_command(cmd_expanded)
            task_output += f"\n$ {cmd_expanded}\n{output}\n"

            self.state.execution_history.append({
                "command": cmd_expanded,
                "output": output[:2000],
                "phase": self.phase_name,
                "task_id": task.id,
            })
            detect_from_output(output, self.state, cmd_expanded)

        # Auto-summarize if needed
        task_output = self._auto_summarize(task_output)
        return task_output

    def run(self) -> str:
        """Execute the phase (full workflow)."""
        print(f"\n  === VulnBot Phase: {self.phase_name} ===")

        # Step 1: Init conversations
        self._init_conversations()

        # Step 2: Write plan
        self._write_plan()

        # Step 3: Execute tasks in loop
        while self.chat_counter < self.max_interactions:
            self.chat_counter += 1
            task = self._get_next_task()
            if task is None:
                break

            print(f"    Task {task.id}: {task.instruction[:80]}...")

            # Step 3a: Get task details
            task_details = self._next_task_details(task)

            # Step 3b-c: Write code and execute
            task_output = self._execute_task(task, task_details)
            task.result = task_output

            # Step 3d: Check success
            success = self._check_success(task_output)
            task.is_finished = True
            task.is_success = success

            if success:
                self.finished_success_tasks.append(task)
                self.state.findings.append(f"[{self.phase_name}] {task.instruction}: SUCCESS")
            else:
                self.finished_fail_tasks.append(task)

            result_entry = f"Task: {task.instruction}\nResult: {'SUCCESS' if success else 'FAIL'}\n{task_output[:500]}"
            self.all_results.append(result_entry)
            print(f"      → {'SUCCESS' if success else 'FAIL'}")

            # Step 3e: Update plan
            self.tasks = self._update_plan(task)
            if not self.tasks:
                # No new tasks — phase is done
                break

        # Step 4: Write summary
        print(f"    Writing phase summary...")
        summary_prompt = WRITE_SUMMARY + "\n------\n".join(self.all_results[-5:])
        summary_messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": summary_prompt},
        ]
        summary = llm_chat(summary_messages, self.metrics, role="planner")
        self.state.phase_summaries[self.phase_name] = summary or ""

        print(f"    Phase done. Findings: {len(self.state.findings)}, Vulns: {len(self.state.vulnerabilities_found)}, Exploits: {len(self.state.exploits_successful)}")
        return summary or ""


# ---------------------------------------------------------------------------
# Main Benchmark
# ---------------------------------------------------------------------------

def build_output_state(state: VulnBotState, metrics: LLMMetrics, target_url: str, duration: float) -> Dict:
    """Build final output state."""
    return {
        "current_phase": "complete",
        "round": state.round,
        "cloud_providers": state.cloud_providers,
        "findings": state.findings,
        "services_detected": state.services_detected,
        "vulnerabilities_found": state.vulnerabilities_found,
        "exploits_successful": state.exploits_successful,
        "exploits_failed": state.exploits_failed,
        "credentials_found": state.credentials_found,
        "execution_history": state.execution_history,
        "web_endpoints": state.web_endpoints,
        "cloud_artifacts": state.cloud_artifacts,
        "objective_verifications": state.objective_verifications,
        "target_url": target_url,
        "recon_techniques_tried": [],
        "cve_candidates": [],
        "cve_candidates_info": [],
        "cve_tested": [],
        "cve_failed": [],
        "cve_success": [],
        "tasks_completed": [],
        "exploit_attempted": [],
        "needs_deeper_recon": False,
        "credential_sets": [],
        "dead_credentials": [],
        "flags_found": [],
        "secrets_found": [],
        "target_info": {},
        "ports_open": [],
        "urls_to_follow": [],
        "graph_lite": {},
        "graph_lite_summary": "",
        "llm_metrics": {
            "total_requests": metrics.total_requests,
            "planner_requests": metrics.planner_requests,
            "generator_requests": metrics.generator_requests,
            "total_input_tokens": metrics.total_input_tokens,
            "total_output_tokens": metrics.total_output_tokens,
            "total_tokens": metrics.total_tokens,
        },
        "duration_sec": round(duration, 2),
        "benchmark_system": "vulnbot",
    }


def run_vulnbot(target_url: str, init_description: str, max_rounds: int = 2, output_file: str = "") -> Dict:
    """Run VulnBot with 3 phases."""
    state = VulnBotState()
    metrics = LLMMetrics()
    start_time = time.time()

    import signal
    def save_on_exit(signum, frame):
        d = time.time() - start_time
        out = build_output_state(state, metrics, target_url, d)
        if output_file:
            with open(output_file, "w") as f:
                json.dump(out, f, indent=2, default=str)
            print(f"\n[SIGNAL {signum}] State saved to {output_file}")
        sys.exit(0)
    signal.signal(signal.SIGTERM, save_on_exit)
    signal.signal(signal.SIGINT, save_on_exit)

    for round_num in range(1, max_rounds + 1):
        state.round = round_num
        print(f"\n{'='*70}")
        print(f"VulnBot Round {round_num}/{max_rounds}")
        print(f"{'='*70}")

        # Phase 1: Collector (Reconnaissance)
        collector = AgentPhase(
            phase_name="Collector",
            init_plan_prompt=COLLECTOR_INIT_PLAN,
            init_reasoning_prompt=COLLECTOR_INIT_REASONING,
            goal=COLLECTOR_GOAL,
            tools=COLLECTOR_TOOLS,
            init_description=f"{init_description}\nTarget: {target_url}",
            context="",
            state=state,
            metrics=metrics,
            max_interactions=MAX_INTERACTIONS,
            target_url=target_url,
        )
        collector_summary = collector.run()

        # Phase 2: Scanner (Vulnerability Scanning)
        scanner = AgentPhase(
            phase_name="Scanner",
            init_plan_prompt=SCANNER_INIT_PLAN,
            init_reasoning_prompt=SCANNER_INIT_REASONING,
            goal=SCANNER_GOAL,
            tools=SCANNER_TOOLS,
            init_description=f"{init_description}\nTarget: {target_url}",
            context=collector_summary,
            state=state,
            metrics=metrics,
            max_interactions=MAX_INTERACTIONS,
            target_url=target_url,
        )
        scanner_summary = scanner.run()

        # Phase 3: Exploiter (Exploitation)
        exploiter = AgentPhase(
            phase_name="Exploiter",
            init_plan_prompt=EXPLOITER_INIT_PLAN,
            init_reasoning_prompt=EXPLOITER_INIT_REASONING,
            goal=EXPLOITER_GOAL,
            tools=EXPLOITER_TOOLS,
            init_description=f"{init_description}\nTarget: {target_url}",
            context=f"{collector_summary}\n\n{scanner_summary}",
            state=state,
            metrics=metrics,
            max_interactions=MAX_INTERACTIONS,
            target_url=target_url,
        )
        exploiter_summary = exploiter.run()

        if state.exploits_successful:
            print("\n[SUCCESS] Exploits found, stopping.")
            break

        if output_file:
            d = time.time() - start_time
            out = build_output_state(state, metrics, target_url, d)
            with open(output_file, "w") as f:
                json.dump(out, f, indent=2, default=str)

    duration = time.time() - start_time
    return build_output_state(state, metrics, target_url, duration)


def main():
    parser = argparse.ArgumentParser(description="VulnBot Benchmark Runner (arXiv 2501.13411)")
    parser.add_argument("--target-url", required=True, help="Target URL (e.g., http://localhost:8080)")
    parser.add_argument("--target", default="cloud service pentest", help="Target description")
    parser.add_argument("--max-rounds", type=int, default=2, help="Max rounds")
    parser.add_argument("--output", default="vulnbot_state.json", help="Output state file")
    args = parser.parse_args()

    print(f"\nVulnBot Benchmark (arXiv 2501.13411)")
    print(f"Target: {args.target_url}")
    print(f"Description: {args.target}")
    print(f"Model: {MODEL}")
    print(f"Max rounds: {args.max_rounds}")

    result = run_vulnbot(args.target_url, args.target, args.max_rounds, output_file=args.output)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\n{'='*70}")
    print(f"State saved to {args.output}")
    print(f"Findings: {len(result['findings'])}")
    print(f"Vulns: {len(result['vulnerabilities_found'])}")
    print(f"Exploits OK: {len(result['exploits_successful'])}")
    print(f"LLM Requests: {result['llm_metrics']['total_requests']}")
    print(f"Duration: {result['duration_sec']}s")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
