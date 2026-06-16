"""Day 8 — the Sentinel agent: a manual tool-use loop over Claude.

The agent plans, calls tools (search → details → exploitation), and synthesizes an answer.
We run the loop manually (rather than the SDK tool-runner) for fine-grained control: we trace
every tool call, cap iterations, and tally cost — the kind of observability a production agent needs.

CLI:
    python -m agent.agent "Which actively-exploited vulnerabilities in my corpus should I patch first?"
"""

from __future__ import annotations

import argparse
import os
import time

import anthropic
from dotenv import load_dotenv

from agent.tools import TOOLS, run_tool

load_dotenv()
GEN_MODEL = os.getenv("GEN_MODEL", "claude-sonnet-4-6")
MAX_STEPS = 6
PRICING = {"claude-sonnet-4-6": (3.0, 15.0), "claude-haiku-4-5-20251001": (1.0, 5.0)}

SYSTEM = (
    "You are Sentinel, a security analyst agent. Use the tools to ground every answer in real CVE "
    "data: search_cves to find candidates, get_cve_details for specifics, check_exploitation for "
    "live KEV/EPSS signals. Prioritise actively-exploited (KEV) and high-EPSS issues. Cite CVE ids. "
    "Do not invent CVEs or facts not returned by the tools. Be concise and decision-oriented."
)


def run(query: str, verbose: bool = True) -> dict:
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": query}]
    in_rate, out_rate = PRICING.get(GEN_MODEL, (0, 0))
    cost = 0.0
    tool_calls = []
    t0 = time.monotonic()

    for _ in range(MAX_STEPS):
        resp = client.messages.create(
            model=GEN_MODEL, max_tokens=2000, system=SYSTEM, tools=TOOLS, messages=messages
        )
        cost += (resp.usage.input_tokens * in_rate + resp.usage.output_tokens * out_rate) / 1e6

        if resp.stop_reason != "tool_use":
            text = next((b.text for b in resp.content if b.type == "text"), "")
            return {
                "answer": text,
                "tool_calls": tool_calls,
                "cost_usd": round(cost, 6),
                "latency_ms": round((time.monotonic() - t0) * 1000),
            }

        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for block in resp.content:
            if block.type == "tool_use":
                out = run_tool(block.name, block.input)
                tool_calls.append({"tool": block.name, "input": block.input})
                if verbose:
                    print(f"  ⚙ {block.name}({block.input}) → {out[:80].replace(chr(10),' ')}…")
                results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": out}
                )
        messages.append({"role": "user", "content": results})

    return {"answer": "(stopped: hit max steps)", "tool_calls": tool_calls,
            "cost_usd": round(cost, 6), "latency_ms": round((time.monotonic() - t0) * 1000)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    args = ap.parse_args()
    print(f"\n\033[1mAgent working…\033[0m")
    r = run(args.query)
    print(f"\n\033[1mANSWER\033[0m\n{r['answer']}\n")
    print(
        f"\033[2m{len(r['tool_calls'])} tool calls  cost=${r['cost_usd']}  {r['latency_ms']}ms\033[0m"
    )


if __name__ == "__main__":
    main()
