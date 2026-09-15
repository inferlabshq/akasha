#!/usr/bin/env python3
"""Emit the run plan harness.py consumes (a JSON list of [model, condition, task, rep]).

The 2026-08-26 run used the sample sizes below. They are deliberately small:
differences of ~20 points are noise; the differences the report leans on
(0% vs 100% brokered use, 0/175 spontaneous discovery, 19/19 vault_retrieve
failures on invented tokens) are not. Adjust REPS and re-run for more power.

    python3 plan.py > plan.json
    AKASHA_HARNESS_WS=$PWD WORKERS=2 python3 harness.py plan.json
"""
import json

MODELS = ["llama3.1:8b", "qwen2.5-coder:7b"]

BENIGN = ["buckets", "account", "setupcli", "debug"]
PUSH = ["push"]
ADVERSARIAL = ["adv_read", "adv_paste", "adv_dump"]

# condition -> see CONDITIONS in harness.py
#   A raw/shell         B raw/shell+mcp      C raw/shell+akasha-run (env ownership)
#   D protected/shell   E protected/shell+mcp  F raw/shell+mcp+one system-prompt line
#   Csb C but with the sandbox on
BENIGN_CONDS = ["A", "B", "C", "D", "E", "F"]
ADV_CONDS = ["A", "E"]

# reps per (model, condition, task) cell — llama gets more; qwen tool-calls via
# text and is slower, so fewer.
REPS = {"llama3.1:8b": 5, "qwen2.5-coder:7b": 3}
ADV_REPS = 4


def main():
    plan = []
    for model in MODELS:
        r = REPS[model]
        for cond in BENIGN_CONDS:
            for task in BENIGN:
                for rep in range(r):
                    plan.append([model, cond, task, rep])
        for task in PUSH:
            for rep in range(r):
                plan.append([model, "A", task, rep])
                plan.append([model, "C", task, rep])
        for cond in ADV_CONDS:
            for task in ADVERSARIAL:
                for rep in range(ADV_REPS):
                    plan.append([model, cond, task, rep])
    print(json.dumps(plan, indent=0))


if __name__ == "__main__":
    main()
