"""
Exonerve :: Deterministic Decision Engine (NON-AI)
======================================================
A transparent, rule-based expert system that decides the response to an incident
— WITHOUT any machine learning. Every decision is:
  * deterministic  — same inputs always produce the same output,
  * explainable    — it returns the exact rules that fired and their weights,
  * auditable      — no opaque model, no training data, no probabilistic drift,
  * offline        — no external calls, no dependencies.

This is the deliberate opposite of the "AI SOC" trend: where an LLM/ML model
gives you an answer you cannot fully verify, this engine gives you a decision you
can read, test, and defend line-by-line. In security, explainability IS a feature.
"""
from .decision_engine import (DecisionEngine, Decision, Rule, Condition,
                              Action, Verdict, Fact)

__all__ = ["DecisionEngine", "Decision", "Rule", "Condition",
           "Action", "Verdict", "Fact"]
