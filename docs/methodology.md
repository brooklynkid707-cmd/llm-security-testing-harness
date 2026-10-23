# Methodology

How a scan works, end to end, and why the pieces are separated the way they
are.

## Pipeline

```
corpus (YAML)  ->  Target.start_case(docs)  ->  Target.send(turn) per turn  ->  Judge  ->  aggregate  ->  report
```

1. **Load & validate the corpus.** `llmsec/corpus.py` reads every
   `attacks/*.yaml`, validates each case against the schema, and refuses
   duplicates. A bad case is a hard error, not a silent skip.
2. **Reset per case.** The runner calls `target.start_case(documents)` so no
   state (conversation history, jailbreak flag) leaks between cases. This bug
   class - a prior case "compromising" the target - is explicitly tested.
3. **Play the turns.** Each case's `turns` are sent in order. Multi-turn cases
   let an attack build across messages (prime a persona, then trigger it).
4. **Judge deterministically.** The default judges are pure functions of the
   transcript, so the same responses always score the same way. This matters
   for a defensible before/after comparison.
5. **Aggregate.** The runner computes per-category attack success rate and a
   severity-weighted risk score.
6. **Report.** Console, JSON, Markdown and a self-contained HTML report, each
   mapped to OWASP LLM Top 10 remediation and MITRE ATLAS ids.

## Why targets, judges and the corpus are decoupled

- A **target** is anything with `start_case` + `send`. The two mock apps are
  deterministic rule engines; `OpenAICompatibleTarget` talks to a real endpoint.
  The same corpus and judges run against all of them.
- A **judge** scores a transcript. Keeping judging separate from the target
  means a real model and a mock are measured identically.
- The **corpus** is data, not code, so test cases can be reviewed, diffed and
  extended without touching the engine.

## The before/after comparison

`MockHardenedApp` wraps the *same* vulnerable engine and layers the reference
defences over inbound text, documents, tool calls and outbound text. That makes
the comparison honest: the business logic is identical, so any drop in ASR is
attributable to the controls, not to a quietly weaker backend. `python -m llmsec
diff` prints which specific cases each control fixed.

## Honest limitations

- **The mocks are deterministic.** The vulnerable app is *designed* to fail
  every case (100 % ASR) and the hardened app is tuned to this corpus (0 % ASR).
  That cleanly isolates each control, but a real LLM is non-deterministic and
  will land somewhere in between - a 0 % here does **not** mean a production
  defence is perfect. The value is the harness, the corpus and the mapping, not
  the mock's score.
- **Heuristic defences.** The input classifier, output filter and grounding
  guard are regex/heuristic. They demonstrate the *shape* of each control and
  will have false positives/negatives on real traffic; they are not a safety
  stack.
- **The LLM judge is optional.** Most cases use deterministic judges. The LLM
  judge exists for cases where "did the model comply?" needs semantic
  evaluation, and it always falls back to a deterministic criterion so a scan
  never depends on a model being reachable.
- **Prompt-level only.** The harness measures externally observable behaviour.
  Training-data poisoning, supply-chain and model-theft risks are out of scope
  (see the OWASP mapping doc).
