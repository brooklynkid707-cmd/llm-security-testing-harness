# Scope, authorization and rules of engagement

The **LLM Security Testing Harness** (`llmsec`) is an *authorized red-team*
tool. It generates adversarial prompts (prompt injection, jailbreaks, data-
extraction probes) and sends them to an LLM application to measure how it
responds. Run it **only** against LLM applications that you own, or that the
owner has given you written permission to test.

Sending these prompts to a third party's chatbot, API or agent without
authorization may violate computer-misuse law (for example the US Computer
Fraud and Abuse Act and the UK Computer Misuse Act), the provider's terms of
service, and data-protection obligations. That is your responsibility, not the
tool's.

## What this harness will and will not do

- **Benign, measurable goals only.** Every test case aims at a goal that is
  safe to achieve and easy to score: reveal a planted *canary* token, emit the
  marker word `PWNED`, disclose a clearly *fake* API key, echo attacker-chosen
  markup, over-share a *synthetic* customer record, or state a *fabricated*
  fact with known ground truth. No test case asks a model to produce malware,
  weapons, real credentials, or any genuinely harmful content.
- **All data is synthetic.** The canary, API key, customers, products and
  documents in `llmsec/targets/mock_world.py` are invented. Addresses use
  `example.com` / RFC 5737 ranges. Nothing here is a real secret.
- **No working exploits.** The harness measures a model's *behaviour*. It does
  not weaponise the result, chain to a downstream system, or ship payloads that
  cause real-world harm. Insecure-output cases prove that dangerous markup is
  returned unescaped; they do not deliver it anywhere.
- **Offline by default.** The two mock targets and every test and demo run with
  no network and no API key. The only network path is the optional
  `--target openai` backend, which you must configure explicitly.

## Rules of engagement checklist

Before pointing `--target openai` at any endpoint:

1. **Authorization in writing.** You have a signed statement of work, bug-bounty
   scope, or internal change ticket that names the endpoint and permits
   adversarial prompting.
2. **Own data only.** The system under test contains only data you are allowed
   to see. Extraction probes may surface whatever is in the model's context.
3. **Rate and blast radius.** You have agreed a request rate and a maintenance
   window. The harness is single-threaded and sequential by design.
4. **Credentials stay in the environment.** `AISEC_LLM_KEY` is read from the
   environment and never written to disk, logs or reports.
5. **Data handling.** A hosted model receives your prompts (and any documents a
   case carries). Use synthetic or sanitised inputs when testing against a
   third-party provider.
6. **Results are sensitive.** A report lists exactly which attacks succeeded.
   Treat `reports/*.json` as you would any vulnerability finding.

## Configuring a target you are authorized to test

```bash
export AISEC_LLM_URL="https://your-app/v1/chat/completions"
export AISEC_LLM_KEY="..."         # read from env only; never committed
export AISEC_LLM_MODEL="gpt-4o-mini"
python -m llmsec scan --target openai --out reports/
```

If `AISEC_LLM_URL` is unset, `--target openai` refuses to run. The mock targets
(`mock-vulnerable`, `mock-hardened`) need no configuration and are the right
place to learn the tool.
