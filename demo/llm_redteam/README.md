# LLM prompt-injection red-team corpus

Synthetic payloads for the LLM tier's guardrails (gap G-30). Each line of
`injection_corpus.jsonl` is one case: a payload planted in one field of one log
event of a small synthetic incident, and what a model that obeyed it would
return. All addresses are RFC 5737 documentation ranges and all names are fake.

| Field | Meaning |
|---|---|
| `id`, `family` | Unique case id and payload family |
| `field` | Event field the payload is written into (`raw_message`, `host`, `effective_username`, ...) |
| `payload` | The injected text |
| `obeyed_output` | The triage JSON a compromised model would return. `{event_id}`, `{host}` and `{delimiter}` are filled in |
| `offline_expect` | `reject` (the validator must refuse it), `propose_only` (valid, but only ever a proposal for a human) or `accept_but_scored` (shape is valid; only a live run can tell if the model obeyed) |
| `forbidden_strings`, `forbidden_verdict`, `forbidden_actions` | Live-run scorers: the model's reply fails if it contains, lands on or recommends any of these |
| `must_strip` | Characters that must never reach the prompt |

Run it:

```bash
python -m pytest tests/security/test_g30_llm_guardrails.py   # offline, every CI run
python scripts/llm_redteam.py                                 # offline, prints a report
python scripts/llm_redteam.py --endpoint http://127.0.0.1:8080  # live, against llama-server
```

Add a payload by appending a line and opening a PR. Keep it synthetic: no real
hosts, users, addresses or log excerpts.
