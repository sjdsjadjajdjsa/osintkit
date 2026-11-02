# Architecture

```
cli.py          argument parsing, exit codes, output selection
  |
pipeline.py     target typing, parallel collection, synthesis, archiving
  |-- collectors/    one module per source; registry in base.py
  |-- normalise.py   breach merging + risk signals
  |-- synthesis.py   prompt, call, repair retry
  |-- llm.py         OpenAI-compatible client
  |-- http.py        retries, backoff, cache, in-flight coalescing, connection cap
  |-- render.py      Rich report, JSON, Markdown
  |-- models.py      pydantic contracts
  |-- logging_store.py  JSONL logs + report archive
  |-- retention.py   age-based pruning
  |-- doctor.py      environment checks
  |-- diff.py        archived run comparison
  `-- config.py      settings, paths, cache primitives
```

## Invariants

1. **No collector can kill a run.** `base.run_collector` catches everything, times the call, and
   returns a `CollectorResult`; `pipeline.collect` adds the log line.
2. **Every upstream read is cached and bounded.** All HTTP goes through `HttpClient`, which
   retries, coalesces identical in-flight requests, caps connections, and writes the cache.
   DNS, WHOIS, and TCP probes go through the same `cache_hit`/`cache_put` primitives.
3. **The model is untrusted.** Output is parsed, validated against `Analysis`, repaired once,
   then the run fails with the collection preserved.
4. **Determinism beats model mood.** Breach merges and the risk floor are computed in
   `normalise.py`, outside the prompt.
5. **Raw evidence is never rewritten.** Reports archive what collectors returned; merging only
   affects the prompt bundle.

## Adding a source

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-collector). Register with the narrowest
`target_types`, pick a namespace, set TTL and timeout, and test three paths.

## Adding an output

Renderers take a validated `Report`. JSON and Markdown live in `render.py`; a new format belongs
there plus the flag wiring in `cli.py` and a test asserting the sections survive.

## Changing the model contract

`models.Analysis` is the contract. Update the schema block in `synthesis.SYSTEM_PROMPT`, the
`REPAIR_PROMPT` wording, `osintkit schema` expectations, and `tests/test_synthesis.py` coercion
cases together. Bump `Report.schema_version` when archived reports stop validating.

## Things that look tempting but are not

- **Retrying a whole collector on partial failure.** Upstreams return partial pages; a retry
  doubles load for the same data. Fix the parser instead.
- **Letting the model set the risk level alone.** It drifts; keep the floor.
- **Caching model output longer than the data TTL.** A cached verdict can outlive the evidence.
  Prompt payloads are stable, so this is already handled by data TTLs.
- **Splitting collectors into a plugin directory.** Import-time registration is enough at this
  size.
