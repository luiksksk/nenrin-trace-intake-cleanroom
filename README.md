# Independent NENRIN TRACE intake verifier

A clean-room implementation of section 2 of `nenrin-trace-bind-v0/SPEC.md`, written from that specification without consulting the JS, Python, or Go verifiers.

It reads TSUNAGI's batch input (`[{"name": ..., "bundle": ...}]`) and writes verdict signatures keyed by case name. It uses only Node.js built-ins and requires Node.js 18 or newer.

```sh
node trace_intake.mjs batch.json results.json
```

The repository is registered for the `nenrin-trace-intake-v0` corpus. A green TSUNAGI result establishes agreement on that corpus only; it does not establish correctness for other inputs.

## License

MIT. See [LICENSE](LICENSE).
