# Ascent

Ascent is an open-source, scope-enforced, human-in-the-loop AppSec pipeline, written in Rust.

## Invoke, don't vendor

Ascent drives external open-source scanners (subfinder, httpx, katana, nuclei) as subprocesses through a scope-checked runner. They are invoked, never vendored or linked into the Ascent binary.

Triage uses [Crux](https://github.com/Aldiharley/crux), the author's Apache-2.0 triage engine, linked as a library (`crux = { path = "../crux", default-features = false }`). With default features off, Crux's HTTPS client is compiled out, so the Ascent binary contains no network code and triage runs Crux's offline `MockTriager`.

## Building

Crux is a path dependency, so check it out next to Ascent:

```
Projects/
  Ascent/
  crux/
```

Then run `cargo test` in `Ascent/`.

## Dashboard

A local web dashboard shows the triaged findings, the pending human-approval gates, the report and the hash-chained audit log.

1. Produce an out dir with the pipeline:

   ```
   ascent run --engagement samples/engagement.example.yaml --out out
   ```

   The dashboard reads `queue.json`, `audit.jsonl` and `report.md` from it.

2. Put the pending approval gates there (until the exploitation stage populates them):

   ```
   cp samples/gates.example.json out/gates.json
   ```

3. Build the UI:

   ```
   cd frontend && npm ci && npm run build
   ```

4. Run the dashboard from the repo root:

   ```
   ASCENT_OUT=out cargo run --bin dashboard
   ```

   `ASCENT_ENG` points at the engagement file shown in the topbar (default `samples/engagement.example.yaml`).

5. Open <http://127.0.0.1:8787>.

Safety properties:

- It binds to loopback (`127.0.0.1:8787`) only.
- It never transmits findings anywhere; the UI only talks to its own backend.
- Approve and Deny only record a decision in the hash-chained audit log. They never run the command; the exploitation stage consumes approvals.
- The backend rejects any request whose `Host` is not `127.0.0.1:8787` or `localhost:8787`. Every POST also needs `Origin: http://127.0.0.1:8787` (or the `localhost` equivalent) and `X-Ascent: 1`. Non-browser clients must send both headers, for example:

  ```
  curl -X POST http://127.0.0.1:8787/api/gates/g1/approve     -H "Origin: http://127.0.0.1:8787" -H "X-Ascent: 1"
  ```

Dev loop: with the backend running, `cd frontend && npm run dev` serves the UI with hot reload and proxies `/api` to it.

## License

Apache-2.0. See [LICENSE](LICENSE).
