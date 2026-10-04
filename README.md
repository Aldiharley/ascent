# Ascent

Ascent is an open-source, scope-enforced, human-in-the-loop AppSec pipeline, written in Rust and shipped as a single static binary.

## Invoke, don't vendor

Ascent drives external open-source scanners and the Crux triage engine as subprocesses. They are invoked, never vendored or linked into the Ascent binary.

## License

Apache-2.0. See [LICENSE](LICENSE).
