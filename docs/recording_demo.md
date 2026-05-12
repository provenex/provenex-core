# Recording the demo

How to record [`examples/standalone_demo.py`](../examples/standalone_demo.py) as an asciinema cast and embed it in the README.

The demo runs in ~12 seconds with default pacing. The script's `time.sleep()` calls between acts are tuned for recording — long enough for a viewer to read each section header and the result line, short enough that the whole thing fits in a tweet-sized loop.

## Prerequisites

```bash
# macOS
brew install asciinema

# Linux
pipx install asciinema   # or: apt install asciinema
```

`asciinema --version` should report 2.x.

## Record

From a clean checkout (so `pip install -e .` and the demo's temp DB don't appear mid-recording):

```bash
git clone https://github.com/provenex/provenex-core.git provenex-demo
cd provenex-demo
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e . > /dev/null

export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

asciinema rec demo.cast \
    --idle-time-limit 1.5 \
    --command "python examples/standalone_demo.py" \
    --title "Provenex: cryptographic provenance for RAG"
```

Flags worth knowing:

- `--idle-time-limit 1.5` — compresses gaps longer than 1.5 s so the recording stays tight. Without this, the script's pacing sleeps get faithfully recorded and the cast feels sluggish on playback.
- `--command` — runs the demo as the recorded session (no shell prompt visible). For a shell-prompt-style recording instead, drop `--command` and run the demo manually inside the recording.
- `--title` — shows up on the asciinema.org page if uploaded.

## Verify locally

```bash
asciinema play demo.cast
```

Watch the whole thing. If anything looks wrong (tearing, prompt artefacts, broken colors in your terminal emulator), re-record.

## Upload

```bash
asciinema upload demo.cast
```

Returns a URL like `https://asciinema.org/a/abc123`. The first upload is anonymous — to claim the recording under your account, register at asciinema.org and run `asciinema auth` once.

## Embed in the README

Once you have an asciinema URL, drop this badge near the top of the README (e.g., right under the opening paragraph, or in the "Try it in 30 seconds" section):

```markdown
[![asciicast](https://asciinema.org/a/<id>.svg)](https://asciinema.org/a/<id>)
```

Both `<id>` placeholders are the same — the numeric/alphanumeric portion of the URL.

GitHub renders the SVG as a clickable still that opens the player on asciinema.org. Don't try to use the SVG as a self-playing animation — GitHub's content security policy strips the JavaScript that drives it.

## Alternatives for non-asciinema audiences

| Need | Recipe |
|---|---|
| GIF for X/Twitter, Bluesky, blog posts | `agg demo.cast demo.gif` (install: `cargo install agg`) — produces a clean GIF from the cast |
| MP4 for LinkedIn / non-loopable platforms | Record once as asciinema → `agg demo.cast demo.gif` → `ffmpeg -i demo.gif demo.mp4` |
| Live demo to one person on a call | `python examples/standalone_demo.py` (the pacing sleeps are tuned for live narration) |
| CI-fast sanity check | `python examples/standalone_demo.py --fast` (skips pacing) |

## Re-recording

If the demo script changes (new act, different bench numbers, etc.), rerun the recording and the upload. asciinema URLs are immutable — uploading produces a *new* URL, so update the README embed too. Keep the old `demo.cast` in git (or don't) — it's small (~10 KB) and useful for diffs.
