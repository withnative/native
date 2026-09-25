# Record-mention fixtures (grammar v1)

`corpus.json` is the canonical mention corpus shared by the Rust scanner
(`src/mentions.rs`, `MENTION_PARSER_VERSION = 1`) and — from slice 5 on — a
JS consumer on the demo lineage. Keep it readable from both: plain JSON, no
comments, UTF-8, `\n` line endings.

Grammar v1 is the demo `refs.js` behaviour accepted by plan a9392df, not
CommonMark. The normative statement is the scanner plus its unit tests;
what follows summarises for the JS reader.

## Shape

```json
{
  "version": 1,
  "cases": [
    {
      "name": "bare_basic",
      "body": "See abc1234 for details.",
      "expected": [
        {
          "form": "bare_hex",
          "authored_reference": "abc1234",
          "lookup_key": "abc1234",
          "span_start": 4,
          "span_end": 11
        }
      ]
    }
  ]
}
```

- `version` tracks the scanner contract (`MENTION_PARSER_VERSION`). A case
  whose expectation changes under a scanner bump updates here, not in code.
- `form` is one of `url`, `wiki_hex`, `wiki_name`, `bare_hex`.
- `authored_reference` is the reference exactly as authored (URL first path
  segment, trimmed wiki reference, bare run); `lookup_key` is its lowercase
  fold. Dashes are preserved verbatim in both.
- `span_start`/`span_end` are UTF-8 **byte** offsets into `body`
  (exclusive end), always on character boundaries. `body[span_start..span_end]`
  is the whole mention construct: the full URL (through any query/fragment),
  the full `[[...]]`, or the bare run. **JS consumers must convert**: JS
  string indices are UTF-16 code units, so slice with a byte→UTF-16 mapping
  (e.g. via `TextEncoder`) rather than using these offsets directly.

## Grammar v1 summary

- **Bare:** exactly seven hex digits, not adjacent to an ASCII letter, digit
  or `-`. Underscore adjacency is allowed. Longer runs and UUID-internal
  segments match nothing.
- **URL:** optional `http://`/`https://`, then `n8v.to` or `app.withnative.ai`
  (case-insensitive, no `www.` form), `/`, and a first segment of
  `[A-Za-z0-9_-]{4,64}`. A full UUID there is lexical, not resolution.
- **Wiki:** `[[content]]` with content trimmed; trimmed-empty, any `|`, `[`,
  `]`, newline, or a trimmed reference over 80 characters rejects the
  candidate (length is Unicode scalar values, not JS UTF-16 units). A
  rejected-but-closed span is consumed without emitting, so it never leaks
  an inner `bare_hex`. There is no `|label` form.
- **Fences:** a line with up to three leading spaces/tabs (ASCII only, not
  full JS `\s`) plus a 3+ run of backticks/tildes opens (any trailing text);
  a later same-character 3+ run closes regardless of length or trailing
  text. Mismatched characters never close; an unclosed opener swallows to
  end of input. Inline code is not skipped.

## Coverage contract

Every behaviour above has a named case; add a case before widening the
scanner: fence open/close parity (trailing text, mismatched character,
longer closer, info strings, two-space indent, unclosed), UTF-8 byte spans,
UUID exclusion, nine-hex exclusion, alnum/dash versus underscore adjacency,
wiki padding / whitespace-only / trim-relative 80/81 / pipe cases, wiki
precedence over bare, URL query/fragment spans, scheme-less 6/32/UUID path
forms, short/long segment rejection, and name-shaped wiki references.
