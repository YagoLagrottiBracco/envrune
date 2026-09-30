# Output redaction: design

`envrune run` and `envrune up` replace any vault value that a child process
prints with `****` before it reaches your terminal. `envrune guard`,
`envrune scan`, and `envrune mcp` use the same matcher to find values in a
diff, in Git history, and in command output. This document records how it
works and what it does not protect against.

## What is matched

The matcher receives the values the command has in hand: for `run` and `up`,
the variables injected into the child; for `guard` and `scan`, every value
in the vault and the team file. For each value it looks for:

- the value itself;
- its URL-encoded forms (query and path escaping), when they differ;
- its standard and URL-safe base64 encodings, padded and unpadded.

A base64 encoding is only found when the value starts at the beginning of
the encoded text, as in `Authorization: Basic ...` built from the value
alone. A value inside a longer base64 blob is not found.

Values shorter than 6 bytes, such as `true` or `3000`, are not matched: they
appear in ordinary output too often, and masking them would hide useful
text and reveal where they occur. `envrune doctor` lists them.

## Streaming

Output arrives in chunks of any size, and a value can be split between two
chunks. The writer keeps back only the end of the stream that could still be
the start of a value, and writes everything before it at once, so
interactive output is not delayed by line buffering.

When no new output arrives for 150 ms, the kept-back bytes are written
anyway, so a prompt that happens to end like the start of a secret still
shows. If the rest of the value then arrives, it is masked, but the part
written before the pause stays visible. A program that prints a value
slowly, a few bytes at a time with pauses, can therefore show its
beginning.

Values are matched longest first, and overlapping matches are merged, so a
value that contains another is masked as a whole.

## Terminals

Masking requires reading the child's output, which means the child no
longer writes directly to the terminal. When the output of `run` is a
terminal, the child gets a pseudo-terminal instead (a pty on Linux and
macOS, ConPTY on Windows), so colors, progress bars, and prompts keep
working. Its standard output and standard error then arrive as one stream,
as they do in a terminal. Your keyboard input is passed through in raw mode,
so Ctrl+C reaches the child as it would without EnvRune.

When the output is not a terminal (a pipe, a file, CI), the child gets
pipes and its standard output and standard error stay separate.

`--no-redact` turns masking off and connects the child directly to the
terminal, as in EnvRune 0.1.0.

## Memory

The matcher holds copies of the values and their encodings only while the
command runs, and wipes them when it ends. Nothing it holds is written to
disk. `guard` and `scan` compare in memory; they do not store hashes of
values, because a stored hash of a short or guessable value could be
checked offline.

## What redaction does not do

Redaction prevents a value from appearing by accident in a terminal, a
screen recording, a CI log, or an AI agent's transcript. It does not stop a
program from using or leaking the value on purpose:

- the child can write the value to a file, send it over the network, or
  transform it (reverse it, split it with spaces, hex-encode it) before
  printing it;
- any process running as you can read the child's environment;
- output the child writes directly to the terminal device, bypassing its
  standard streams, is not seen. With a pseudo-terminal this is rare.

Treat masking as protection against accidents, not against a program you do
not trust.
