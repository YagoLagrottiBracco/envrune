# Demo GIF script

A 30-second recording for the README and the release page: a project with a
`.env` file becomes an EnvRune project, starts, and prints a masked value.

## Setup (not recorded)

- A terminal about 100×28 characters, a dark theme, a large font, and
  `NO_COLOR` unset. Record with [VHS](https://github.com/charmbracelet/vhs)
  so the timing is repeatable (tape below), or asciinema plus agg.
- A Next.js or Node project, `shop/`, with a `.env` that holds
  `DATABASE_URL`, `STRIPE_KEY`, and `SESSION_SECRET`, and a dev server that
  logs its configuration at startup, including `STRIPE_KEY` "by mistake":
  `console.log("stripe key:", process.env.STRIPE_KEY)`.
- A vault already created (`envrune init`) and unlocked
  (`envrune unlock --ttl 1h`), so no password is typed on camera.
- Values that look real but are not, such as
  `sk_test_51Demo0nlyN0tAReal8Key`.

## Scenes

| Time | Shown | Caption |
| --- | --- | --- |
| 0–4 s | `cat .env` shows the three values in plain text. | "Secrets in plain text, next to the code." |
| 4–13 s | `envrune migrate` prints the plan (names and references, no values); type `y` twice to apply and delete the file. | "One command moves them into an encrypted vault." |
| 13–16 s | `cat envrune.yml` shows variable names and references. | "The project keeps only names. Commit it." |
| 16–26 s | `envrune run -- npm run dev`: the server starts and logs `stripe key: ****`. | "Your app gets the values. Your logs do not." |
| 26–30 s | `ls -a` shows no `.env`; end card with `github.com/YagoLagrottiBracco/envrune` and the install command. | "Goodbye, .env." |

## VHS tape

```text
Output demo.gif
Set FontSize 20
Set Width 1200
Set Height 700
Set TypingSpeed 60ms

Type "cat .env" Enter Sleep 3s
Type "envrune migrate" Enter Sleep 4s
Type "y" Enter Sleep 2s
Type "y" Enter Sleep 2s
Type "cat envrune.yml" Enter Sleep 3s
Type "envrune run -- npm run dev" Enter Sleep 8s
Ctrl+C Sleep 1s
Type "ls -a" Enter Sleep 3s
```

Check the last frame before publishing: no real value, token, or path from
your machine should appear anywhere in the recording.
