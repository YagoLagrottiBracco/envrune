# Showing the vault state in your prompt

`envrune status --format prompt` prints one short word, fast enough to run
before every prompt because it never unlocks anything:

| Output | Meaning |
| --- | --- |
| `unlocked 7h` | An agent holds the key for about 7 more hours (`unlocked 25m` under an hour). |
| `keychain` | The system keychain unlocks the vault. |
| `locked` | Commands will ask for the master password. |
| `no vault` | Run `envrune init`. |

It prints nothing outside a folder with an `envrune.yml` (or below one), so
the segment only appears where it matters. Add `--always` to show it
everywhere.

## Starship

In `~/.config/starship.toml`:

```toml
[custom.envrune]
command = "envrune status --format prompt"
when = true
style = "bold yellow"
format = "([🔑 $output]($style) )"
```

The parentheses in `format` hide the segment when `$output` is empty, which
is the case outside projects. See [Starship's custom commands](https://starship.rs/config/#custom-commands)
for the other options.

## Oh My Posh

Oh My Posh reads environment variables in templates, and lets you set them
right before each prompt with `set_poshcontext`. Add the function to your
shell profile, after `oh-my-posh init`:

```bash
# bash or zsh
function set_poshcontext() {
    export ENVRUNE_STATE="$(envrune status --format prompt)"
}
```

```powershell
# PowerShell
function Set-EnvRuneState([bool]$originalStatus) {
    $env:ENVRUNE_STATE = (envrune status --format prompt) -join ""
}
New-Alias -Name 'Set-PoshContext' -Value 'Set-EnvRuneState' -Scope Global -Force
```

```fish
# fish
function set_poshcontext
    set --export ENVRUNE_STATE (envrune status --format prompt)
end
```

Then add a `text` segment to your theme:

```json
{
  "type": "text",
  "style": "plain",
  "foreground": "#e0af68",
  "template": "{{ if .Env.ENVRUNE_STATE }}🔑 {{ .Env.ENVRUNE_STATE }} {{ end }}"
}
```

See Oh My Posh's [templates](https://ohmyposh.dev/docs/configuration/templates)
for how `set_poshcontext` works in each shell.

## Anything else

Any prompt that can run a command can use it:

```bash
# plain bash
PS1='$(envrune status --format prompt | sed "s/.*/[&] /")'"$PS1"
```

For scripts and editors, `envrune status --format json` reports the same
state with details: whether the vault exists, whether an agent is unlocked
and until when, whether the keychain is enabled, and the current project and
default environment.
