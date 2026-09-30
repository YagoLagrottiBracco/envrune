# Distribution (maintainers)

The `release` workflow runs when a `v*` tag is pushed. Besides the archives,
`.deb`/`.rpm` packages, and installers, it can publish to package managers.
Each channel stays off until its secret exists, so a release never fails for
lack of one.

| Channel | Published by | Needs |
| --- | --- | --- |
| Homebrew | GoReleaser `homebrew_casks` | repository `YagoLagrottiBracco/homebrew-tap`, secret `PACKAGES_TOKEN` |
| Scoop | GoReleaser `scoops` | repository `YagoLagrottiBracco/scoop-bucket`, secret `PACKAGES_TOKEN` |
| winget | `winget` job (winget-releaser) | secret `WINGET_TOKEN`, a first version already in winget-pkgs |
| apt | `apt` job | secret `APT_GPG_PRIVATE_KEY`, GitHub Pages serving `gh-pages` |

## Homebrew and Scoop

1. Create two empty public repositories: `homebrew-tap` and `scoop-bucket`.
2. Create a fine-grained token with **Contents: read and write** on both, and
   store it as the `PACKAGES_TOKEN` secret of the `envrune` repository.

On the next release, GoReleaser commits `Casks/envrune.rb` and
`envrune.json`. Users install with:

```sh
brew install --cask yagolagrottibracco/tap/envrune
```

```powershell
scoop bucket add envrune https://github.com/YagoLagrottiBracco/scoop-bucket
scoop install envrune
```

The cask removes the macOS quarantine flag after installing, because the
binary is not notarized yet.

## winget

winget-releaser can only update a package that already exists in
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs), so the
first version goes in by hand:

```powershell
winget install Microsoft.WingetCreate
wingetcreate new https://github.com/YagoLagrottiBracco/envrune/releases/download/v0.2.0/envrune_0.2.0_windows_setup.exe
```

Use the identifier `YagoLagrottiBracco.EnvRune`. After that pull request is
merged, create a classic token with `public_repo`, store it as
`WINGET_TOKEN`, and later releases open their pull request automatically.
Users install with `winget install YagoLagrottiBracco.EnvRune`.

## apt

1. Create a signing key without a passphrase, used only for this repository:

   ```sh
   gpg --batch --passphrase '' --quick-gen-key "EnvRune apt <you@example.com>" ed25519 sign never
   gpg --armor --export-secret-keys "EnvRune apt" > apt-private.asc
   ```

2. Store the contents of `apt-private.asc` as the `APT_GPG_PRIVATE_KEY`
   secret, then delete the file.
3. After the first release, enable GitHub Pages for the `gh-pages` branch.

The job adds the release's `.deb` files to a flat repository in `apt/`, signs
it, and publishes the public key as `apt/envrune.gpg`. Users install with:

```sh
curl -fsSL https://yagolagrottibracco.github.io/envrune/apt/envrune.gpg \
  | sudo tee /usr/share/keyrings/envrune.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/envrune.gpg] https://yagolagrottibracco.github.io/envrune/apt ./" \
  | sudo tee /etc/apt/sources.list.d/envrune.list
sudo apt update && sudo apt install envrune
```

Pre-release tags, such as `v1.0.0-rc.1`, skip winget and apt.
