# Releasing

[ภาษาไทย](releasing.th.md)

## One-time setup

1. Make `moomdate/veil` public. Homebrew can't download from a private repo.
2. Create the tap repo, public and empty:
   ```sh
   gh repo create moomdate/homebrew-tap --public --description "Homebrew tap for Veil"
   ```
3. Create a fine-grained token: GitHub → Settings → Developer settings →
   Fine-grained tokens. Repository access: only `moomdate/homebrew-tap`.
   Permissions: Contents, read and write. Nothing else.
4. Save it in the Veil repo as the Actions secret `HOMEBREW_TAP_TOKEN`:
   ```sh
   gh secret set HOMEBREW_TAP_TOKEN --repo moomdate/veil
   ```
   Paste the token at the prompt, so it doesn't land in your shell history.

## Each release

1. Update `CHANGELOG.md`: move "Unreleased" under the new version.
2. Try the pipeline locally:
   ```sh
   go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,sbom,publish
   ```
3. Tag and push:
   ```sh
   git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0
   ```

The release workflow then tests, builds signed binaries for macOS and Linux
with checksums, an SBOM and cosign signatures, creates the GitHub release,
and publishes the Homebrew formula. Users install with:

```sh
brew install moomdate/tap/veil
```

## How the Homebrew formula works

`packaging/homebrew/veil.rb.tmpl` builds Veil from the tagged source, signs
it with the hardened runtime, and installs shell completions. On each tag,
`packaging/homebrew/update-tap.sh` fills in the source tarball's URL and
sha256 and pushes `Formula/veil.rb` to the tap. The step is skipped when
`HOMEBREW_TAP_TOKEN` isn't set.

To test a formula change before releasing, install it from a local tap:

```sh
git archive --format=tar.gz --prefix=veil-0.0.0/ -o /tmp/veil-0.0.0.tar.gz HEAD
brew tap-new --no-git veiltest/local
packaging/homebrew/render.sh 0.0.0 file:///tmp/veil-0.0.0.tar.gz \
  "$(shasum -a 256 /tmp/veil-0.0.0.tar.gz | cut -d' ' -f1)" \
  > "$(brew --repository veiltest/local)/Formula/veil.rb"
brew install --build-from-source veiltest/local/veil && brew test veiltest/local/veil
brew uninstall veil && brew untap veiltest/local
```
