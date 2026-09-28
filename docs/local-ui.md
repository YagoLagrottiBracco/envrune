# Local dashboard

Run `envrune ui` in a terminal. Envrune asks for the master password there, opens the vault, then starts an HTTP listener on `127.0.0.1` at a free port. It attempts to open your Linux browser with `xdg-open`; the terminal also prints the link.

```sh
envrune ui
envrune ui --port 43821
envrune ui --no-browser
```

The link contains a random, one-use session token and expires after five minutes. Treat that link as private. Its token is carried in the URL fragment, removed from the address bar immediately, and exchanged for an HttpOnly, SameSite=Strict session cookie. It is never sent as a URL query or stored in browser storage. Each run creates new credentials.

The dashboard shows secret references, registered projects, environments, variable bindings, missing references, and where each reference is used. Refresh rereads registered project files so edits to `envrune.yml` appear immediately. An unavailable project is identified without exposing parser errors or file contents.

No page or API returns secret values. There are no value editing controls. Use the terminal for changes. The vault remains open and locked for this foreground process only, so close the dashboard before running another command against it. The master password buffer is cleared immediately after opening the vault.

Choose **Lock & exit** to revoke the session and stop the server, or press Ctrl+C in the terminal. No daemon remains. Closing just the browser tab does not stop the CLI process. The next session requires the master password again.

The server checks the exact loopback Host and Origin, rejects cross-site browser requests, requires a session for metadata, and validates a per-session CSRF token for the lock action. It sends `Cache-Control: no-store`, a restrictive Content Security Policy, anti-framing and no-referrer headers; templates escape metadata. It uses embedded local assets, no third-party resources, and no HTTP access logs.

HTTP on loopback is intentional. Envrune does not support exposing this server through a proxy, LAN address, or tunnel. As with the rest of v1, it does not protect against root or malicious processes running as the same user.
