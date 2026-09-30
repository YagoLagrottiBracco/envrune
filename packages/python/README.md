# envrune for Python

Load environment variables from the [EnvRune](https://github.com/YagoLagrottiBracco/envrune)
vault instead of a `.env` file.

```python
import envrune

envrune.load()                       # instead of load_dotenv()
envrune.load("staging", override=True)
```

The vault must be unlocked (`envrune unlock`); otherwise `load` raises
`envrune.EnvruneError` and never falls back to a `.env` file. See
[Replacing dotenv in code](../../docs/packages.md).
