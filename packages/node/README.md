# envrune for Node

Load environment variables from the [EnvRune](https://github.com/YagoLagrottiBracco/envrune)
vault instead of a `.env` file.

```js
import "envrune/config"; // instead of import "dotenv/config"
```

```js
import { load } from "envrune";
load({ env: "staging", override: true });
```

The vault must be unlocked (`envrune unlock`); otherwise loading throws an
`EnvruneError` and never falls back to a `.env` file. See
[Replacing dotenv in code](../../docs/packages.md).
