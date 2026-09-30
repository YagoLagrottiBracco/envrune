// `import "envrune/config"` loads the default environment, as
// `import "dotenv/config"` loads .env. ENVRUNE_ENV picks another environment.
import { load } from "./index.js";

load({ env: process.env.ENVRUNE_ENV || undefined });
