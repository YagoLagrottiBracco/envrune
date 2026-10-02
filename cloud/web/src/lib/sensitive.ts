import { Decrypter, identityToRecipient } from "age-encryption";

// Sensitive secrets, on the server. The CLI seals a value to the server's
// proxy identity (internal/cloudcrypto/sensitive.go); this opens it, in
// memory, for the time of one request. See docs/managed-keys.md.

/** A sensitive secret's current version as the database returns it to the server. */
export interface SensitiveRow {
  org_id: string;
  project_id: string;
  environment_id: string;
  name: string;
  version: number;
  sealed: string; // base64
}

/** What the owner sealed: the value and where it may be sent. */
export interface SensitiveContent {
  hosts: string[];
  value: Uint8Array;
  /** A client certificate and its key, in PEM, when the secret is one. */
  certificate?: string;
  key?: string;
}

/** The public half of a proxy identity, which values are sealed to. */
export function recipientOf(identity: string): Promise<string> {
  return identityToRecipient(identity);
}

/**
 * Opens a sensitive secret with the proxy identity and checks that what was
 * sealed is that secret, in that environment, at that version: a ciphertext
 * moved between rows of the database does not open.
 */
export async function openSensitive(identity: string, row: SensitiveRow): Promise<SensitiveContent> {
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  const plain = await decrypter.decrypt(Buffer.from(row.sealed, "base64"), "text");
  const content = JSON.parse(plain) as {
    org: string;
    project: string;
    environment: string;
    name: string;
    version: number;
    hosts: string[];
    value: string | null;
    certificate?: string;
    key?: string;
  };
  if (
    content.org !== row.org_id ||
    content.project !== row.project_id ||
    content.environment !== row.environment_id ||
    content.name !== row.name ||
    content.version !== row.version ||
    !Array.isArray(content.hosts) ||
    content.hosts.some((h) => typeof h !== "string")
  ) {
    throw new Error("the sealed content belongs to another secret or version");
  }
  const pem = (field?: string) => (field ? Buffer.from(field, "base64").toString("utf8") : undefined);
  return {
    hosts: content.hosts,
    value: Buffer.from(content.value ?? "", "base64"),
    certificate: pem(content.certificate),
    key: pem(content.key),
  };
}
