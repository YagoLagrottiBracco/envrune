"use server";

import { revalidatePath } from "next/cache";
import { sessionClient } from "@/lib/supabase/server";

/**
 * Revokes one of the signed-in member's own devices, such as a lost one. The
 * server stops serving it and deletes the keys wrapped for it at once; the
 * new keys for what it held are made by a CLI, which this site cannot do
 * (docs/cloud-operations.md).
 */
export async function revokeDevice(id: string): Promise<void> {
  const supabase = await sessionClient();
  const { error } = await supabase.rpc("revoke_device", { p_id: id });
  if (error) {
    throw new Error("Could not revoke that device.");
  }
  revalidatePath("/");
}
