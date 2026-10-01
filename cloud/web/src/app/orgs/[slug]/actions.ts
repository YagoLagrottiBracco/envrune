"use server";

import { revalidatePath } from "next/cache";
import { sessionClient } from "@/lib/supabase/server";

/**
 * Records that a secret someone who left could read keeps its value. The
 * database checks that the caller is an owner or admin and writes it to the
 * audit log; this site only passes the request on as the signed-in user.
 */
export async function acceptRotationItem(slug: string, task: string, secret: string): Promise<void> {
  const supabase = await sessionClient();
  const { error } = await supabase.rpc("update_rotation_item", { p_task: task, p_secret: secret, p_status: "accepted" });
  if (error) {
    throw new Error("Could not record that. Only owners and admins update rotation.");
  }
  revalidatePath(`/orgs/${slug}`);
}
