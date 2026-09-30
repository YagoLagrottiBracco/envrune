// GET: whether this is an EnvRune Cloud server, and which API it speaks.
export function GET() {
  return Response.json({ service: "envrune-cloud", api: 1 });
}
