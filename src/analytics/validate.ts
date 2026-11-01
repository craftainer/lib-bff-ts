import { z } from "zod";
import type { Scalar } from "./types.ts";

/** Event names: dotted lowercase segments, e.g. `hero.created` (I3). */
export const NAME_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
export const MAX_NAME = 50;
export const MAX_VALUE = 200;
export const MAX_URL = 500;
/** Events accepted in one `POST /bff/analytics`. */
export const MAX_EVENTS = 50;

/** A validated event as the client sends it (`url` already reduced to a path). */
export interface IncomingEvent {
  name: string;
  props: Record<string, Scalar>;
  url: string;
}

/**
 * `url` is a path only: it must start with exactly one `/`, hold no control
 * characters, and has its query and fragment stripped. Defaults to `/`.
 */
const urlSchema = z
  .string()
  .max(MAX_URL)
  .transform((value, ctx) => {
    const path = value.split(/[?#]/, 1)[0] as string;
    if (
      !path.startsWith("/") ||
      path.startsWith("//") ||
      [...path].some((c) => c <= "\u001f" || c === "\u007f")
    ) {
      ctx.addIssue({ code: "custom", message: "must be a path" });
      return z.NEVER;
    }
    return path;
  });

/** The body of `POST /bff/analytics`: one event or 1 to 50 events. */
export function bodySchema(
  propKeys: readonly string[],
): z.ZodType<IncomingEvent[]> {
  const allowed = new Set(propKeys);
  const event = z.strictObject({
    name: z.string().max(MAX_NAME).regex(NAME_PATTERN),
    props: z
      .record(
        z.string().refine((key) => allowed.has(key), "key not allowed"),
        z.union([z.string().max(MAX_VALUE), z.number(), z.boolean()]),
      )
      .optional(),
    url: urlSchema.optional(),
  });
  return z
    .union([event, z.array(event).min(1).max(MAX_EVENTS)])
    .transform((parsed) =>
      (Array.isArray(parsed) ? parsed : [parsed]).map((e) => ({
        name: e.name,
        props: e.props ?? {},
        url: e.url ?? "/",
      })),
    );
}
