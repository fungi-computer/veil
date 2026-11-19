import { RE2JS } from "re2js";
import type { MatchFollower, OpenMatch, TextSpan } from "./redaction.js";

/** A vendored rule as the redactor compiled it. */
export type CompiledRule = Readonly<{
  id: string;
  regex?: RE2JS | undefined;
  keywords: readonly string[];
}>;

export type OpenRule = Readonly<{
  id: string;
  keywords: readonly string[];
  opener: RE2JS;
  /** Whether a match from an opener ending at `from` is complete in `text`. */
  ended: (text: string, from: number) => boolean;
  /** Follows that unfinished match into the text after `text`. */
  follow: (text: string, from: number) => MatchFollower;
}>;

/**
 * Vendored rules whose match can outgrow any scan window before it completes.
 * Each opener is the rule's own source before `unbounded`; a table whose rule
 * lacks that span (or, for a private key, whose tail differs) fails the load,
 * and hosts then withhold output.
 *
 * - A private key has ended at the first `tail` after its opener once the
 *   body is past 64 characters, which a held block always is.
 * - A curl command has ended once twelve `\n` follow its opener: `.` spans
 *   `\r`, so only `\n` bounds it, and `unbounded` admits at most eleven (five
 *   `[\r\n]{1,2}` groups and one `[ \t\n\r]` separator) before the flag's line.
 *
 * Not detected here: a changed curl remainder (a quoted `-u` value already
 * spans lines) or a new unbounded rule; redaction.test.ts snapshots every
 * vendored rule with an unbounded quantifier so a regenerated table that adds
 * one fails until it is classified.
 */
const unboundedRules = [
  {
    id: "private-key",
    unbounded: "[\\s\\S-]{64,}?",
    tail: "KEY(?: BLOCK)?-----",
  },
  {
    id: "curl-auth-header",
    unbounded: "(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r]",
    newlines: 12,
  },
  {
    id: "curl-auth-user",
    unbounded: "(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r]",
    newlines: 12,
  },
] as const;

/** Longer than any `tail` match, so a tail split across reads is still seen. */
const tailCarry = 64;

function newlinesIn(text: string, from: number, limit: number): number {
  let seen = 0;
  for (let index = text.indexOf("\n", from); index !== -1 && seen < limit;) {
    seen++;
    index = text.indexOf("\n", index + 1);
  }
  return seen;
}

function tailRule(source: string, at: number, tail: string) {
  const rest = source.slice(at);
  if (rest !== tail) return undefined;
  const expression = RE2JS.compile(
    (source.startsWith("(?i)") ? "(?i)" : "") + tail,
  );
  return {
    ended: (text: string, from: number) => expression.matcher(text).find(from),
    follow: (text: string, from: number): MatchFollower => {
      let carry = text.slice(Math.max(from, text.length - tailCarry));
      return {
        read: (piece) => {
          const joined = carry + piece;
          const matcher = expression.matcher(joined);
          if (matcher.find()) return Math.max(0, matcher.end() - carry.length);
          carry = joined.slice(-tailCarry);
          return undefined;
        },
      };
    },
  };
}

function newlineRule(count: number) {
  return {
    ended: (text: string, from: number) =>
      newlinesIn(text, from, count) >= count,
    follow: (text: string, from: number): MatchFollower => {
      let remaining = count - newlinesIn(text, from, count);
      return {
        read: (piece) => {
          for (let index = piece.indexOf("\n"); index !== -1;) {
            if (--remaining === 0) return index + 1;
            index = piece.indexOf("\n", index + 1);
          }
          return undefined;
        },
      };
    },
  };
}

export function openRules(rules: readonly CompiledRule[]): OpenRule[] {
  return unboundedRules.map((declared) => {
    const rule = rules.find((candidate) => candidate.id === declared.id);
    const source = rule?.regex?.pattern() ?? "";
    const at = source.indexOf(declared.unbounded);
    const end =
      "tail" in declared
        ? tailRule(source, at + declared.unbounded.length, declared.tail)
        : newlineRule(declared.newlines);
    if (rule === undefined || at <= 0 || end === undefined)
      throw new Error(
        `redaction rule ${declared.id} no longer has the span it is held by`,
      );
    return {
      id: declared.id,
      keywords: rule.keywords,
      opener: RE2JS.compile(source.slice(0, at)),
      ...end,
    };
  });
}

/** The earliest unfinished match's opener in `text`, if any. */
export function openFrom(
  text: string,
  rules: readonly OpenRule[],
): OpenMatch | undefined {
  const lower = text.toLowerCase();
  let earliest: { opener: TextSpan; rule: OpenRule } | undefined;
  for (const rule of rules) {
    if (
      rule.keywords.length > 0 &&
      !rule.keywords.some((word) => lower.includes(word))
    )
      continue;
    const openers: TextSpan[] = [];
    const matcher = rule.opener.matcher(text);
    while (matcher.find())
      openers.push({ start: matcher.start(), end: matcher.end() });
    // Every opener after an unfinished one is unfinished too: walk back.
    for (let index = openers.length - 1; index >= 0; index--) {
      const opener = openers[index];
      if (opener === undefined || rule.ended(text, opener.end)) break;
      if (earliest === undefined || opener.start < earliest.opener.start)
        earliest = { opener, rule };
    }
  }
  if (earliest === undefined) return undefined;
  const { opener, rule } = earliest;
  return {
    opener,
    follow: () => rule.follow(text, opener.end),
  };
}
