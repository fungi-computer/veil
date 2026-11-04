import type { NarrowFetch } from "./contract.js";

const toolLimit = 1_024;

/** The tool names an MCP server offers, listed with the maintained SDK client. */
export async function listMcpTools(
  url: string,
  fetch: NarrowFetch,
): Promise<readonly string[]> {
  const sdk = await import("@modelcontextprotocol/client");
  const client = new sdk.Client({ name: "fungi-connections", version: "1" });
  await client.connect(
    new sdk.StreamableHTTPClientTransport(new URL(url), {
      fetch,
      requestInit: { redirect: "error" },
    }),
  );
  try {
    const names: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await client.listTools(
        cursor === undefined ? undefined : { cursor },
      );
      names.push(...page.tools.map((tool) => tool.name));
      cursor = page.nextCursor;
    } while (cursor !== undefined && names.length < toolLimit);
    return names.slice(0, toolLimit);
  } finally {
    await client.close();
  }
}
