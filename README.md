# Roots by Benda — Cosmetic Regulatory Intelligence MCP Server

The first MCP server for cosmetic and chemical regulatory data. Query 30,000+ ingredients, 46,000+ NOAEL toxicology studies, and regulatory status across 55+ jurisdictions — all from your AI agent.

**Live:** `https://roots-mcp-server.rootsbybenda.workers.dev/mcp`

## Tools

### `check_ingredient`
Look up any cosmetic or chemical ingredient by name, INCI name, or CAS number.

**Returns:** Safety rating, EU/US regulatory status, concentration limits, NOAEL value, dermal absorption, sensitization data, expert verdict with SCCS opinion references, regulatory flags.

```
query: "retinol"  →  Safety: MODERATE, EU: restricted (0.05% RE body lotions),
                     NOAEL: 43 mg/kg bw/day, Pregnancy: no, SCCS/1639/21
```

### `check_formula`
Batch check up to 50 ingredients for safety and regulatory compliance. Returns flagged ingredients, restricted substances, and overall risk level (LOW / MODERATE / HIGH).

```
ingredients: "Retinol, Cetearyl Alcohol, Titanium Dioxide"
jurisdiction: "EU"  →  Risk: MODERATE (1 flagged: Retinol — restricted)
```

### `search_ingredients`
Search the database by keyword — find ingredients by partial name, function, or category.

```
query: "sunscreen"  →  10 matches with safety ratings and regulatory status
```

## Data

| Dataset | Records |
|---------|---------|
| Ingredients | 30,553 |
| NOAEL Studies | 46,309 |
| Unique Substances with NOAEL | 10,923 |
| Regulatory List Entries | 19,746 |
| Jurisdictions Covered | 55+ |

Sources: SCCS opinions, CIR reports, EFSA evaluations, ECHA REACH dossiers, JECFA monographs, EPA CompTox, FDA databases.

## Quick Start

### Claude Desktop / Claude Code
Add to your MCP config:
```json
{
  "mcpServers": {
    "roots-by-benda": {
      "url": "https://roots-mcp-server.rootsbybenda.workers.dev/sse"
    }
  }
}
```

### Any MCP Client
Connect via Streamable HTTP:
```
https://roots-mcp-server.rootsbybenda.workers.dev/mcp
```

## Built With

- [Cloudflare Workers](https://workers.cloudflare.com/) + [Agents SDK](https://developers.cloudflare.com/agents/)
- [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite at the edge)
- [Durable Objects](https://developers.cloudflare.com/durable-objects/) (stateful sessions)
- [Model Context Protocol](https://modelcontextprotocol.io/) (MCP)

## Who Built This

**Roots by Benda** — cosmetic regulatory intelligence platform built by Shahar Ben-David (formulator) and Claude (CTO). 30,000+ ingredient database assembled through months of regulatory research across SCCS, CIR, EFSA, ECHA, JECFA, and EPA sources.

- Website: [rootsbybenda.com](https://rootsbybenda.com)
- LinkedIn: [Shahar Ben-David](https://www.linkedin.com/in/shahar-ben-david-25549a3a8/)

## License

MIT
