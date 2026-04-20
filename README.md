# Roots by Benda — Cosmetic Regulatory Intelligence MCP Server

**The world's first cosmetic-regulatory MCP.** Check cosmetic ingredient safety and multi-jurisdiction compliance — EU Regulation 1223/2009, US FDA, Korea MFDS, Japan MHLW, ASEAN, Saudi SFDA, Canada Hotlist, Australia SUSMP, ECHA SVHC, California Prop 65, California TFCA, Washington TFCA — backed by 885,895 rows of SCCS opinions, NOAEL studies, CIR conclusions, and pre-calculated Margin of Safety values.

Equivalent data licensed from commercial providers (Coptis, CosmEthics) runs €16,000/year. This MCP is free.

**Live endpoint:** `https://roots-mcp-server.rootsbybenda.workers.dev/mcp`
**SSE fallback:** `https://roots-mcp-server.rootsbybenda.workers.dev/sse`
**Smithery:** [smithery.ai/server/twohalves/cosmetic-regulatory](https://smithery.ai/server/twohalves/cosmetic-regulatory)

## Tools

### `check_ingredient`
Full regulatory profile for a single cosmetic ingredient by name, INCI name, or CAS.

**Returns:** SCCS safety opinion, EU Annex II/III/V/VI classification, pre-calculated Margin of Safety, NOAEL reference, dermal absorption, sensitization profile, CIR conclusion, endocrine-disruptor status, ECHA SVHC listing, China IECIC status, plus jurisdictional_profile — the regulatory status across all 12 supported jurisdictions in one response.

```
query: "retinol"
→ EU: restricted (0.05% body, 0.3% face); Korea_MFDS: restricted; California_Prop65: (not listed);
  SCCS/1639/21 — MoS 167 @ 0.3% face cream (pass); NOAEL 0.43 mg/kg bw/day
```

### `check_formula`
Batch compliance scan for an INCI deck (up to 50 ingredients). Returns per-ingredient regulatory status, flagged restricted/banned substances, and overall formula risk level.

```
ingredients: "Aqua, Retinol, Cetearyl Alcohol, Titanium Dioxide, Phenoxyethanol"
jurisdiction: "EU"
→ Risk: MODERATE — 1 flagged (Retinol — restricted max 0.05% body leave-on under Annex III/321)
```

### `search_ingredients`
Discovery search when you don't know the exact INCI. Filter by partial name, function, or category.

```
query: "sunscreen" → 10 matches (UV filters with safety ratings and EU status)
query: "preservative" → parabens, phenoxyethanol, benzyl alcohol, etc.
```

### `calculate_mos`
Margin of Safety calculator per SCCS Notes of Guidance (SCCS/1647/22) methodology. Returns SED, MoS value, and pass/fail against the SCCS-100 threshold used in CPSR safety assessments.

```
ingredient: "retinol", concentration: 0.3, product_type: "face cream"
→ SED 0.129 mg/kg bw/day; MoS 333 (pass, >100 threshold); dermal absorption 40% (SCCS/1639/21)
```

## Data

| Dataset | Records |
|---------|---------|
| Ingredients (curated INCI) | 30,553 |
| NOAEL study records (EPA ToxRefDB, ChemIDplus, EPA-ECOTOX, EPA-IRIS, GESTIS-DNEL, EFSA, Cal-OEHHA, Health Canada) | 174,973 |
| Pre-calculated MoS values (SCCS methodology, 20 product categories) | 101,085 |
| Sensitization assays | 8,898 |
| Dermal absorption profiles | 860 |
| GHS classifications (PubChem) | 468,165 |
| Substance identifiers (INCI ↔ CAS ↔ EC ↔ CID crosswalk) | 73,252 |
| CIR safety conclusions | 5,267 |
| Multi-jurisdiction regulatory opinions (12 jurisdictions) | **15,925** |
| Distinct substances with multi-jurisdiction profile | 6,917 |
| **TOTAL** | **885,895** |

**100% source-traceability:** every row has a `src_local_path` pointing at a specific primary-source file on disk and a `src_verification_status` in the verified set. No QSAR predictions, no unsourced aggregates.

**Sources:** SCCS opinions (EU Scientific Committee on Consumer Safety), CIR reports (Cosmetic Ingredient Review), EFSA evaluations, ECHA REACH dossiers, EPA ToxValDB, FDA databases, Korea MFDS, Japan MHLW, ASEAN Cosmetic Directive Annex II, Saudi SFDA, Health Canada Hotlist, Australia SUSMP/TGA, California Office of Environmental Health Hazard Assessment (Prop 65), California AB-2762 / AB-496, Washington SB 5369.

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

### Cursor / Windsurf / Zed
Use the Streamable HTTP endpoint:
```
https://roots-mcp-server.rootsbybenda.workers.dev/mcp
```

### Install via Smithery
```bash
npx -y @smithery/cli install twohalves/cosmetic-regulatory --client claude
```

## Rate Limits

No authentication required. Session-level limits keep the free service sustainable:

| Tool | Full-data calls | Basic-data calls | After |
|------|-----------------|------------------|-------|
| `check_ingredient` | 1–10 | 11–25 | Upgrade prompt |
| `check_formula` | 1–5 | — | Upgrade prompt |
| `calculate_mos` | 1–5 | — | Upgrade prompt |
| `search_ingredients` | 1–50 | — | Upgrade prompt |

Unlimited access with full 12-jurisdiction profiles, PDF reports, and 22-tool web workspace: [rootsbybenda.com/pricing](https://rootsbybenda.com/pricing).

## Built With

- [Cloudflare Workers](https://workers.cloudflare.com/) + [Agents SDK](https://developers.cloudflare.com/agents/)
- [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite at the edge, 885,895 rows)
- [Durable Objects](https://developers.cloudflare.com/durable-objects/) (session-scoped rate limiting)
- [Model Context Protocol](https://modelcontextprotocol.io/) (MCP)

## Who Built This

**Roots by Benda** — cosmetic regulatory intelligence platform built by Shahar Ben-David (formulator) with Claude (CTO pair-programmer). Regulatory database assembled from primary sources across SCCS, CIR, EFSA, ECHA, EPA ToxValDB, FDA, and the 12 national/state regulatory bodies listed above.

- Website: [rootsbybenda.com](https://rootsbybenda.com)
- LinkedIn: [Shahar Ben-David](https://www.linkedin.com/in/shahar-ben-david-25549a3a8/)
- Smithery publisher: [twohalves](https://smithery.ai/server/twohalves/cosmetic-regulatory)

## License

MIT
