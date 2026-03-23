import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Escape LIKE special characters in user input to prevent wildcard injection
function escapeLike(s: string): string {
  return s.replace(/[%_\\]/g, '\\$&');
}

interface Env {
  DB: D1Database;
  MCP_OBJECT: DurableObjectNamespace;
}

export class RootsMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "roots-by-benda",
    version: "1.0.0",
  });

  async init() {
    // Tool 1: check_ingredient — lookup by name, INCI, or CAS number
    this.server.tool(
      "check_ingredient",
      "Look up a cosmetic or chemical ingredient by name, INCI name, or CAS number. Returns safety rating, regulatory status (EU/US), NOAEL values, dermal absorption, sensitization data, concern level, and expert verdict.",
      {
        query: z
          .string()
          .describe(
            "Ingredient name, INCI name, or CAS number (e.g. 'retinol', 'RETINOL', '68-26-8')"
          ),
      },
      async ({ query }) => {
        const q = query.trim();

        // Try exact key match first, then CAS, then INCI, then fuzzy name
        let ingredient = await this.env.DB.prepare(
          `SELECT * FROM ingredients WHERE key = ? COLLATE NOCASE`
        )
          .bind(q.toUpperCase().replace(/[\s-]+/g, "_"))
          .first();

        if (!ingredient) {
          ingredient = await this.env.DB.prepare(
            `SELECT * FROM ingredients WHERE cas = ? COLLATE NOCASE`
          )
            .bind(q)
            .first();
        }

        if (!ingredient) {
          ingredient = await this.env.DB.prepare(
            `SELECT * FROM ingredients WHERE inci = ? COLLATE NOCASE`
          )
            .bind(q.toUpperCase())
            .first();
        }

        if (!ingredient) {
          const qEsc = escapeLike(q);
          ingredient = await this.env.DB.prepare(
            `SELECT * FROM ingredients WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 1`
          )
            .bind(`%${qEsc}%`)
            .first();
        }

        if (!ingredient) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "not_found",
                  message: `No ingredient found matching "${query}". Try searching by INCI name or CAS number.`,
                  suggestion:
                    "Use exact INCI names (e.g. 'RETINOL') or CAS numbers (e.g. '68-26-8') for best results.",
                }),
              },
            ],
          };
        }

        // Fetch NOAEL studies for this ingredient
        const noaelStudies = await this.env.DB.prepare(
          `SELECT endpoint_type, value, qualifier, unit, study_type, route, duration, species, source, reference
           FROM noael_studies
           WHERE substance_name = ? COLLATE NOCASE OR cas_number = ?
           LIMIT 10`
        )
          .bind(
            ingredient.name as string,
            (ingredient.cas as string) || ""
          )
          .all();

        // Fetch regulatory list entries
        const regLists = await this.env.DB.prepare(
          `SELECT list_key, list_name FROM regulatory_lists
           WHERE chemical_name = ? COLLATE NOCASE OR cas_number = ?
           LIMIT 20`
        )
          .bind(
            ingredient.name as string,
            (ingredient.cas as string) || ""
          )
          .all();

        const result = {
          name: ingredient.name,
          inci: ingredient.inci,
          cas: ingredient.cas,
          function: ingredient.function,
          category: ingredient.category,
          safety_rating: ingredient.safety,
          concern_level: ingredient.concern,
          concern_reason: ingredient.concern_reason || null,
          regulatory: {
            eu_status: ingredient.eu_status,
            eu_max_concentration: ingredient.eu_max || null,
            us_status: ingredient.us_status,
            us_notes: ingredient.us_note || null,
          },
          safety_data: {
            margin_of_safety: ingredient.mos || null,
            dermal_absorption: ingredient.absorption || null,
            sensitization: ingredient.sensitization || null,
            noael_value: ingredient.noael_value || null,
            pregnancy_safe: ingredient.pregnancy_safe || null,
            comedogenicity: ingredient.comedogenicity_rating || null,
          },
          expert_verdict: ingredient.verdict || null,
          regulatory_flags: (() => {
            try {
              return JSON.parse(ingredient.flags as string);
            } catch {
              return [];
            }
          })(),
          noael_studies:
            noaelStudies.results?.map((s: Record<string, unknown>) => ({
              endpoint: s.endpoint_type,
              value: s.value,
              qualifier: s.qualifier,
              unit: s.unit,
              study_type: s.study_type,
              route: s.route,
              duration: s.duration,
              species: s.species,
              source: s.source,
              reference: s.reference,
            })) || [],
          regulatory_lists:
            regLists.results?.map((r: Record<string, unknown>) => ({
              list: r.list_key,
              name: r.list_name,
            })) || [],
          source: "Roots by Benda — rootsbybenda.com",
          data_verified: "2026-03",
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      }
    );

    // Tool 2: check_formula — batch check a list of ingredients
    this.server.tool(
      "check_formula",
      "Check a list of cosmetic ingredients for safety and regulatory compliance. Returns a summary with flagged ingredients, restricted substances, and overall risk assessment. Pass ingredients as a comma-separated list or one per line.",
      {
        ingredients: z
          .string()
          .describe(
            "Comma-separated or newline-separated list of ingredient names (e.g. 'Retinol, Cetearyl Alcohol, Titanium Dioxide')"
          ),
        jurisdiction: z
          .string()
          .optional()
          .describe(
            "Target jurisdiction for compliance check (e.g. 'EU', 'US', 'China', 'Korea'). Defaults to EU + US."
          ),
      },
      async ({ ingredients, jurisdiction }) => {
        const names = ingredients
          .split(/[,\n]+/)
          .map((n) => n.trim())
          .filter(Boolean);

        if (names.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "empty_list",
                  message: "No ingredients provided.",
                }),
              },
            ],
          };
        }

        if (names.length > 50) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "too_many",
                  message:
                    "Maximum 50 ingredients per request. Split into multiple calls.",
                }),
              },
            ],
          };
        }

        const results = [];
        const flagged = [];
        let found = 0;
        let notFound = 0;

        for (const name of names) {
          const key = name.toUpperCase().replace(/[\s-]+/g, "_");
          let ingredient = await this.env.DB.prepare(
            `SELECT name, inci, cas, safety, eu_status, eu_max, us_status, concern, flags, noael_value
             FROM ingredients WHERE key = ? COLLATE NOCASE`
          )
            .bind(key)
            .first();

          if (!ingredient) {
            const nameEsc = escapeLike(name);
            ingredient = await this.env.DB.prepare(
              `SELECT name, inci, cas, safety, eu_status, eu_max, us_status, concern, flags, noael_value
               FROM ingredients WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 1`
            )
              .bind(`%${nameEsc}%`)
              .first();
          }

          if (ingredient) {
            found++;
            const flags = (() => {
              try {
                return JSON.parse(ingredient.flags as string);
              } catch {
                return [];
              }
            })();

            const entry: Record<string, unknown> = {
              input: name,
              matched: ingredient.name,
              inci: ingredient.inci,
              cas: ingredient.cas,
              safety: ingredient.safety,
              concern: ingredient.concern,
              eu_status: ingredient.eu_status,
              eu_max: ingredient.eu_max || null,
              us_status: ingredient.us_status,
              noael: ingredient.noael_value || null,
              flags,
            };

            results.push(entry);

            if (
              ingredient.safety === "POOR" ||
              ingredient.concern === "High" ||
              (ingredient.eu_status as string)?.includes("banned") ||
              (ingredient.eu_status as string)?.includes("restricted") ||
              flags.length > 0
            ) {
              flagged.push(entry);
            }
          } else {
            notFound++;
            results.push({
              input: name,
              matched: null,
              message: "Not found in database",
            });
          }
        }

        const summary = {
          total_ingredients: names.length,
          found,
          not_found: notFound,
          flagged_count: flagged.length,
          risk_level:
            flagged.length === 0
              ? "LOW"
              : flagged.length <= 2
                ? "MODERATE"
                : "HIGH",
          flagged_ingredients: flagged.map((f) => ({
            name: f.matched,
            reason: `${f.eu_status}${f.concern ? `, concern: ${f.concern}` : ""}`,
          })),
          all_results: results,
          jurisdiction_checked: jurisdiction || "EU + US (default)",
          source: "Roots by Benda — rootsbybenda.com",
        };

        return {
          content: [
            { type: "text" as const, text: JSON.stringify(summary, null, 2) },
          ],
        };
      }
    );

    // Tool 3: search_ingredients — full-text search across the database
    this.server.tool(
      "search_ingredients",
      "Search the ingredient database by keyword. Useful for finding ingredients by partial name, function, or category. Returns up to 10 matches with basic safety data.",
      {
        query: z
          .string()
          .describe("Search keyword (e.g. 'sunscreen', 'preservative', 'retinoid')"),
        limit: z
          .number()
          .optional()
          .describe("Max results to return (1-20, default 10)"),
      },
      async ({ query, limit }) => {
        const maxResults = Math.min(Math.max(limit || 10, 1), 20);
        const queryEsc = escapeLike(query);

        const results = await this.env.DB.prepare(
          `SELECT name, inci, cas, function, safety, eu_status, concern, noael_value
           FROM ingredients
           WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
              OR inci LIKE ? ESCAPE '\\' COLLATE NOCASE
              OR function LIKE ? ESCAPE '\\' COLLATE NOCASE
              OR category LIKE ? ESCAPE '\\' COLLATE NOCASE
           LIMIT ?`
        )
          .bind(
            `%${queryEsc}%`,
            `%${queryEsc}%`,
            `%${queryEsc}%`,
            `%${queryEsc}%`,
            maxResults
          )
          .all();

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  query,
                  count: results.results?.length || 0,
                  results:
                    results.results?.map((r: Record<string, unknown>) => ({
                      name: r.name,
                      inci: r.inci,
                      cas: r.cas,
                      function: r.function,
                      safety: r.safety,
                      eu_status: r.eu_status,
                      concern: r.concern,
                      has_noael: r.noael_value != null,
                    })) || [],
                  source: "Roots by Benda — rootsbybenda.com",
                },
                null,
                2
              ),
            },
          ],
        };
      }
    );

    // Tool 4: calculate_mos — Margin of Safety calculation per SCCS guidelines
    this.server.tool(
      "calculate_mos",
      "Calculate the Margin of Safety (MoS) for a cosmetic ingredient using SCCS Notes of Guidance methodology. Requires ingredient name (or CAS), concentration in product (%), and product type. Returns SED (Systemic Exposure Dose), MoS value, and whether it passes the SCCS safety threshold (MoS > 100).",
      {
        ingredient: z
          .string()
          .describe(
            "Ingredient name, INCI name, or CAS number (e.g. 'retinol', '68-26-8')"
          ),
        concentration: z
          .number()
          .describe("Concentration of ingredient in the product (%, e.g. 0.5 for 0.5%)"),
        product_type: z
          .string()
          .describe(
            "Product type (e.g. 'body lotion', 'shampoo', 'lipstick', 'face cream', 'hand cream', 'shower gel', 'toothpaste', 'mouthwash', 'hair styling', 'deodorant')"
          ),
        body_weight: z
          .number()
          .optional()
          .describe("Body weight in kg (default: 60 for adults)"),
        dermal_absorption: z
          .number()
          .optional()
          .describe(
            "Dermal absorption percentage override (if known from studies). If not provided, uses SCCS default of 50%."
          ),
      },
      async ({ ingredient, concentration, product_type, body_weight, dermal_absorption }) => {
        const bw = body_weight || 60;

        // 1. Look up the ingredient for NOAEL
        const q = ingredient.trim();
        const qEsc = escapeLike(q);
        const ing = await this.env.DB.prepare(
          `SELECT name, cas, noael_value, dermal_absorption as da
           FROM ingredients
           WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE OR inci LIKE ? ESCAPE '\\' COLLATE NOCASE OR cas = ?
           LIMIT 1`
        )
          .bind(`%${qEsc}%`, `%${qEsc}%`, q)
          .first();

        // Also check noael_studies for the best NOAEL
        const noaelStudy = await this.env.DB.prepare(
          `SELECT substance_name, value, species, route, duration, study_type, source
           FROM noael_studies
           WHERE substance_name LIKE ? ESCAPE '\\' COLLATE NOCASE
           ORDER BY CASE WHEN route LIKE '%dermal%' THEN 0 WHEN route LIKE '%oral%' THEN 1 ELSE 2 END,
                    CAST(value AS REAL) ASC
           LIMIT 1`
        )
          .bind(`%${qEsc}%`)
          .first();

        // 2. Look up SCCS exposure parameters for product type
        const ptEsc = escapeLike(product_type.trim());
        const exposure = await this.env.DB.prepare(
          `SELECT * FROM sccs_exposure_parameters
           WHERE product_type LIKE ? ESCAPE '\\' COLLATE NOCASE
              OR product_category LIKE ? ESCAPE '\\' COLLATE NOCASE
           LIMIT 1`
        )
          .bind(`%${ptEsc}%`, `%${ptEsc}%`)
          .first();

        // Get NOAEL value
        let noael: number | null = null;
        let noaelSource = "none";

        if (noaelStudy && noaelStudy.value) {
          noael = parseFloat(String(noaelStudy.value));
          noaelSource = `${noaelStudy.species || "unknown species"}, ${noaelStudy.route || "unknown route"}, ${noaelStudy.duration || "unknown duration"} (${noaelStudy.source || "study"})`;
        } else if (ing && ing.noael_value) {
          noael = parseFloat(String(ing.noael_value));
          noaelSource = "ingredient database";
        }

        if (!noael || isNaN(noael)) {
          return {
            content: [
              {
                type: "text" as const,
                text: `## MoS Calculation — Cannot Complete\n\n**Ingredient:** ${q}\n**Reason:** No NOAEL value found for this ingredient in our database (46,000+ studies searched).\n\nTo calculate MoS, a NOAEL (No Observed Adverse Effect Level) is required. Consider:\n- Searching with the CAS number or exact INCI name\n- Checking if the ingredient has an alternative name\n- The substance may not have published toxicology data`,
              },
            ],
          };
        }

        // Get exposure parameters
        let dailyExposure = 0;
        let retentionFactor = 1;
        let productLabel = product_type;

        if (exposure) {
          dailyExposure = parseFloat(String(exposure.estimated_daily_amount_g_per_day || exposure.calculated_daily_exposure_g_per_day || 0));
          retentionFactor = parseFloat(String(exposure.retention_factor || 1));
          productLabel = String(exposure.product_type || product_type);
        } else {
          // Default values if product type not found
          const defaults: Record<string, [number, number]> = {
            "body lotion": [17.4, 1],
            "face cream": [1.54, 1],
            "hand cream": [2.16, 1],
            "shampoo": [10.46, 0.01],
            "shower gel": [18.67, 0.01],
            "lipstick": [0.057, 1],
            "toothpaste": [2.75, 0.05],
            "mouthwash": [21.62, 0.1],
            "deodorant": [1.5, 1],
            "hair styling": [3.92, 0.1],
            "mascara": [0.025, 1],
            "eyeliner": [0.005, 1],
            "foundation": [0.51, 1],
            "hair dye": [100, 0.001],
          };

          const key = Object.keys(defaults).find(k =>
            product_type.toLowerCase().includes(k)
          );
          if (key) {
            dailyExposure = defaults[key][0];
            retentionFactor = defaults[key][1];
          } else {
            dailyExposure = 17.4; // default: body lotion (worst case leave-on)
            retentionFactor = 1;
          }
        }

        // Dermal absorption: use override > ingredient DB > default 50%
        const da = dermal_absorption ||
          (ing && ing.da ? parseFloat(String(ing.da)) : 50);

        // 3. Calculate SED
        // SED = (daily_exposure_mg × concentration/100 × retention_factor × dermal_absorption/100) / body_weight
        // dailyExposure is in g/day, multiply by 1000 to convert to mg/day (NOAEL is in mg/kg/day)
        const sed = (dailyExposure * 1000 * (concentration / 100) * retentionFactor * (da / 100)) / bw;

        // Convert NOAEL to mg/kg/day if needed (assume already in mg/kg/day)
        const noaelMgKgDay = noael;

        // 4. Calculate MoS
        const mos = noaelMgKgDay / sed;
        const passes = mos >= 100;

        // 5. Format response
        let text = `## Margin of Safety Calculation\n\n`;
        text += `### Input Parameters\n`;
        text += `- **Ingredient:** ${ing ? ing.name : q}${ing && ing.cas ? ` (CAS: ${ing.cas})` : ""}\n`;
        text += `- **Concentration:** ${concentration}%\n`;
        text += `- **Product type:** ${productLabel}\n`;
        text += `- **Body weight:** ${bw} kg\n\n`;

        text += `### SCCS Exposure Parameters\n`;
        text += `- **Daily exposure (Eproduct):** ${dailyExposure} g/day\n`;
        text += `- **Retention factor:** ${retentionFactor}\n`;
        text += `- **Dermal absorption:** ${da}%${dermal_absorption ? " (user-specified)" : ing && ing.da ? " (from database)" : " (SCCS default)"}\n\n`;

        text += `### Toxicological Reference\n`;
        text += `- **NOAEL:** ${noaelMgKgDay} mg/kg/day\n`;
        text += `- **Source:** ${noaelSource}\n\n`;

        text += `### Calculation\n`;
        text += `\`\`\`\n`;
        text += `SED = (${dailyExposure} g/day × ${concentration}/100 × ${retentionFactor} × ${da}/100) / ${bw} kg\n`;
        text += `SED = ${sed.toFixed(6)} mg/kg/day\n\n`;
        text += `MoS = NOAEL / SED\n`;
        text += `MoS = ${noaelMgKgDay} / ${sed.toFixed(6)}\n`;
        text += `MoS = ${mos.toFixed(1)}\n`;
        text += `\`\`\`\n\n`;

        text += `### Result\n`;
        text += `- **MoS = ${mos.toFixed(1)}**\n`;
        text += `- **SCCS threshold: MoS > 100**\n`;
        text += `- **Verdict: ${passes ? "PASSES — Considered safe at this concentration" : "FAILS — MoS below 100, concentration may need to be reduced"}**\n\n`;

        if (!passes) {
          const maxConc = (noaelMgKgDay * bw * 100) / (dailyExposure * retentionFactor * (da / 100) * 100);
          text += `### Recommendation\n`;
          text += `To achieve MoS > 100, maximum concentration should be ≤ **${maxConc.toFixed(3)}%**\n`;
        }

        text += `\n---\n*Calculation follows SCCS Notes of Guidance (11th Revision, SCCS/1628/21)*`;

        return { content: [{ type: "text" as const, text }] };
      }
    );
  }
}

// Worker entry point — handles HTTP transport
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          name: "Roots by Benda MCP Server",
          version: "1.0.0",
          status: "healthy",
          tools: ["check_ingredient", "check_formula", "search_ingredients", "calculate_mos"],
          data: {
            ingredients: "30,000+",
            noael_studies: "46,000+",
            jurisdictions: "55+",
          },
          docs: "https://rootsbybenda.com",
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // SSE transport (legacy clients)
    if (url.pathname === "/sse" || url.pathname.startsWith("/sse/")) {
      return RootsMCP.serveSSE("/sse").fetch(request, env, ctx);
    }

    // Streamable HTTP transport (new spec)
    if (url.pathname === "/mcp") {
      return RootsMCP.serve("/mcp").fetch(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },
};

// RootsMCP is already exported via `export class` above
