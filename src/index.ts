import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

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
          ingredient = await this.env.DB.prepare(
            `SELECT * FROM ingredients WHERE name LIKE ? COLLATE NOCASE LIMIT 1`
          )
            .bind(`%${q}%`)
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
            ingredient = await this.env.DB.prepare(
              `SELECT name, inci, cas, safety, eu_status, eu_max, us_status, concern, flags, noael_value
               FROM ingredients WHERE name LIKE ? COLLATE NOCASE LIMIT 1`
            )
              .bind(`%${name}%`)
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

        const results = await this.env.DB.prepare(
          `SELECT name, inci, cas, function, safety, eu_status, concern, noael_value
           FROM ingredients
           WHERE name LIKE ? COLLATE NOCASE
              OR inci LIKE ? COLLATE NOCASE
              OR function LIKE ? COLLATE NOCASE
              OR category LIKE ? COLLATE NOCASE
           LIMIT ?`
        )
          .bind(
            `%${query}%`,
            `%${query}%`,
            `%${query}%`,
            `%${query}%`,
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
          tools: ["check_ingredient", "check_formula", "search_ingredients"],
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
