import { McpAgent, getMcpAuthContext } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Escape LIKE special characters in user input to prevent wildcard injection
function escapeLike(s: string): string {
  return s.replace(/[%_\\]/g, '\\$&');
}

interface Env {
  DB: D1Database;
  MCP_OBJECT: DurableObjectNamespace;
  // Auth env — required for Pro-tier gating. See KAIROS #41 audit_codex_rescue ledger
  // and HARD RULE #2 (no-premium-data-leakage). Without these, every caller is treated
  // as free tier (under-grant by design — better than over-granting premium data).
  MCP_KEY_SECRET?: string;
  SUPABASE_URL?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
}

// --- Auth: HMAC-validated MCP key + Supabase plan lookup ---
// MCP keys are issued by rootsbybenda-site/functions/api/mcp-key.js using the
// SAME MCP_KEY_SECRET. Format: mcp_<base64url(user_id)>_<sha256_hmac[:32]>.
// Free callers (no key, invalid key, non-paid plan) get public-source data only;
// premium computed values (MoS, NOAEL, dermal absorption, formulation risk) are
// gated per HARD RULE #2.

const PAID_PLANS = new Set(["starter", "trial", "professional", "enterprise"]);
const ADMIN_EMAILS = ["benda5505@gmail.com"];

interface AuthProps extends Record<string, unknown> {
  tier: "paid" | "free";
  user_id: string | null;
  plan: string;
}

function base64urlDecodeToString(b64url: string): string {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  return atob(padded);
}

async function hmacSha256Hex(message: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Validate Authorization: Bearer mcp_<...>_<...> against MCP_KEY_SECRET, then
 * look up profile.plan in Supabase. Returns the effective tier ("paid" / "free")
 * plus user_id + plan. Anonymous / invalid / non-paid → tier "free".
 *
 * Designed to under-grant on every error path: missing secret, missing Supabase
 * config, lookup failures all return free tier rather than crashing or silently
 * granting paid access.
 */
async function resolveAuth(request: Request, env: Env): Promise<AuthProps> {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(mcp_[A-Za-z0-9_-]+_[a-f0-9]{32})\s*$/i);
  if (!match) return { tier: "free", user_id: null, plan: "anonymous" };

  const key = match[1];
  const parts = key.split("_");
  if (parts.length !== 3 || parts[0] !== "mcp") {
    return { tier: "free", user_id: null, plan: "anonymous" };
  }
  const userIdB64 = parts[1];
  const providedHmac = parts[2].toLowerCase();

  if (!env.MCP_KEY_SECRET) {
    console.error("resolveAuth: MCP_KEY_SECRET not configured");
    return { tier: "free", user_id: null, plan: "anonymous" };
  }

  let userId: string;
  try {
    userId = base64urlDecodeToString(userIdB64);
  } catch {
    return { tier: "free", user_id: null, plan: "anonymous" };
  }
  if (!userId) return { tier: "free", user_id: null, plan: "anonymous" };

  const computed = (await hmacSha256Hex(userId, env.MCP_KEY_SECRET)).slice(0, 32);
  if (!constantTimeEqual(computed, providedHmac)) {
    return { tier: "free", user_id: null, plan: "anonymous" };
  }

  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error("resolveAuth: Supabase env not configured — falling through to free tier");
    return { tier: "free", user_id: null, plan: "anonymous" };
  }

  // Admin override by email
  let userEmail: string | null = null;
  try {
    const userRes = await fetch(
      `${env.SUPABASE_URL}/auth/v1/admin/users/${userId}`,
      {
        headers: {
          Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        },
      }
    );
    if (userRes.ok) {
      const user = (await userRes.json()) as { email?: string };
      userEmail = user.email || null;
    }
  } catch (e) {
    console.error("resolveAuth: admin user lookup failed", e);
  }

  if (userEmail && ADMIN_EMAILS.includes(userEmail)) {
    return { tier: "paid", user_id: userId, plan: "enterprise" };
  }

  let plan = "free";
  try {
    const profileRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/profiles?id=eq.${userId}&select=plan`,
      {
        headers: {
          Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        },
      }
    );
    if (profileRes.ok) {
      const profiles = (await profileRes.json()) as Array<{ plan?: string }>;
      if (profiles.length > 0 && profiles[0].plan) {
        const raw = profiles[0].plan;
        const dbPlan = raw === "pro" ? "professional" : raw;
        if (PAID_PLANS.has(dbPlan)) {
          return { tier: "paid", user_id: userId, plan: dbPlan };
        }
        plan = dbPlan;
      }
    }
  } catch (e) {
    console.error("resolveAuth: profile lookup failed", e);
  }

  return { tier: "free", user_id: userId, plan };
}

/**
 * Read the auth context that the Worker fetch handler set on ctx.props.
 * Returns true if the caller's HMAC validated AND their plan is in PAID_PLANS
 * (or admin email override). False on any other condition — no-key, invalid key,
 * Supabase-down, free plan. Use to gate premium-field emission per HARD RULE #2.
 */
function isPaid(): boolean {
  const auth = getMcpAuthContext();
  return (auth?.props as AuthProps | undefined)?.tier === "paid";
}

/**
 * Standard upgrade-required response for tools that have no free-tier function
 * (calculate_mos is the only one currently — it's a Roots-computed value, not
 * public regulatory data).
 */
function upgradeRequiredResponse(tool: string) {
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({
        error: "subscription_required",
        message: `${tool} requires a Roots Pro subscription (Starter / Professional / Enterprise / Trial). Premium computed values like Margin of Safety synthesis are gated; public regulatory data remains available via check_ingredient and search_ingredients on the free tier.`,
        upgrade_url: "https://rootsbybenda.com/pricing",
        get_api_key: "https://rootsbybenda.com/account/api-key",
        source: "Roots by Benda — rootsbybenda.com",
      }),
    }],
  };
}

/**
 * Input bounds error — K40 audit P0 fix on calculate_mos (concentration / body_weight /
 * dermal_absorption could be 0, negative, or non-finite producing Infinity MoS).
 * Returns 400-class structured error WITHOUT computing or returning any premium data.
 */
function boundsErrorResponse(message: string) {
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({
        error: "invalid_input",
        message,
        source: "Roots by Benda — rootsbybenda.com",
      }),
    }],
  };
}

/**
 * Strip Roots-computed premium fields from a check_ingredient result for free
 * callers. Public-source values (regulatory status, jurisdictional profile,
 * SVHC, allergen, IFRA, CIR conclusion enum) display freely per the April 11
 * `no-premium-data-leakage` revision — these ARE the SEO moat. Only
 * Roots-synthesized values gate.
 */
function stripPremiumFields(result: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...result };
  delete out.safety_data;
  delete out.mos_calculations;
  delete out.sccs_noael_values;
  delete out.dermal_penetration;
  // Keep: name, inci, cas, function, category, safety_rating, concern_level,
  //       regulatory, expert_verdict, regulatory_flags, noael_studies (public
  //       SCCS extracted), safety_opinions, eu_allergen, ifra_standard,
  //       echa_svhc, endocrine_disruptor, china_iecic, jurisdictional_profile,
  //       cir_conclusion, sensitization_profile, jurisdiction_*, source.
  out._gated = true;
  out._gated_fields = ["safety_data", "mos_calculations", "sccs_noael_values", "dermal_penetration"];
  out._upgrade_url = "https://rootsbybenda.com/pricing";
  out._get_api_key = "https://rootsbybenda.com/account/api-key";
  return out;
}
// --- End auth ---

export class RootsMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "roots-by-benda",
    version: "1.1.3",
  });

  async init() {
    // Tool 1: check_ingredient — lookup by name, INCI, or CAS number
    this.server.tool(
      "check_ingredient",
      "Use this tool when the user asks about the safety, regulatory status, or compliance of a cosmetic ingredient under EU Regulation 1223/2009, US FDA, Korea MFDS, Japan MHLW, ASEAN, Saudi SFDA, Canada Hotlist, Australia SUSMP, ECHA SVHC, California Prop 65, California TFCA, or Washington TFCA. Accepts common name, INCI name (e.g. 'Retinol', 'Sodium Lauryl Sulfate'), or CAS number (e.g. '68-26-8', '151-21-3'). Returns: SCCS safety opinion, EU Annex II/III/V/VI classification, pre-calculated Margin of Safety (MoS) value, NOAEL reference, dermal absorption, sensitization profile, CIR conclusion, endocrine-disruptor status, ECHA SVHC listing, China IECIC status, and jurisdiction-specific restrictions across 12 regulatory bodies. Backed by 884,345 rows of primary-source-traceable data from rootsbybenda.com. Do not use for general chemistry queries unrelated to cosmetic ingredient compliance.",
      {
        query: z
          .string()
          .describe(
            "Common name (e.g. 'Retinol'), INCI name (International Nomenclature of Cosmetic Ingredients — the standard EU/ISO identifier defined in Regulation (EC) No 1223/2009, e.g. 'RETINOL'), or CAS number (Chemical Abstracts Service registry number, e.g. '68-26-8'). INCI is the preferred format for exact matching."
          ),
        jurisdiction: z
          .string()
          .optional()
          .describe(
            "Optional filter for jurisdiction_restrictions table. Legacy codes accepted: 'EU', 'US', 'CN', 'CA', 'KR', 'JP', 'BR', 'ASEAN', 'GCC', 'AU', 'IN', 'UK'. If omitted, the response still includes the full jurisdictional_profile across all 12 supported regulatory bodies from jurisdictional_status — use that instead for multi-jurisdiction queries."
          ),
      },
      async ({ query, jurisdiction }) => {
        const paid = isPaid();

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

        // --- All enrichment queries in parallel ---
        const inci = (ingredient.inci as string) || "";
        const cas = (ingredient.cas as string) || "";
        const nameStr = (ingredient.name as string) || "";
        const nameEscaped = escapeLike(nameStr);

        const [
          noaelStudies,
          regLists,
          jurisdictionResults,
          safetyOpinions,
          allergenCheck,
          ifraCheck,
          svhcCheck,
          edCheck,
          iecicCheck,
          cirCheck,
          sensitCheck,
          mosCalcResults,
          sccsNoaelResults,
          dermalPenCheck,
          jurisdStatus,
        ] = await Promise.all([
          // 1. NOAEL studies
          // KAIROS #33 TD#49: filter endpoint_type='NOAEL' + clean unit + no inequality qualifier
          // so MCP consumers (Claude agents, downstream tools) never receive
          // LD50/LC50/LOAEL values labeled as NOAEL in the tool response.
          this.env.DB.prepare(
            `SELECT endpoint_type, value, qualifier, unit, study_type, route, duration, species, source, reference
             FROM noael_studies
             WHERE (substance_name = ? COLLATE NOCASE OR cas_number = ?)
               AND UPPER(endpoint_type) = 'NOAEL'
               AND (qualifier IS NULL OR qualifier = '' OR qualifier = '=')
               AND unit LIKE '%mg/kg%'
             LIMIT 10`
          ).bind(nameStr, cas).all(),

          // 2. Regulatory list entries
          this.env.DB.prepare(
            `SELECT list_key, list_name FROM regulatory_lists
             WHERE chemical_name = ? COLLATE NOCASE OR cas_number = ?
             LIMIT 20`
          ).bind(nameStr, cas).all(),

          // 3. Jurisdiction restrictions (always query — filter result later)
          jurisdiction
            ? this.env.DB.prepare(
                `SELECT jurisdiction, status, max_concentration_percent, product_type_restriction, conditions, regulation_reference
                 FROM jurisdiction_restrictions
                 WHERE (inci_name = ? COLLATE NOCASE OR cas_number = ? OR ingredient_name = ? COLLATE NOCASE)
                   AND jurisdiction = ? COLLATE NOCASE
                 LIMIT 10`
              ).bind(inci, cas, nameStr, jurisdiction.toUpperCase()).all()
            : Promise.resolve({ results: [] as Record<string, unknown>[] }),

          // 4. SCCS/CIR safety opinions
          this.env.DB.prepare(
            `SELECT source, sccs_reference, noael_value, noael_unit, noael_route,
                    max_concentration_percent, product_type, safety_verdict, conclusion_text, opinion_date
             FROM safety_opinions
             WHERE ingredient_name LIKE ? ESCAPE '\\' COLLATE NOCASE
                OR cas_number = ?
             LIMIT 10`
          ).bind(`%${nameEscaped}%`, cas).all(),

          // 5. EU allergen status
          this.env.DB.prepare(
            `SELECT annex_iii_entry, chemical_name, inci_name, cas_numbers, category, status,
                    leave_on_threshold_pct, rinse_off_threshold_pct, additional_restrictions
             FROM eu_allergens WHERE inci_name = ? COLLATE NOCASE OR cas_numbers LIKE ? LIMIT 1`
          ).bind(inci || nameStr, `%${cas}%`).first(),

          // 6. IFRA fragrance standard
          this.env.DB.prepare(
            `SELECT std_number, ifra_name, cas_numbers, recommendation_type, amendment, publication_date
             FROM ifra_standards WHERE cas_numbers LIKE ? OR ifra_name LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 1`
          ).bind(`%${cas}%`, `%${nameEscaped}%`).first(),

          // 7. ECHA SVHC status
          this.env.DB.prepare(
            `SELECT substance_name, cas_number, reason, date_included
             FROM echa_svhc WHERE cas_number = ? OR substance_name LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 1`
          ).bind(cas, `%${nameEscaped}%`).first(),

          // 8. Endocrine disruptor status
          this.env.DB.prepare(
            `SELECT chemical_name, cas_number, categories, alternative_names, source
             FROM endocrine_disruptors WHERE cas_number = ? OR chemical_name LIKE ? ESCAPE '\\' COLLATE NOCASE LIMIT 1`
          ).bind(cas, `%${nameEscaped}%`).first(),

          // 9. China IECIC listing
          this.env.DB.prepare(
            `SELECT inci_name, chinese_name, remarks FROM china_iecic
             WHERE inci_name = ? COLLATE NOCASE LIMIT 1`
          ).bind(inci || nameStr).first(),

          // 10. CIR safety conclusions
          this.env.DB.prepare(
            `SELECT conclusion, max_concentration, restrictions, report_reference, original_year, latest_review_year
             FROM cir_safety_conclusions WHERE inci_name = ? COLLATE NOCASE OR cas_number = ? LIMIT 1`
          ).bind(inci || nameStr, cas).first(),

          // 11. Sensitization profile
          this.env.DB.prepare(
            `SELECT eu_allergen_listed, allergen_class, cross_reactivity_group, patch_test_frequency_pct,
                    sensitization_rate, common_reaction_type, ifra_restricted, ifra_max_level_pct, source
             FROM sensitization_profiles WHERE inci_name = ? COLLATE NOCASE LIMIT 1`
          ).bind(inci || nameStr).first(),

          // 12. MoS calculations — DEFER-BY-REMOVAL for free tier per K40 audit P0
          // recommendation (HR-1: don't fetch then strip — gate at the query layer
          // so timing/error vectors can't leak premium row counts).
          paid
            ? this.env.DB.prepare(
                `SELECT noael_mg_kg_day, noael_study_source, noael_study_type, noael_species_route,
                        dermal_absorption_pct, dermal_absorption_method, sed_mg_kg_day, mos_value, mos_adequate,
                        product_type, max_use_concentration_pct, safety_conclusion, sccs_opinion_number, year, notes
                 FROM mos_calculations WHERE inci_name = ? COLLATE NOCASE OR cas_number = ?
                 ORDER BY year DESC LIMIT 5`
              ).bind(inci || nameStr, cas).all()
            : Promise.resolve({ results: [] as Record<string, unknown>[] }),

          // 13. SCCS NOAEL database
          this.env.DB.prepare(
            `SELECT noael_mgkgday, loael_mgkgday, route, species, study_type, study_duration,
                    absorption_pct_used_by_sccs, sccs_opinion_number, opinion_year
             FROM sccs_noael_database WHERE inci_name = ? COLLATE NOCASE OR cas_number = ?
             ORDER BY opinion_year DESC LIMIT 5`
          ).bind(inci || nameStr, cas).all(),

          // 14. Dermal penetration profile
          this.env.DB.prepare(
            `SELECT molecular_weight_da, log_p_value, skin_penetration_level, penetration_depth,
                    absorption_pct, systemic_absorption, bioavailability_topical_pct, safety_margin_factor, source
             FROM dermal_penetration_profiles WHERE inci_name = ? COLLATE NOCASE LIMIT 1`
          ).bind(inci || nameStr).first(),

          // 15. Jurisdictional status — 12-jurisdiction cleanly-normalized regulatory profile
          //     (EU, US_FDA, Korea_MFDS, Japan_MHLW, ASEAN, Saudi_SFDA, Canada_Hotlist,
          //     Australia_SUSMP, ECHA_SVHC, California_Prop65, California_TFCA, Washington_TFCA)
          //     Matches ingredients.key first, CAS second, and the 'cas:<number>' synthetic key
          //     used for substances not in the curated INCI table (per KAIROS #15 pivot).
          this.env.DB.prepare(
            `SELECT jurisdiction, status, max_concentration, product_scope, conditions,
                    source_reference, effective_date
             FROM jurisdictional_status
             WHERE substance_key = ? OR substance_key = 'cas:' || ? OR cas_number = ?
             ORDER BY jurisdiction ASC, status ASC
             LIMIT 60`
          ).bind(
            (ingredient.key as string) || "",
            cas,
            cas
          ).all(),
        ]);

        const jurisdictionRestrictions = (jurisdictionResults.results || []) as Record<string, unknown>[];

        // --- Build result object ---
        const result: Record<string, unknown> = {
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
          data_verified: "2026-04",
          db_rows_total: 884345,
          jurisdictions_covered: 12,
        };

        // Attach enrichment results
        if (safetyOpinions.results && safetyOpinions.results.length > 0) {
          result.safety_opinions = (safetyOpinions.results as Record<string, unknown>[]).map((so) => ({
            source: so.source,
            reference: so.sccs_reference || null,
            noael_value: so.noael_value || null,
            noael_unit: so.noael_unit || null,
            noael_route: so.noael_route || null,
            max_concentration_percent: so.max_concentration_percent || null,
            product_type: so.product_type || null,
            verdict: so.safety_verdict,
            conclusion: so.conclusion_text || null,
            date: so.opinion_date || null,
          }));
        }

        if (allergenCheck) {
          result.eu_allergen = {
            status: allergenCheck.status,
            category: allergenCheck.category,
            leave_on_threshold: allergenCheck.leave_on_threshold_pct,
            rinse_off_threshold: allergenCheck.rinse_off_threshold_pct,
            restrictions: allergenCheck.additional_restrictions || null,
          };
        }

        if (ifraCheck) {
          result.ifra_standard = {
            type: ifraCheck.recommendation_type,
            amendment: ifraCheck.amendment,
            std_number: ifraCheck.std_number || null,
            publication_date: ifraCheck.publication_date || null,
          };
        }

        if (svhcCheck) {
          result.echa_svhc = {
            status: "SUBSTANCE_OF_VERY_HIGH_CONCERN",
            reason: svhcCheck.reason,
            date_added: svhcCheck.date_included,
          };
        }

        if (edCheck) {
          result.endocrine_disruptor = {
            categories: edCheck.categories,
            alternative_names: edCheck.alternative_names || null,
            source: edCheck.source || null,
          };
        }

        if (iecicCheck) {
          result.china_iecic = {
            status: "listed",
            chinese_name: iecicCheck.chinese_name,
            remarks: iecicCheck.remarks || null,
          };
        } else {
          result.china_iecic = { status: "NOT_LISTED" };
        }

        if (jurisdiction) {
          result.jurisdiction_checked = jurisdiction.toUpperCase();
          if (jurisdictionRestrictions.length > 0) {
            result.jurisdiction_restrictions = jurisdictionRestrictions.map((jr) => ({
              status: jr.status,
              max_concentration: jr.max_concentration_percent || null,
              product_restriction: jr.product_type_restriction || null,
              conditions: jr.conditions || null,
              regulation: jr.regulation_reference || null,
            }));
          } else {
            result.jurisdiction_restrictions = [];
            result.jurisdiction_note = `No specific restrictions found for this ingredient in ${jurisdiction.toUpperCase()}. This may mean it is permitted without special limits, or data is not yet available for this jurisdiction.`;
          }
        }

        // CIR safety conclusion
        if (cirCheck) {
          result.cir_conclusion = {
            verdict: (cirCheck.conclusion as string || "").replace(/_/g, " "),
            max_concentration: cirCheck.max_concentration || null,
            restrictions: cirCheck.restrictions || null,
            report_reference: cirCheck.report_reference || null,
            original_year: cirCheck.original_year || null,
            latest_review_year: cirCheck.latest_review_year || null,
          };
        }

        // Sensitization profile
        if (sensitCheck) {
          result.sensitization_profile = {
            rate: sensitCheck.sensitization_rate,
            allergen_class: sensitCheck.allergen_class,
            eu_allergen_listed: sensitCheck.eu_allergen_listed,
            patch_test_positive_pct: sensitCheck.patch_test_frequency_pct || null,
            cross_reactivity_group: sensitCheck.cross_reactivity_group || null,
            reaction_type: sensitCheck.common_reaction_type || null,
            ifra_restricted: sensitCheck.ifra_restricted,
            ifra_max_level_pct: sensitCheck.ifra_max_level_pct || null,
          };
        }

        // MoS calculations
        if (mosCalcResults.results && mosCalcResults.results.length > 0) {
          result.mos_calculations = (mosCalcResults.results as Record<string, unknown>[]).map((m) => ({
            noael_mg_kg_day: m.noael_mg_kg_day || null,
            noael_study_source: m.noael_study_source || null,
            noael_study_type: m.noael_study_type || null,
            noael_species_route: m.noael_species_route || null,
            dermal_absorption_pct: m.dermal_absorption_pct || null,
            dermal_absorption_method: m.dermal_absorption_method || null,
            sed_mg_kg_day: m.sed_mg_kg_day || null,
            mos_value: m.mos_value || null,
            mos_adequate: m.mos_adequate || null,
            safety_conclusion: m.safety_conclusion || null,
            product_type: m.product_type || null,
            max_use_concentration_pct: m.max_use_concentration_pct || null,
            sccs_opinion_number: m.sccs_opinion_number || null,
            year: m.year || null,
            notes: m.notes || null,
          }));
        }

        // SCCS NOAEL values
        if (sccsNoaelResults.results && sccsNoaelResults.results.length > 0) {
          result.sccs_noael_values = (sccsNoaelResults.results as Record<string, unknown>[]).map((s) => ({
            noael_mg_kg_day: s.noael_mgkgday || null,
            loael_mg_kg_day: s.loael_mgkgday || null,
            route: s.route || null,
            species: s.species || null,
            study_type: s.study_type || null,
            study_duration: s.study_duration || null,
            dermal_absorption_pct_sccs: s.absorption_pct_used_by_sccs || null,
            sccs_opinion: s.sccs_opinion_number || null,
            opinion_year: s.opinion_year || null,
          }));
        }

        // Dermal penetration profile
        if (dermalPenCheck) {
          result.dermal_penetration = {
            absorption_pct: dermalPenCheck.absorption_pct || null,
            penetration_level: dermalPenCheck.skin_penetration_level || null,
            penetration_depth: dermalPenCheck.penetration_depth || null,
            molecular_weight_da: dermalPenCheck.molecular_weight_da || null,
            log_p: dermalPenCheck.log_p_value || null,
            systemic_absorption: dermalPenCheck.systemic_absorption || null,
            bioavailability_topical_pct: dermalPenCheck.bioavailability_topical_pct || null,
            safety_margin_factor: dermalPenCheck.safety_margin_factor || null,
            source: dermalPenCheck.source || null,
          };
        }

        // Jurisdictional profile — 12-jurisdiction regulatory map per substance
        // Source: jurisdictional_status table (15,925 rows, 6,917 distinct substances,
        // 100% source-traceable; row count reflects KAIROS #18 Apr 16-17 2026 compound-CAS
        // normalization dedup — distinct-substance coverage IMPROVED from 6,845 → 6,917).
        // Competitive anchor: Coptis charges €16,000/year for comparable cross-jurisdiction view.
        if (jurisdStatus.results && jurisdStatus.results.length > 0) {
          const byJurisdiction: Record<string, Array<Record<string, unknown>>> = {};
          (jurisdStatus.results as Record<string, unknown>[]).forEach((j) => {
            const jur = (j.jurisdiction as string) || "UNKNOWN";
            if (!byJurisdiction[jur]) byJurisdiction[jur] = [];
            byJurisdiction[jur].push({
              status: j.status,
              max_concentration: j.max_concentration || null,
              product_scope: j.product_scope || null,
              conditions: j.conditions || null,
              source_reference: j.source_reference,
              effective_date: j.effective_date || null,
            });
          });
          result.jurisdictional_profile = {
            jurisdictions_with_opinion: Object.keys(byJurisdiction).length,
            total_opinions: jurisdStatus.results.length,
            covered: [
              "EU", "US_FDA", "Korea_MFDS", "Japan_MHLW", "ASEAN", "Saudi_SFDA",
              "Canada_Hotlist", "Australia_SUSMP", "ECHA_SVHC",
              "California_Prop65", "California_TFCA", "Washington_TFCA",
            ],
            by_jurisdiction: byJurisdiction,
          };
        } else {
          result.jurisdictional_profile = {
            jurisdictions_with_opinion: 0,
            total_opinions: 0,
            covered: [
              "EU", "US_FDA", "Korea_MFDS", "Japan_MHLW", "ASEAN", "Saudi_SFDA",
              "Canada_Hotlist", "Australia_SUSMP", "ECHA_SVHC",
              "California_Prop65", "California_TFCA", "Washington_TFCA",
            ],
            note: "No record found in this database for the 12 covered jurisdictions. Do not infer permitted status without checking the primary regulation directly — absence of record is not affirmative compliance clearance.",
          };
        }

        // HARD RULE #2 tier gating: strip Roots-computed premium fields
        // (safety_data block, mos_calculations, sccs_noael_values, dermal_penetration)
        // for free callers. Public-source data (regulatory, jurisdictional, allergen,
        // SVHC, CIR conclusion enum, NOAEL studies extracted) stays — these ARE the
        // SEO moat per the April 11 no-premium-data-leakage revision.
        const finalResult = paid ? result : stripPremiumFields(result);

        return {
          content: [{ type: "text" as const, text: JSON.stringify(finalResult, null, 2) }],
        };
      }
    );

    // Tool 2: check_formula — batch check a list of ingredients
    this.server.tool(
      "check_formula",
      "Use this tool when the user provides an INCI deck, product formula, or ingredient list (comma or newline separated, up to 50 items) and wants a one-shot compliance scan for a finished cosmetic product. Returns per-ingredient regulatory status, flagged restricted/banned substances with jurisdiction-specific citations, overall formula risk level (LOW / MODERATE / HIGH), and actionable compliance notes. Coverage: EU Regulation 1223/2009, US FDA, Korea MFDS, Japan MHLW, ASEAN, Saudi SFDA, Canada Hotlist, Australia SUSMP, and 4 additional US-state jurisdictions (California Prop 65, California TFCA, Washington TFCA) via the jurisdictional_status table. Do not use for single-ingredient lookups — use check_ingredient for that; use this only for batch compliance review of a full formula.",
      {
        ingredients: z
          .string()
          .describe(
            "Comma-separated or newline-separated list of INCI ingredient names (e.g. 'Aqua, Retinol, Cetearyl Alcohol, Titanium Dioxide, Phenoxyethanol'). Max 50 ingredients per call. Typical usage: paste an INCI declaration straight from a product label."
          ),
        jurisdiction: z
          .string()
          .optional()
          .describe(
            "Optional target jurisdiction for compliance focus. Supported codes: 'EU' (Regulation 1223/2009), 'US' / 'US_FDA', 'Korea_MFDS', 'Japan_MHLW', 'ASEAN', 'Saudi_SFDA', 'Canada_Hotlist', 'Australia_SUSMP'. Legacy codes 'CN', 'CA', 'KR', 'JP', 'BR', 'GCC', 'AU', 'IN', 'UK' accepted for backward compat. If omitted, defaults to EU + US multi-jurisdiction scan."
          ),
      },
      async ({ ingredients, jurisdiction }) => {
        const paid = isPaid();

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
              flags,
            };
            // HARD RULE #2 (K40 audit HR-3): noael_value is Roots-computed premium content
            if (paid) entry.noael = ingredient.noael_value || null;

            // Check jurisdiction-specific restrictions if jurisdiction is provided
            if (jurisdiction) {
              const jrResults = await this.env.DB.prepare(
                `SELECT status, max_concentration_percent, product_type_restriction, conditions, regulation_reference
                 FROM jurisdiction_restrictions
                 WHERE (inci_name = ? COLLATE NOCASE OR cas_number = ? OR ingredient_name = ? COLLATE NOCASE)
                   AND jurisdiction = ? COLLATE NOCASE
                 LIMIT 5`
              )
                .bind(
                  (ingredient.inci as string) || "",
                  (ingredient.cas as string) || "",
                  (ingredient.name as string) || "",
                  jurisdiction.toUpperCase()
                )
                .all();

              const jRestrictions = (jrResults.results || []) as Record<string, unknown>[];
              if (jRestrictions.length > 0) {
                entry.jurisdiction_restrictions = jRestrictions.map((jr) => ({
                  status: jr.status,
                  max_concentration: jr.max_concentration_percent || null,
                  product_restriction: jr.product_type_restriction || null,
                  conditions: jr.conditions || null,
                  regulation: jr.regulation_reference || null,
                }));
              }
            }

            // Check China IECIC status if jurisdiction is CN/China
            if (jurisdiction && ["CN", "CHINA"].includes(jurisdiction.toUpperCase())) {
              const inciName = (ingredient.inci as string) || (ingredient.name as string) || "";
              const iecicResult = await this.env.DB.prepare(
                `SELECT inci_name, chinese_name, remarks FROM china_iecic
                 WHERE inci_name = ? COLLATE NOCASE LIMIT 1`
              )
                .bind(inciName)
                .first();

              if (iecicResult) {
                entry.china_iecic = {
                  status: "listed",
                  chinese_name: iecicResult.chinese_name,
                  inci_name: iecicResult.inci_name,
                  remarks: iecicResult.remarks || null,
                };
              } else {
                entry.china_iecic = {
                  status: "NOT_LISTED",
                  warning: "Not in IECIC — requires new cosmetic ingredient registration with NMPA (3+ year process)",
                };
              }
            }

            results.push(entry);

            // Flag based on EU/US data OR jurisdiction-specific restrictions
            const jrBanned = Array.isArray(entry.jurisdiction_restrictions) &&
              (entry.jurisdiction_restrictions as Record<string, unknown>[]).some(
                (jr) => jr.status === "banned" || jr.status === "prohibited"
              );
            const jrRestricted = Array.isArray(entry.jurisdiction_restrictions) &&
              (entry.jurisdiction_restrictions as Record<string, unknown>[]).some(
                (jr) => jr.status === "restricted"
              );

            const chinaNotListed = entry.china_iecic &&
              (entry.china_iecic as Record<string, unknown>).status === "NOT_LISTED";

            if (
              ingredient.safety === "POOR" ||
              ingredient.concern === "High" ||
              (ingredient.eu_status as string)?.includes("banned") ||
              (ingredient.eu_status as string)?.includes("restricted") ||
              flags.length > 0 ||
              jrBanned ||
              jrRestricted ||
              chinaNotListed
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

        const summary: Record<string, unknown> = {
          total_ingredients: names.length,
          found,
          not_found: notFound,
          flagged_count: flagged.length,
          all_results: results,
          jurisdiction_checked: jurisdiction || "EU + US (default)",
          source: "Roots by Benda — rootsbybenda.com",
        };
        if (paid) {
          // HARD RULE #2 (K40 audit HR-3): formula-level risk synthesis is Roots-
          // computed premium content. Free callers see per-ingredient public regulatory
          // status only — no overall risk_level, no flagged_ingredients reasoning.
          summary.risk_level =
            flagged.length === 0
              ? "LOW"
              : flagged.length <= 2
                ? "MODERATE"
                : "HIGH";
          summary.flagged_ingredients = flagged.map((f) => {
            const reasons: string[] = [];
            if (f.eu_status) reasons.push(`EU: ${f.eu_status}`);
            if (f.concern) reasons.push(`concern: ${f.concern}`);
            if (Array.isArray(f.jurisdiction_restrictions)) {
              (f.jurisdiction_restrictions as Record<string, unknown>[]).forEach((jr) => {
                reasons.push(`${jurisdiction?.toUpperCase()}: ${jr.status}${jr.max_concentration ? ` (max ${jr.max_concentration}%)` : ""}`);
              });
            }
            if (f.china_iecic && (f.china_iecic as Record<string, unknown>).status === "NOT_LISTED") {
              reasons.push("CN: NOT in IECIC — requires new ingredient registration");
            }
            return { name: f.matched, reason: reasons.join(", ") };
          });
        } else {
          summary._gated = true;
          summary._gated_fields = ["risk_level", "flagged_ingredients", "noael"];
          summary._upgrade_url = "https://rootsbybenda.com/pricing";
          summary._get_api_key = "https://rootsbybenda.com/account/api-key";
        }

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
      "Use this tool when the user doesn't know the exact INCI name and wants to discover cosmetic ingredients by partial name, function (e.g. 'sunscreen', 'emulsifier', 'preservative', 'surfactant'), or category (e.g. 'humectant', 'UV filter', 'antioxidant'). Returns up to 20 matches per query with INCI name, CAS number, functional category, safety rating, EU status, and concern level. Fast discovery tool — best for identifying candidate ingredients before deep-diving with check_ingredient. Do not use for known INCI lookups (use check_ingredient directly); do not use for batch compliance (use check_formula).",
      {
        query: z
          .string()
          .describe(
            "Search keyword matching ingredient name (partial), function, or category. Examples: 'sunscreen' (returns UV filters), 'preservative' (returns parabens, phenoxyethanol, etc.), 'retinoid' (returns retinol family), 'hyaluronic' (returns HA derivatives)."
          ),
        limit: z
          .number()
          .optional()
          .describe("Max results to return (1-20, default 10). Use higher limits for broad exploratory queries; lower limits for specific searches."),
      },
      async ({ query, limit }) => {
        // Public discovery — no tier gate. Per April 11 no-premium-data-leakage
        // revision, INCI/CAS/function/category/safety enum are public-source fields.
        // The has_noael boolean is metadata, not the gated value itself.

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
      "Use this tool when the user needs a Margin of Safety (MoS) calculation for cosmetic safety assessment, CPSR (Cosmetic Product Safety Report) documentation, or regulatory submission under SCCS Notes of Guidance (SCCS/1647/22) methodology. Computes SED (Systemic Exposure Dose, mg/kg bw/day) from NOAEL, dermal absorption, product type exposure parameters, and use concentration, then MoS = NOAEL / SED. SCCS safety threshold is MoS > 100 for acceptable consumer risk. Returns SED, MoS value, pass/fail against SCCS-100 threshold, and full calculation trace including NOAEL source, dermal absorption basis, and SCCS exposure parameters used. Do not use for general toxicology or non-cosmetic safety margin queries — this is specifically the SCCS-methodology MoS calculation for cosmetic ingredients.",
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
        // HARD RULE #2: calculate_mos IS the formulation risk tool — Roots-computed
        // premium content. No free-tier fallback (K40 audit HR-3, HR-4).
        if (!isPaid()) return upgradeRequiredResponse("calculate_mos");

        // Input bounds — K40 audit P0 (calculate_mos:913-927 unsafe numeric inputs).
        // Reject zero/negative/non-finite values that produce Infinity or fabricated
        // safety conclusions on garbage input.
        if (!Number.isFinite(concentration) || concentration <= 0 || concentration > 100) {
          return boundsErrorResponse("concentration must be a finite number in (0, 100]");
        }
        if (body_weight !== undefined && (!Number.isFinite(body_weight) || body_weight <= 0 || body_weight > 500)) {
          return boundsErrorResponse("body_weight must be a finite positive number in (0, 500]");
        }
        if (dermal_absorption !== undefined && (!Number.isFinite(dermal_absorption) || dermal_absorption < 0 || dermal_absorption > 100)) {
          return boundsErrorResponse("dermal_absorption must be a finite number in [0, 100]");
        }

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
        // KAIROS #33 TD#49: must filter endpoint_type='NOAEL' — picking MIN(value) ASC
        // without filter returns LD50s at the bottom of the distribution (low values
        // = scary lethality data) which would then feed MoS calculations as if NOAEL.
        const noaelStudy = await this.env.DB.prepare(
          `SELECT substance_name, value, species, route, duration, study_type, source
           FROM noael_studies
           WHERE substance_name LIKE ? ESCAPE '\\' COLLATE NOCASE
             AND UPPER(endpoint_type) = 'NOAEL'
             AND (qualifier IS NULL OR qualifier = '' OR qualifier = '=')
             AND unit LIKE '%mg/kg%'
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
          version: "1.1.3",
          status: "healthy",
          tools: ["check_ingredient", "check_formula", "search_ingredients", "calculate_mos"],
          data: {
            ingredients: "30,553",
            noael_studies: "174,973",
            calculated_mos: "99,535",
            sensitization_assays: "8,898",
            jurisdictions: "55+",
          },
          docs: "https://rootsbybenda.com",
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // SEP-1649 server-card discovery (authentication.required: true — premium content)
    if (url.pathname === "/.well-known/mcp/server-card.json") {
      return Response.json({
        "$schema": "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json",
        "version": "1.0",
        "protocolVersion": "2025-06-18",
        "serverInfo": { "name": "roots-mcp-server", "title": "Roots by Benda MCP Server", "version": "1.1.3" },
        "description": "Cosmetic ingredient safety MCP — primary-source-verified regulatory + MoS data",
        "iconUrl": "https://rootsbybenda.com/icon.png",
        "documentationUrl": "https://rootsbybenda.com",
        "transport": { "type": "streamable-http", "endpoint": "/mcp" },
        "capabilities": { "tools": { "listChanged": true }, "resources": { "subscribe": false, "listChanged": false } },
        "authentication": { "required": true, "schemes": ["bearer"] },
        "tools": ["dynamic"]
      }, { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" } });
    }

    // Resolve auth tier from Authorization: Bearer mcp_<...> header BEFORE dispatching
    // to MCP transport. Set on ctx.props so getMcpAuthContext() returns it inside
    // tool handlers (per agents/mcp framework convention — `If not provided, the
    // handler will look for props in the execution context.`).
    if (url.pathname === "/sse" || url.pathname.startsWith("/sse/") || url.pathname === "/mcp") {
      const auth = await resolveAuth(request, env);
      (ctx as ExecutionContext & { props?: AuthProps }).props = auth;
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
