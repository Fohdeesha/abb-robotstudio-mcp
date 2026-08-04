#!/usr/bin/env node

/**
 * ABB RobotStudio MCP Server — Combined SDK + RWS
 * - SDK tools (rs_*): Control RobotStudio app via ClaudeBridge Add-In
 * - RWS tools (rws_*): Control the robot controller via Robot Web Services
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createHash, randomBytes } from "node:crypto";

// ── Configuration ────────────────────────────────────────────

const BRIDGE_URL = process.env.ABB_BRIDGE_URL || "http://localhost:58080";
const RWS_URL = process.env.ABB_RWS_URL || "http://localhost:80";
const RWS_USER = process.env.ABB_RWS_USER || "Default User";
const RWS_PASS = process.env.ABB_RWS_PASS || "robotics";

// ── SDK Bridge Client (Add-In HTTP) ─────────────────────────

async function bridge(
  path: string,
  method: "GET" | "POST" = "GET",
  body?: object
): Promise<any> {
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : null,
  });
  const json = (await res.json()) as Record<string, unknown>;
  if (json.error) throw new Error(String(json.error));
  return json;
}

// ── RWS Client (Robot Web Services REST) ────────────────────

// The IRC5 issues TWO cookies and needs BOTH replayed: "-http-session-" is the
// session identifier, ABBCX alone answers 401. Keep them in a jar rather than a
// single string -- collapsing to one drops the session id, so every request
// re-runs the Digest handshake and burns one of the controller's 70 sessions
// ("Cannot add new user. ID is not unique").
const rwsCookieJar = new Map<string, string>();
function rwsCookieHeader(): string {
  return [...rwsCookieJar.values()].join("; ");
}

// ── RWS API version (IRC5/RWS1.0 vs OmniCore/RWS2.0) ─────────
// IRC5 (RobotWare 6) speaks RWS 1.0: Accept "application/xhtml+xml" (no version
// param) and I/O set via ".../{signal}?action=set". OmniCore (RobotWare 7)
// speaks RWS 2.0: Accept "application/xhtml+xml;v=2.0" and I/O set via
// ".../{signal}/set-value". Sending the versioned media type to a strict IRC5
// yields HTTP 406 ("Server cannot generate response for given accept header").
// We detect ONCE (cached) and adapt. Detection keys off the RobotWare MAJOR
// version (RW7+ => v2, RW6/lower => v1) because some IRC5 firmware/VCs leniently
// 2xx the versioned Accept -- the controller GENERATION is the reliable signal,
// not its content-negotiation strictness.
const RWS_ACCEPT_V1 = "application/xhtml+xml";
const RWS_ACCEPT_V2 = "application/xhtml+xml;v=2.0";
let rwsApiVersion: "v1" | "v2" | null = null;
let rwsReadyPromise: Promise<void> | null = null;

function rwsAccept(): string {
  return rwsApiVersion === "v2" ? RWS_ACCEPT_V2 : RWS_ACCEPT_V1;
}

// Single-flight readiness gate: the FIRST RWS call runs one serial probe that
// detects the API version AND completes the Digest handshake / seeds the
// session cookie. Every later call (including the concurrent Promise.all bursts
// in rws_controller_status / rws_get_position) then reuses that warm cookie,
// instead of each racing its own Digest handshake and minting a throwaway
// session on the controller (the 70-session cap / "ID is not unique" trap).
function ensureRwsReady(): Promise<void> {
  if (rwsApiVersion) return Promise.resolve();
  if (!rwsReadyPromise) {
    rwsReadyPromise = detectApiVersion().catch((e) => {
      rwsReadyPromise = null; // allow re-detection on the next call
      throw e;
    });
  }
  return rwsReadyPromise;
}

async function detectApiVersion(): Promise<void> {
  // Probe /rw/system with the v2 Accept. OmniCore answers 2xx; a strict IRC5
  // answers 406. Read the RobotWare version to decide by generation.
  let probe = await rwsRaw("GET", "/rw/system", undefined, undefined, RWS_ACCEPT_V2);
  let rwver = rwsExtract(probe.body, "rwversion");
  if (!rwver && probe.status === 406) {
    // Strict IRC5 rejected the versioned media type; re-read with the v1 Accept
    // to recover the version string (and confirm reachability).
    probe = await rwsRaw("GET", "/rw/system", undefined, undefined, RWS_ACCEPT_V1);
    rwver = rwsExtract(probe.body, "rwversion");
  }
  const major = parseInt((rwver.split(".")[0] || "").trim(), 10);
  if (Number.isFinite(major) && major >= 7) rwsApiVersion = "v2";
  else if (Number.isFinite(major) && major >= 1) rwsApiVersion = "v1";
  else rwsApiVersion = probe.status >= 200 && probe.status < 300 ? "v2" : "v1";
  console.error(
    `RWS API: ${rwsApiVersion}${rwver ? ` (RobotWare ${rwver})` : ""} @ ${RWS_URL}`
  );
}

function rwsOk(status: number): boolean {
  return status >= 200 && status < 300;
}

// ── HTTP Digest auth (IRC5 / RobotWare RWS requires Digest, not Basic) ──
function md5(s: string): string {
  return createHash("md5").update(s).digest("hex");
}
function parseDigestChallenge(header: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /(\w+)=(?:"([^"]*)"|([^,\s]+))/g;
  let m: RegExpExecArray | null;
  const body = header.replace(/^Digest\s+/i, "");
  while ((m = re.exec(body)) !== null) {
    out[m[1].toLowerCase()] = (m[2] ?? m[3] ?? "").trim();
  }
  return out;
}
let digestNc = 0;
function buildDigestHeader(method: string, uri: string, c: Record<string, string>): string {
  const realm = c.realm ?? "";
  const nonce = c.nonce ?? "";
  const algorithm = c.algorithm ?? "MD5";
  const ha1 = md5(`${RWS_USER}:${realm}:${RWS_PASS}`);
  const ha2 = md5(`${method}:${uri}`);
  const parts = [
    `username="${RWS_USER}"`, `realm="${realm}"`, `nonce="${nonce}"`,
    `uri="${uri}"`, `algorithm=${algorithm}`,
  ];
  if (c.qop) {
    const qop = c.qop.split(",")[0].trim();
    const nc = (++digestNc).toString(16).padStart(8, "0");
    const cnonce = randomBytes(8).toString("hex");
    const response = md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
    parts.push(`qop=${qop}`, `nc=${nc}`, `cnonce="${cnonce}"`, `response="${response}"`);
  } else {
    parts.push(`response="${md5(`${ha1}:${nonce}:${ha2}`)}"`);
  }
  if (c.opaque) parts.push(`opaque="${c.opaque}"`);
  return "Digest " + parts.join(", ");
}

// Low-level request: explicit Accept header, no version-readiness gate (the
// detector calls this directly). Handles the cookie jar + Digest handshake.
async function rwsRaw(
  method: string,
  path: string,
  body: string | undefined,
  contentType: string | undefined,
  accept: string
): Promise<{ status: number; body: string }> {
  const url = `${RWS_URL}${path}`;
  const baseHeaders: Record<string, string> = { Accept: accept };
  // NOTE body !== undefined, not truthiness: several RWS 2.0 POSTs take an
  // EMPTY form body (resetpp, mastership request/release) but still demand the
  // versioned form Content-Type -- an empty string is falsy, and the truthy
  // check silently dropped the header, turning those calls into 406
  // "Content type is not supported" rejections.
  if (body !== undefined && contentType) baseHeaders["Content-Type"] = contentType;

  const attempt = async (extra: Record<string, string>) => {
    const headers: Record<string, string> = { ...baseHeaders, ...extra };
    const cookie = rwsCookieHeader();
    if (cookie) headers["Cookie"] = cookie;
    const res = await fetch(url, { method, headers, body: body ?? null });
    const setCookie = res.headers.getSetCookie?.() ?? [];
    for (const c of setCookie) {
      const kv = c.split(";")[0] ?? "";
      const eq = kv.indexOf("=");
      if (eq <= 0) continue;
      const name = kv.slice(0, eq);
      if (name === "ABBCX" || name === "-http-session-") rwsCookieJar.set(name, kv);
    }
    return res;
  };

  // Try any existing session cookie first; on 401, answer whichever scheme the
  // controller challenges with and retry. IRC5/RWS 1.0 challenges Digest;
  // OmniCore/RWS 2.0 challenges BASIC and rejects Digest outright (measured on
  // the RW7 VC 2026-08-04: WWW-Authenticate: Basic realm="validusers@robapi.abb"
  // -- pre-fix, every rws_* call against an OmniCore died 401 here because only
  // the Digest branch existed). Both generations then issue the same
  // -http-session-/ABBCX cookie pair, so the shared jar covers both.
  let res = await attempt({});
  if (res.status === 401) {
    const www = res.headers.get("www-authenticate") || "";
    if (/digest/i.test(www)) {
      res = await attempt({ Authorization: buildDigestHeader(method, path, parseDigestChallenge(www)) });
    } else if (/basic/i.test(www)) {
      res = await attempt({
        Authorization: "Basic " + Buffer.from(`${RWS_USER}:${RWS_PASS}`).toString("base64"),
      });
    }
  }
  return { status: res.status, body: await res.text() };
}

async function rws(
  methodOrPath: string,
  pathOrBody?: string,
  bodyOrCt?: string,
  ct?: string
): Promise<{ status: number; body: string }> {
  // Support both rws("/path") and rws("POST", "/path", body, ct)
  let method: string, path: string, body: string | undefined, contentType: string | undefined;
  if (methodOrPath === "GET" || methodOrPath === "POST" || methodOrPath === "PUT") {
    method = methodOrPath; path = pathOrBody!; body = bodyOrCt; contentType = ct;
  } else {
    method = "GET"; path = methodOrPath; body = pathOrBody; contentType = bodyOrCt;
  }
  await ensureRwsReady();
  // RWS 2.0 requires the VERSIONED media type on request bodies too --
  // MEASURED on the RW7 VC 2026-08-04: a POST with a plain
  // application/x-www-form-urlencoded Content-Type answers 406 whatever the
  // Accept header says; ";v=2.0" on the Content-Type turns the same request
  // into a 204. (Same convention the egm-bridge's own RWS client uses.)
  if (rwsApiVersion === "v2" && contentType && !/;v=2\.0/.test(contentType)) {
    contentType = `${contentType};v=2.0`;
  }
  return rwsRaw(method, path, body, contentType, rwsAccept());
}

// Decode the few HTML entities RWS bodies carry in text spans (RWS 2.0 returns
// e.g. &quot;v5.5.1&quot; for a RAPID string value).
function rwsDecodeEntities(s: string): string {
  return s
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

// Resolve a bare I/O signal name to its full Network/Device/Signal path via the
// signal list (the li titles carry the full path on both generations). RWS 2.0
// REJECTS bare names on reads outright ("Invalid IO signal name passed in the
// uri", measured on the RW7 VC); RWS 1.0 accepts bare names on GET but requires
// the full path on SET (measured on the RW6 VC 2026-07-16). Full paths pass
// through untouched.
async function rwsResolveSignalPath(signal: string): Promise<string> {
  if (signal.includes("/")) return signal;
  const r = await rws("/rw/iosystem/signals");
  const re = /class="ios-signal-li" title="([^"]*)"/gi;
  let m: RegExpExecArray | null;
  const matches: string[] = [];
  while ((m = re.exec(r.body)) !== null) {
    const path = m[1];
    const leaf = path.split("/").pop() ?? "";
    if (leaf.toLowerCase() === signal.toLowerCase()) matches.push(path);
  }
  if (matches.length === 0) return signal; // let the controller report the error
  return matches[0];
}

function rwsExtract(xml: string, tag: string): string {
  const m =
    xml.match(new RegExp(`class="${tag}"[^>]*>([^<]*)<`, "i")) ??
    xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, "i"));
  return m?.[1]?.trim() ?? "";
}

function rwsExtractAll(xml: string, field: string): string[] {
  const results: string[] = [];
  const re = new RegExp(`class="${field}"[^>]*>([^<]*)<`, "gi");
  let m;
  while ((m = re.exec(xml)) !== null) results.push((m[1] ?? "").trim());
  return results;
}

// ── Helpers ──────────────────────────────────────────────────

function ok(data: any) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}
function err(e: any) {
  return { content: [{ type: "text" as const, text: `Error: ${e.message ?? e}` }] };
}

// ── MCP Server ───────────────────────────────────────────────

const server = new McpServer({
  name: "abb-robotstudio",
  version: "2.0.0",
});

// ═══════════════════════════════════════════════════════════════
// ██  SDK TOOLS (rs_*) — RobotStudio Application via Add-In  ██
// ═══════════════════════════════════════════════════════════════

server.tool("rs_ping", "Check if RobotStudio ClaudeBridge Add-In is running and connected", {},
  async () => { try { return ok(await bridge("/ping")); } catch (e: any) {
    return err(`Cannot connect to ClaudeBridge at ${BRIDGE_URL}. Is RobotStudio running?`);
  }}
);

// ── Station ──────────────────────────────────────────────────

server.tool("rs_get_station", "Get active RobotStudio station info (name, controllers)", {},
  async () => { try { return ok(await bridge("/station")); } catch (e: any) { return err(e); } }
);

server.tool("rs_get_station_objects", "List all objects in the station (robots, tools, smart components)", {},
  async () => { try { return ok(await bridge("/station/objects")); } catch (e: any) { return err(e); } }
);

server.tool("rs_save_station", "Save the active station to disk", {},
  async () => { try { return ok(await bridge("/station/save", "POST")); } catch (e: any) { return err(e); } }
);

// ── RAPID via SDK ────────────────────────────────────────────

server.tool("rs_get_tasks", "List RAPID tasks with module counts (SDK)", {},
  async () => { try { return ok(await bridge("/rapid/tasks")); } catch (e: any) { return err(e); } }
);

server.tool("rs_get_modules", "List RAPID modules in a task (SDK)",
  { task: z.string().describe("Task name, e.g. 'T_ROB1'") },
  async ({ task }) => { try {
    return ok(await bridge(`/rapid/modules?task=${encodeURIComponent(task)}`));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_read_module", "Read full RAPID source code of a module (SDK)",
  { task: z.string(), module: z.string().describe("e.g. 'module_MAIN', 'module_EGM', 'Wizard_Params'") },
  async ({ task, module }) => { try {
    return ok(await bridge(`/rapid/module/text?task=${encodeURIComponent(task)}&module=${encodeURIComponent(module)}`));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_write_module", "Write RAPID module source code into running controller (SDK)",
  { task: z.string(), module: z.string(), code: z.string().describe("Full RAPID code (MODULE ... ENDMODULE)") },
  async ({ task, module, code }) => { try {
    return ok(await bridge(`/rapid/module/text?task=${encodeURIComponent(task)}&module=${encodeURIComponent(module)}`, "POST", { code }));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_read_variable", "Read a RAPID variable's LIVE controller value (PC SDK; falls back to the station declaration if the controller is unreachable)",
  { task: z.string(), name: z.string(),
    module: z.string().optional().describe("Module name; omit to search shared data + all modules") },
  async ({ task, name, module }) => { try {
    const mod = module ? `&module=${encodeURIComponent(module)}` : "";
    return ok(await bridge(`/rapid/variable?task=${encodeURIComponent(task)}&name=${encodeURIComponent(name)}${mod}`));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_write_variable", "Set a RAPID variable initial value (SDK)",
  { task: z.string(), name: z.string(), value: z.string() },
  async ({ task, name, value }) => { try {
    return ok(await bridge(`/rapid/variable?task=${encodeURIComponent(task)}&name=${encodeURIComponent(name)}`, "POST", { value }));
  } catch (e: any) { return err(e); } }
);

// ── Simulation ───────────────────────────────────────────────

server.tool("rs_controller_status", "Get controller state via SDK (systemState, runMode, simulation)", {},
  async () => { try { return ok(await bridge("/controller/status")); } catch (e: any) { return err(e); } }
);

// ── Virtual panel / guard-stop recovery (VC only) ────────────
//
// A latched guard stop (typically 50027 "Joint Out of Range" on J5, raised from the
// controller's velocity projection well before the joint nears its bound) canNOT be
// cleared by turning motors on -- RWS ctrl-state=motoron is rejected with
// SYS_CTRL_E_REJECT (-1073445881). The operator's reset is: press the pendant
// e-stop, unlatch it, then motors on. These drive RobApi's simulated panel board to
// do exactly that. Verified live: GuardStop -> EmergencyStop -> EmergencyStopReset
// -> MotorsOn.

server.tool("rs_clear_guardstop",
  "Clear a latched guard stop on the VIRTUAL controller by pulsing the virtual pendant e-stop (press -> release -> motors on). Use when controllerState is 'guardstop'; motors-on alone will NOT clear it. VC only.",
  { motors_on: z.boolean().optional().describe("Press motors-on after releasing the e-stop (default true). False leaves the controller at MotorsOff.") },
  async ({ motors_on }) => {
    try {
      const q = motors_on === false ? "?motors_on=false" : "";
      return ok(await bridge("/panel/clear_guardstop" + q, "POST"));
    } catch (e: any) { return err(e); }
  }
);

server.tool("rs_set_estop",
  "Press or release the VIRTUAL pendant emergency stop (VC only). Mostly useful for testing e-stop handling; to recover a guard stop prefer rs_clear_guardstop.",
  { state: z.enum(["press", "release"]).describe("press = e-stop asserted, release = unlatched") },
  async ({ state }) => {
    try {
      return ok(await bridge(`/panel/estop?state=${state === "press" ? "1" : "0"}`, "POST"));
    } catch (e: any) { return err(e); }
  }
);

server.tool("rs_start_simulation", "Start RobotStudio simulation (Play)", {},
  async () => { try { return ok(await bridge("/simulation/start", "POST")); } catch (e: any) { return err(e); } }
);

server.tool("rs_stop_simulation", "Stop RobotStudio simulation", {},
  async () => { try { return ok(await bridge("/simulation/stop", "POST")); } catch (e: any) { return err(e); } }
);

server.tool("rs_pause_simulation", "Pause RobotStudio simulation", {},
  async () => { try { return ok(await bridge("/simulation/pause", "POST")); } catch (e: any) { return err(e); } }
);

server.tool("rs_reset_simulation", "Reset simulation to start position", {},
  async () => { try { return ok(await bridge("/simulation/reset", "POST")); } catch (e: any) { return err(e); } }
);

server.tool("rs_simulation_status", "Get simulation state and time", {},
  async () => { try { return ok(await bridge("/simulation/status")); } catch (e: any) { return err(e); } }
);

server.tool("rs_set_sim_speed", "Set simulation speed multiplier",
  { speed: z.number().describe("Speed multiplier (1.0 = normal)") },
  async ({ speed }) => { try {
    return ok(await bridge("/simulation/speed", "POST", { speed }));
  } catch (e: any) { return err(e); } }
);

// ── Paths & Targets ─────────────────────────────────────────

server.tool("rs_get_paths", "List all robot paths in the station", {},
  async () => { try { return ok(await bridge("/paths")); } catch (e: any) { return err(e); } }
);

server.tool("rs_get_path_targets", "Get targets/waypoints in a path",
  { path: z.string() },
  async ({ path }) => { try {
    return ok(await bridge(`/paths/targets?path=${encodeURIComponent(path)}`));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_create_path", "Create a new robot path",
  { name: z.string() },
  async ({ name }) => { try {
    return ok(await bridge("/paths/create", "POST", { name }));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_create_target", "Create a new robot target at coordinates",
  { name: z.string(), x: z.number().describe("mm"), y: z.number().describe("mm"), z: z.number().describe("mm") },
  async ({ name, x, y, z: zp }) => { try {
    return ok(await bridge("/targets/create", "POST", { name, x, y, z: zp }));
  } catch (e: any) { return err(e); } }
);

// ── Config Files & Collision ─────────────────────────────────

server.tool("rs_read_config", "Read controller config file (SYS.cfg, EIO.cfg, SIO.cfg, MOC.cfg)",
  { name: z.string().describe("e.g. 'SIO.cfg'") },
  async ({ name }) => { try {
    return ok(await bridge(`/config/read?name=${encodeURIComponent(name)}`));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_write_config", "Write controller config file",
  { name: z.string(), content: z.string() },
  async ({ name, content }) => { try {
    return ok(await bridge(`/config/write?name=${encodeURIComponent(name)}`, "POST", { content }));
  } catch (e: any) { return err(e); } }
);

server.tool("rs_check_collisions", "Run collision check on station objects", {},
  async () => { try { return ok(await bridge("/collision/check")); } catch (e: any) { return err(e); } }
);

server.tool("rs_get_position", "Get live joints + world-frame TCP for every mechanical unit of every station controller (PC SDK)", {},
  async () => { try { return ok(await bridge("/robot/position")); } catch (e: any) { return err(e); } }
);

server.tool("rs_get_io_signals", "List I/O signals via SDK", {},
  async () => { try { return ok(await bridge("/io/signals")); } catch (e: any) { return err(e); } }
);

// ═══════════════════════════════════════════════════════════════
// ██  RWS TOOLS (rws_*) — Robot Controller via Web Services   ██
// ═══════════════════════════════════════════════════════════════

// ── Controller ───────────────────────────────────────────────

server.tool("rws_controller_status", "Get controller state via RWS (opmode, motors, RAPID execution)", {},
  async () => { try {
    await ensureRwsReady();
    // RWS 2.0 renamed /rw/panel/ctrlstate -> /rw/panel/ctrl-state (the span
    // class stays "ctrlstate" on both generations).
    const ctrlPath = rwsApiVersion === "v2" ? "/rw/panel/ctrl-state" : "/rw/panel/ctrlstate";
    const [panel, opmode, exec] = await Promise.all([
      rws(ctrlPath),
      rws( "/rw/panel/opmode"),
      rws( "/rw/rapid/execution"),
    ]);
    return ok({
      controllerState: rwsExtract(panel.body, "ctrlstate"),
      operatingMode: rwsExtract(opmode.body, "opmode"),
      executionState: rwsExtract(exec.body, "ctrlexecstate"),
      cycle: rwsExtract(exec.body, "cycle"),
    });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_set_motors", "Turn motors on/off via RWS (real controller command)",
  { state: z.enum(["on", "off"]) },
  async ({ state }) => { try {
    await ensureRwsReady();
    // v2 (OmniCore): POST /rw/panel/ctrl-state with the same body, NO ?action
    // selector -- the egm-bridge's proven form (204 + live transition on RW7).
    const path = rwsApiVersion === "v2"
      ? "/rw/panel/ctrl-state"
      : "/rw/panel/ctrlstate?action=setctrlstate";
    const r = await rws("POST", path,
      `ctrl-state=motor${state}`, "application/x-www-form-urlencoded");
    return ok({ result: rwsOk(r.status) ? `Motors ${state}` : r.body });
  } catch (e: any) { return err(e); } }
);

// ── RAPID Execution ──────────────────────────────────────────

// v2 (OmniCore) execution actions are path segments with implicit mastership
// (?mastership=implicit) instead of v1's ?action= query -- the egm-bridge's
// proven forms, exercised against the RW7 VC on every bridge startup.

server.tool("rws_start_program", "Start RAPID execution on the controller via RWS",
  { mode: z.enum(["continue", "reset"]).optional() },
  async ({ mode }) => { try {
    await ensureRwsReady();
    const path = rwsApiVersion === "v2"
      ? "/rw/rapid/execution/start?mastership=implicit"
      : "/rw/rapid/execution?action=start";
    const r = await rws("POST", path,
      `regain=continue&execmode=${mode || "continue"}&cycle=forever&condition=none&stopatbp=disabled&alltaskbytsp=false`,
      "application/x-www-form-urlencoded");
    return ok({ result: rwsOk(r.status) ? "Program started" : r.body });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_stop_program", "Stop RAPID execution via RWS", {},
  async () => { try {
    await ensureRwsReady();
    const path = rwsApiVersion === "v2"
      ? "/rw/rapid/execution/stop"
      : "/rw/rapid/execution?action=stop";
    const r = await rws("POST", path,
      "stopmode=stop&usetsp=normal", "application/x-www-form-urlencoded");
    return ok({ result: rwsOk(r.status) ? "Program stopped" : r.body });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_reset_pp", "Reset RAPID program pointer via RWS", {},
  async () => { try {
    await ensureRwsReady();
    const path = rwsApiVersion === "v2"
      ? "/rw/rapid/execution/resetpp?mastership=implicit"
      : "/rw/rapid/execution?action=resetpp";
    const r = await rws("POST", path, "", "application/x-www-form-urlencoded");
    return ok({ result: rwsOk(r.status) ? "PP reset" : r.body });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_execution_state", "Get RAPID execution state via RWS", {},
  async () => { try {
    const r = await rws( "/rw/rapid/execution");
    return ok({ state: rwsExtract(r.body, "ctrlexecstate"), cycle: rwsExtract(r.body, "cycle") });
  } catch (e: any) { return err(e); } }
);

// ── RAPID Tasks & Modules (RWS) ─────────────────────────────

server.tool("rws_get_tasks", "List RAPID tasks via RWS", {},
  async () => { try {
    const r = await rws( "/rw/rapid/tasks");
    const names = rwsExtractAll(r.body, "name");
    const excstates = rwsExtractAll(r.body, "excstate");
    return ok(names.map((n, i) => ({ name: n, executionState: excstates[i] ?? "?" })));
  } catch (e: any) { return err(e); } }
);

server.tool("rws_get_modules", "List RAPID modules in a task via RWS",
  { task: z.string() },
  async ({ task }) => { try {
    await ensureRwsReady();
    // MEASURED on both live VCs (2026-08-04): RWS 1.0 (IRC5/RW6) serves the
    // module list at /rw/rapid/modules?task=<task> and answers "Resource not
    // found" (-1073414146) on the tasks/{task}/modules form; RWS 2.0
    // (OmniCore/RW7) is the exact inverse. Same rap-module-info-li shape
    // (name/type spans) either way -- only the path differs.
    const path = rwsApiVersion === "v2"
      ? `/rw/rapid/tasks/${encodeURIComponent(task)}/modules`
      : `/rw/rapid/modules?task=${encodeURIComponent(task)}`;
    const r = await rws(path);
    const names = rwsExtractAll(r.body, "name");
    const types = rwsExtractAll(r.body, "type");
    return ok(names.map((n, i) => ({ name: n, type: types[i] ?? "?" })));
  } catch (e: any) { return err(e); } }
);

// Fetch a module's full source text. The docs show inline
// <span class="module-text">; the real firmware on BOTH VC generations
// (measured 2026-08-04) instead returns a <span class="file-path"> pointing at
// a temp file the controller wrote -- a controller-fs path on OmniCore
// (fetchable via /fileservice), a HOST path on the RW6 VC (readable only on
// the RobotStudio machine; the SDK tool rs_read_module is the reliable reader
// elsewhere). Throws with a useful message on failure.
async function rwsFetchModuleText(task: string, module: string): Promise<{ text: string; source: string }> {
  const path = rwsApiVersion === "v2"
    ? `/rw/rapid/tasks/${task}/modules/${module}/text`
    : `/rw/rapid/modules/${module}?resource=module-text&task=${encodeURIComponent(task)}`;
  const r = await rws(path);
  const inline = rwsExtract(r.body, "module-text");
  if (inline) return { text: rwsDecodeEntities(inline), source: "inline" };
  const fp = rwsDecodeEntities(rwsExtract(r.body, "file-path")).replace(/^"|"$/g, "");
  if (fp) {
    if (/^[A-Za-z]:[\\/]/.test(fp)) {
      try {
        const { readFileSync } = await import("node:fs");
        return { text: readFileSync(fp, "utf8"), source: "vc-host-file" };
      } catch (e: any) {
        throw new Error(`module text is at a VC host path (${fp}) this process cannot read: ${e.message}. Use rs_read_module instead.`);
      }
    }
    const f = await rws(`/fileservice/${fp.replace(/^\//, "")}`);
    if (rwsOk(f.status)) return { text: f.body, source: "fileservice" };
    throw new Error(`module text temp file fetch failed (${f.status}) at ${fp}. Use rs_read_module instead.`);
  }
  throw new Error(`no module text in response (${r.status}): ${r.body.slice(0, 200)}`);
}

server.tool("rws_read_module", "Read RAPID module text via RWS",
  { task: z.string(), module: z.string() },
  async ({ task, module }) => { try {
    await ensureRwsReady();
    const { text, source } = await rwsFetchModuleText(task, module);
    return ok({ task, module, text, source });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_write_module",
  "Write RAPID module text via RWS (auto-mastership; VERIFIES the stored text afterwards -- the RWS form endpoint silently truncates large modules, so prefer rs_write_module for anything big)",
  { task: z.string(), module: z.string(), code: z.string() },
  async ({ task, module, code }) => { try {
    await ensureRwsReady();
    let wr: { status: number; body: string };
    if (rwsApiVersion === "v2") {
      const mr = await rws("POST", "/rw/mastership/edit/request", "", "application/x-www-form-urlencoded");
      if (!rwsOk(mr.status)) return ok({ result: `edit mastership refused (${mr.status}): ${mr.body}` });
      try {
        wr = await rws("POST",
          `/rw/rapid/tasks/${task}/modules/${module}/text?action=set`,
          `module-text=${encodeURIComponent(code)}`, "application/x-www-form-urlencoded");
      } finally {
        await rws("POST", "/rw/mastership/edit/release", "", "application/x-www-form-urlencoded").catch(() => {});
      }
    } else {
      // v1 form per the RWS 1.0 manual: POST /rw/rapid/modules/{module}
      // ?task=...&action=set-module-text with body field "text".
      await rws("POST","/rw/mastership/rapid?action=request");
      try {
        wr = await rws("POST",
          `/rw/rapid/modules/${module}?task=${encodeURIComponent(task)}&action=set-module-text`,
          `text=${encodeURIComponent(code)}`, "application/x-www-form-urlencoded");
      } finally { await rws("POST","/rw/mastership/rapid?action=release").catch(() => {}); }
    }
    if (!rwsOk(wr.status)) return ok({ result: wr.body });
    // MANDATORY post-write verification. MEASURED on the RW6 VC 2026-08-04:
    // set-module-text answered 2xx for a 30 KB module but STORED only ~5 KB --
    // the loaded program lost PROC main and every later symbol, silently.
    // (Recovered via loadprog from the deployed .pgf.) A write this endpoint
    // truncates must be reported as the program-corrupting failure it is.
    const norm = (s: string) => s.replace(/\r\n/g, "\n").trimEnd();
    try {
      const back = await rwsFetchModuleText(task, module);
      if (norm(back.text) !== norm(code)) {
        return err(
          `WRITE CORRUPTED THE MODULE: controller stored ${back.text.length} chars of the ${code.length} sent ` +
          `(the RWS form endpoint truncates large modules). The loaded program is now BROKEN -- reload it ` +
          `(loadprog from its .pgf / restart the bridge) and use rs_write_module for large modules.`);
      }
      return ok({ result: `Module ${module} updated and verified (${code.length} chars)` });
    } catch (e: any) {
      return ok({ result: `Module ${module} updated, but verification read failed: ${e.message}` });
    }
  } catch (e: any) { return err(e); } }
);

// ── RAPID Variables (RWS — live runtime values) ──────────────

server.tool("rws_read_variable", "Read a RAPID variable's live runtime value via RWS",
  { task: z.string(), module: z.string(), variable: z.string() },
  async ({ task, module, variable }) => { try {
    await ensureRwsReady();
    // v1: /rw/rapid/symbol/data/RAPID/... (measured on the RW6 VC; the
    // pre-fix v2-flavored path answered "Resource not found" there).
    // v2: /rw/rapid/symbol/RAPID/.../data (measured on the RW7 VC).
    const path = rwsApiVersion === "v2"
      ? `/rw/rapid/symbol/RAPID/${task}/${module}/${variable}/data`
      : `/rw/rapid/symbol/data/RAPID/${task}/${module}/${variable}`;
    const r = await rws(path);
    const v = rwsExtract(r.body, "value");
    return ok({ variable, value: v ? rwsDecodeEntities(v) : r.body });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_write_variable", "Write a RAPID variable's live value via RWS (auto-mastership)",
  { task: z.string(), module: z.string(), variable: z.string(), value: z.string() },
  async ({ task, module, variable, value }) => { try {
    await ensureRwsReady();
    if (rwsApiVersion === "v2") {
      // OmniCore: edit-domain mastership (subresource form; the v1 "rapid"
      // domain 404s on RW7) held across the write in THIS session. A failed
      // request is surfaced -- proceeding without it just yields the opaque
      // -4501 "without required master ship" on the write itself.
      const mr = await rws("POST", "/rw/mastership/edit/request", "", "application/x-www-form-urlencoded");
      if (!rwsOk(mr.status)) return ok({ result: `edit mastership refused (${mr.status}): ${mr.body}` });
      try {
        const r = await rws("POST",
          `/rw/rapid/symbol/RAPID/${task}/${module}/${variable}/data?action=set`,
          `value=${encodeURIComponent(value)}`, "application/x-www-form-urlencoded");
        return ok({ result: rwsOk(r.status) ? `${variable} = ${value}` : r.body });
      } finally {
        await rws("POST", "/rw/mastership/edit/release", "", "application/x-www-form-urlencoded").catch(() => {});
      }
    }
    await rws("POST","/rw/mastership/rapid?action=request");
    try {
      const r = await rws("POST",
        `/rw/rapid/symbol/data/RAPID/${task}/${module}/${variable}?action=set`,
        `value=${encodeURIComponent(value)}`, "application/x-www-form-urlencoded");
      return ok({ result: rwsOk(r.status) ? `${variable} = ${value}` : r.body });
    } finally { await rws("POST","/rw/mastership/rapid?action=release").catch(() => {}); }
  } catch (e: any) { return err(e); } }
);

// ── Robot Position (RWS — live) ──────────────────────────────

server.tool("rws_get_position", "Get live robot TCP position via RWS",
  { mechUnit: z.string().optional().describe("Default: ROB_1") },
  async ({ mechUnit }) => { try {
    const mu = mechUnit || "ROB_1";
    const [tcp, jt] = await Promise.all([
      rws( `/rw/motionsystem/mechunits/${mu}/robtarget`),
      rws( `/rw/motionsystem/mechunits/${mu}/jointtarget`),
    ]);
    return ok({
      tcp: { x: rwsExtract(tcp.body, "x"), y: rwsExtract(tcp.body, "y"), z: rwsExtract(tcp.body, "z"),
             q1: rwsExtract(tcp.body, "q1"), q2: rwsExtract(tcp.body, "q2"),
             q3: rwsExtract(tcp.body, "q3"), q4: rwsExtract(tcp.body, "q4") },
      joints: { rax_1: rwsExtract(jt.body, "rax_1"), rax_2: rwsExtract(jt.body, "rax_2"),
                rax_3: rwsExtract(jt.body, "rax_3"), rax_4: rwsExtract(jt.body, "rax_4"),
                rax_5: rwsExtract(jt.body, "rax_5"), rax_6: rwsExtract(jt.body, "rax_6") },
    });
  } catch (e: any) { return err(e); } }
);

// ── I/O Signals (RWS — live) ────────────────────────────────

server.tool("rws_get_io_signals", "List all I/O signals via RWS (path = the full Network/Device/Signal form writes require)", {},
  async () => { try {
    const r = await rws( "/rw/iosystem/signals");
    const paths = [...r.body.matchAll(/class="ios-signal-li" title="([^"]*)"/gi)].map(m => m[1]);
    const names = rwsExtractAll(r.body, "name");
    const types = rwsExtractAll(r.body, "type");
    const vals = rwsExtractAll(r.body, "lvalue");
    return ok(names.map((n, i) => ({ name: n, type: types[i], value: vals[i], path: paths[i] })));
  } catch (e: any) { return err(e); } }
);

server.tool("rws_read_io", "Read a single I/O signal via RWS (bare names are auto-resolved to their full path)",
  { signal: z.string().describe("Signal name or full Network/Device/Signal path") },
  async ({ signal }) => { try {
    await ensureRwsReady();
    // RWS 2.0 rejects bare signal names on GET ("Invalid IO signal name passed
    // in the uri", measured on the RW7 VC) -- resolve via the signal list.
    // RWS 1.0 accepts bare names on GET, so only v2 needs the resolution.
    const sig = rwsApiVersion === "v2" ? await rwsResolveSignalPath(signal) : signal;
    const r = await rws( `/rw/iosystem/signals/${sig}`);
    return ok({ signal: sig, type: rwsExtract(r.body, "type"), value: rwsExtract(r.body, "lvalue") });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_write_io", "Set an I/O signal value via RWS (bare names are auto-resolved to their full path)",
  { signal: z.string().describe("Signal name or full Network/Device/Signal path"), value: z.number() },
  async ({ signal, value }) => { try {
    await ensureRwsReady();
    // BOTH generations require the full Network/Device/Signal path on writes
    // (v1 measured 2026-07-16: bare-name SET rejected -1073445881 while
    // full-path succeeded; v2 rejects bare names on any access) -- resolve.
    // v1/IRC5: "?action=set"; v2/OmniCore: "/set-value".
    const sig = await rwsResolveSignalPath(signal);
    const path = rwsApiVersion === "v2"
      ? `/rw/iosystem/signals/${sig}/set-value`
      : `/rw/iosystem/signals/${sig}?action=set`;
    const r = await rws("POST", path, `lvalue=${value}`, "application/x-www-form-urlencoded");
    return ok({ result: rwsOk(r.status) ? `${sig} = ${value}` : r.body });
  } catch (e: any) { return err(e); } }
);

// ── Speed Override (RWS) ────────────────────────────────────

server.tool("rws_get_speed_override", "Get speed override percentage via RWS", {},
  async () => { try {
    const r = await rws( "/rw/panel/speedratio");
    return ok({ speedRatio: rwsExtract(r.body, "speedratio") });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_set_speed_override", "Set speed override (0-100%) via RWS",
  { speed: z.number().min(0).max(100) },
  async ({ speed }) => { try {
    const r = await rws("POST","/rw/panel/speedratio?action=setspeedratio",
      `speed-ratio=${speed}`, "application/x-www-form-urlencoded");
    return ok({ result: rwsOk(r.status) ? `Speed ${speed}%` : r.body });
  } catch (e: any) { return err(e); } }
);

// ── Event Log (RWS) ─────────────────────────────────────────

server.tool("rws_event_log", "Get controller event log via RWS (structured; newest first)",
  { count: z.number().optional().describe("Max entries to return (default 10)"),
    domain: z.number().optional().describe("Elog domain (default 0 = common)") },
  async ({ count, domain }) => { try {
    // Same elog-message-li shape on both generations (measured 2026-08-04).
    // ?lang=en is what makes title/desc appear at all.
    const r = await rws( `/rw/elog/${domain ?? 0}?lang=en`);
    const entries = [...r.body.matchAll(
      /<li class="elog-message-li" title="([^"]*)">([\s\S]*?)<\/li>/gi
    )].map((m) => {
      const seq = m[1].split("/").pop() ?? "";
      const block = m[2];
      const f = (cls: string) => {
        const mm = block.match(new RegExp(`class="${cls}"[^>]*>([^<]*)<`, "i"));
        return rwsDecodeEntities((mm?.[1] ?? "").trim());
      };
      return { seqnum: seq, msgtype: f("msgtype"), code: f("code"),
               tstamp: f("tstamp"), title: f("title"), desc: f("desc") };
    });
    return ok(entries.slice(0, count || 10));
  } catch (e: any) { return err(e); } }
);

// ── Controller Files (RWS) ──────────────────────────────────

server.tool("rws_list_files", "List files on controller filesystem via RWS (structured)",
  { path: z.string().optional().describe("Default: $HOME") },
  async ({ path }) => { try {
    const r = await rws( `/fileservice/${encodeURIComponent(path || "$HOME")}`);
    // fs-dir / fs-file li titles carry the names on both generations.
    const dirs  = [...r.body.matchAll(/<li class="fs-dir" title="([^"]*)"/gi)].map(m => m[1]);
    const files = [...r.body.matchAll(/<li class="fs-file" title="([^"]*)"/gi)].map(m => m[1]);
    return ok({ path: path || "$HOME", dirs, files });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_read_file", "Read a file from controller filesystem via RWS",
  { path: z.string() },
  async ({ path }) => { try {
    const r = await rws( `/fileservice/${encodeURIComponent(path)}`);
    return ok({ content: r.body });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_write_file", "Write a file to controller filesystem via RWS",
  { path: z.string(), content: z.string() },
  async ({ path, content }) => { try {
    const r = await rws("PUT", `/fileservice/${encodeURIComponent(path)}`, content, "text/plain");
    return ok({ result: rwsOk(r.status) ? `Written to ${path}` : r.body });
  } catch (e: any) { return err(e); } }
);

// ── Mastership (RWS) ────────────────────────────────────────
// v1 (IRC5): domains {rapid, cfg, motion}, POST /rw/mastership/{d}?action=...
// v2 (OmniCore, MEASURED on the RW7 VC 2026-08-04): domains {edit, motion}
// with subresource forms POST /rw/mastership/{d}/{request|release} ("rapid"
// 404s; the v1 write domain maps to "edit"). Mastership is SESSION-bound on
// both generations -- request and release must ride the same session cookie,
// which this server's shared jar guarantees (a request whose session dies
// strands the hold until the controller's session timeout reaps it).

function mapMastershipDomain(domain: string | undefined): string {
  const d = domain || "rapid";
  if (rwsApiVersion === "v2") return d === "rapid" || d === "cfg" ? "edit" : d;
  return d;
}

server.tool("rws_request_mastership", "Request mastership (needed for writes; on OmniCore 'rapid'/'cfg' map to the v2 'edit' domain)",
  { domain: z.enum(["rapid", "cfg", "motion", "edit"]).optional() },
  async ({ domain }) => { try {
    await ensureRwsReady();
    const d = mapMastershipDomain(domain);
    const r = rwsApiVersion === "v2"
      ? await rws("POST", `/rw/mastership/${d}/request`, "", "application/x-www-form-urlencoded")
      : await rws("POST", `/rw/mastership/${d}?action=request`);
    return ok({ result: rwsOk(r.status) ? `Mastership acquired (${d})` : r.body });
  } catch (e: any) { return err(e); } }
);

server.tool("rws_release_mastership", "Release mastership",
  { domain: z.enum(["rapid", "cfg", "motion", "edit"]).optional() },
  async ({ domain }) => { try {
    await ensureRwsReady();
    const d = mapMastershipDomain(domain);
    const r = rwsApiVersion === "v2"
      ? await rws("POST", `/rw/mastership/${d}/release`, "", "application/x-www-form-urlencoded")
      : await rws("POST", `/rw/mastership/${d}?action=release`);
    return ok({ result: rwsOk(r.status) ? `Mastership released (${d})` : r.body });
  } catch (e: any) { return err(e); } }
);

// ── Start Server ─────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ABB RobotStudio MCP Server v2.0 (SDK + RWS combined)");
  console.error(`  SDK Bridge: ${BRIDGE_URL}`);
  console.error(`  RWS:        ${RWS_URL}`);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
