// Independent verifier for the VEP wire format (suite 1.0). Node standard library only; it shares no code with
// the Python reference. It implements docs/CONFORMANCE.md.
//
//   node verify.mjs suite <suite.json>      run every vector; exit 1 if any disagrees
//   node verify.mjs bundle <bundle.json>    verify one bundle; prints {valid, code, ...}
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";

const MAX_INT = (1n << 63n) - 1n;
const MAX_DEPTH = 64;
const PARSE_DEPTH_CAP = 200; // anything deeper than MAX_DEPTH is rejected later; this only protects the stack
class Reject extends Error { constructor(code, detail = "") { super(`${code}: ${detail}`); this.code = code; } }
class Canon extends Error {}

// ---------------------------------------------------------------- strict JSON (objects -> Map, integers -> BigInt)
function parseStrict(bytes) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch { throw new Canon("not UTF-8"); }
  if (text.startsWith("﻿")) throw new Canon("BOM");
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const fail = (m) => { throw new Canon(m); };
  function value(d) {
    if (d > PARSE_DEPTH_CAP) fail("too deep");
    ws();
    const c = text[i];
    if (c === "{") {
      i++; const m = new Map(); ws();
      if (text[i] === "}") { i++; return m; }
      for (;;) {
        ws(); if (text[i] !== '"') fail("key");
        const k = str(); ws(); if (text[i++] !== ":") fail("colon");
        if (m.has(k)) fail("duplicate key");
        m.set(k, value(d + 1)); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return m; }
        fail("object");
      }
    }
    if (c === "[") {
      i++; const a = []; ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value(d + 1)); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return a; }
        fail("array");
      }
    }
    if (c === '"') return str();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?/.exec(text.slice(i, i + 5000));
    if (!m) fail("value");
    if (m[2] !== undefined || m[3] !== undefined) fail("float");
    i += m[0].length;
    return BigInt(m[0]);
  }
  function str() {
    i++; let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated");
      const c = text[i++];
      if (c === '"') break;
      if (c.charCodeAt(0) < 0x20) fail("control char");
      if (c !== "\\") { out += c; continue; }
      const e = text[i++];
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e in simple) out += simple[e];
      else if (e === "u") {
        const hex = text.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("\\u");
        out += String.fromCharCode(parseInt(hex, 16)); i += 4;
      } else fail("escape");
    }
    if (!out.isWellFormed()) fail("lone surrogate");
    return out;
  }
  const v = value(0); ws();
  if (i !== text.length) fail("trailing data");
  check(v, 0);
  return v;
}

function check(v, depth) { // mirrors the reference rule exactly: scalars sit one level below their container
  if (depth > MAX_DEPTH) throw new Canon("too deep");
  if (v === null || typeof v === "boolean" || typeof v === "string") return;
  if (typeof v === "bigint") { if ((v < 0n ? -v : v) > MAX_INT) throw new Canon("int range"); return; }
  if (Array.isArray(v)) { for (const x of v) check(x, depth + 1); return; }
  if (v instanceof Map) { for (const [k, x] of v) { check(k, depth + 1); check(x, depth + 1); } return; }
  throw new Canon("type");
}

// ---------------------------------------------------------------- canonical serialization (VEP-C1)
const cpCompare = (a, b) => {
  const x = Array.from(a, (c) => c.codePointAt(0)), y = Array.from(b, (c) => c.codePointAt(0));
  for (let n = 0; n < Math.min(x.length, y.length); n++) if (x[n] !== y[n]) return x[n] - y[n];
  return x.length - y.length;
};
function jstr(s) {
  let o = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') o += '\\"'; else if (ch === "\\") o += "\\\\";
    else if (c === 8) o += "\\b"; else if (c === 12) o += "\\f"; else if (c === 10) o += "\\n";
    else if (c === 13) o += "\\r"; else if (c === 9) o += "\\t";
    else if (c < 0x20) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += ch;
  }
  return o + '"';
}
function canon(v) {
  check(v, 0);
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return jstr(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + [...v.keys()].sort(cpCompare).map((k) => jstr(k) + ":" + canon(v.get(k))).join(",") + "}";
}
const canonBytes = (v) => Buffer.from(canon(v), "utf8");
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const obj = (pairs) => new Map(Object.entries(pairs));

function domainHash(domain, data) {
  const d = Buffer.from(domain, "utf8");
  const l4 = Buffer.alloc(4); l4.writeUInt32BE(d.length);
  const l8 = Buffer.alloc(8); l8.writeBigUInt64BE(BigInt(data.length));
  return sha256(Buffer.concat([Buffer.from("vep-id\0", "latin1"), l4, d, l8, data]));
}

const PREFIX = { Objective: "obj", Snapshot: "snap", WorkClaim: "claim", Candidate: "cand", Action: "act", Evidence: "evd",
  Certificate: "cert", Observation: "obs", TokenReceipt: "rcpt", BudgetLease: "lease", ContextManifest: "ctx",
  ExecutionPolicy: "pol", OptimizationExperiment: "exp" };
const TYPE_OF_PREFIX = Object.fromEntries(Object.entries(PREFIX).map(([t, p]) => [p, t]));
const objectId = (type, ver, fieldsMap) => `${PREFIX[type]}-${domainHash(`vep.${type}.v${ver}`, canonBytes(fieldsMap))}`;

// ---------------------------------------------------------------- schemas (Evidence, Certificate; v1 and v2)
const TRUST = ["TRUSTED_LOCAL", "ISOLATED_VERIFIED", "UNVERIFIED"];
const ISO = ["NONE_TRUSTED_LOCAL", "DOCKER_GVISOR"];
const req = (kind, o = {}) => ({ kind, required: true, ...o }), opt = (kind, o = {}) => ({ kind, required: false, ...o });
const EVIDENCE_V1 = {
  candidate_id: req("id:Candidate"), objective_id: req("id:Objective"), snapshot_id: req("id:Snapshot"),
  policy_id: req("id:ExecutionPolicy"), action_id: req("id:Action"), runner_digest: req("digest"), argv: req("list:str"),
  exit_code: req("int"), verdict: req("enum", { values: ["PASS", "FAIL"] }), tests_discovered: req("int", { min: 0n }),
  tests_run: req("int", { min: 0n }), tests_passed: req("int", { min: 0n }), tests_failed: req("int", { min: 0n }),
  tests_skipped: req("int", { min: 0n }), executed_ids_digest: req("digest"), stdout_digest: req("digest"),
  stderr_digest: req("digest"), staged_tree_snapshot_id: req("id:Snapshot"), isolation: req("enum", { values: ISO }),
  started_at: req("ts"), finished_at: req("ts"), budget_reservation: req("str") };
const CERT_V1 = {
  candidate_id: req("id:Candidate"), objective_id: req("id:Objective"), snapshot_id: req("id:Snapshot"),
  policy_id: req("id:ExecutionPolicy"), evidence_id: req("id:Evidence"), evidence_envelope_digest: req("digest"),
  issuer_key_id: req("digest"), issued_at: req("ts") };
const SCHEMAS = {
  Evidence: { 1: EVIDENCE_V1, 2: { ...EVIDENCE_V1, trust_level: req("enum", { values: TRUST }),
    evaluator_id: req("str", { max: 256 }), execution_environment: req("json"), isolation_attestation_digest: opt("digest") } },
  Certificate: { 1: CERT_V1, 2: { ...CERT_V1, trust_level: req("enum", { values: TRUST }), evaluator_id: req("str", { max: 256 }) } },
};

function validValue(spec, v) {
  const k = spec.kind;
  if (k === "str") return typeof v === "string" && (v.length > 0 || spec.allowEmpty) && Array.from(v).length <= (spec.max ?? 65536);
  if (k === "int") return typeof v === "bigint" && (spec.min === undefined || v >= spec.min);
  if (k === "digest") return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  if (k.startsWith("id:")) {
    const m = typeof v === "string" ? /^([a-z]+)-([0-9a-f]{64})$/.exec(v) : null;
    return !!m && TYPE_OF_PREFIX[m[1]] === k.slice(3);
  }
  if (k === "ts") return typeof v === "string" && /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(v);
  if (k === "enum") return spec.values.includes(v);
  if (k === "json") return true;
  if (k === "list:str") return Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0);
  throw new Error(`unknown kind ${k}`);
}

function validateObject(type, ver, fields) { // returns the normalised field map (null optionals dropped) or throws SCHEMA_INVALID
  const spec = SCHEMAS[type][Number(ver)];
  const out = new Map();
  for (const k of fields.keys()) if (!(k in spec)) throw new Reject("SCHEMA_INVALID", `unknown field ${k}`);
  for (const [name, s] of Object.entries(spec)) {
    const v = fields.get(name);
    if (v === undefined || v === null) { if (s.required) throw new Reject("SCHEMA_INVALID", `missing ${name}`); continue; }
    if (!validValue(s, v)) throw new Reject("SCHEMA_INVALID", `bad ${name}`);
    out.set(name, v);
  }
  if (Number(ver) >= 2) { // trust consistency
    const tl = out.get("trust_level");
    if (type === "Evidence") {
      const att = out.has("isolation_attestation_digest");
      if (tl === "TRUSTED_LOCAL" && (out.get("isolation") !== "NONE_TRUSTED_LOCAL" || att)) throw new Reject("SCHEMA_INVALID", "trust/isolation");
      if (tl === "ISOLATED_VERIFIED" && (out.get("isolation") !== "DOCKER_GVISOR" || !att)) throw new Reject("SCHEMA_INVALID", "trust/isolation");
      if (tl === "UNVERIFIED" && out.get("verdict") === "PASS") throw new Reject("SCHEMA_INVALID", "unverified pass");
    }
  }
  return out;
}

// ---------------------------------------------------------------- envelopes
const PAYLOAD_TYPE = "application/vnd.vep.object+json;v=1";
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const isPlain = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const keysEq = (o, names) => { const k = Object.keys(o).sort(); const n = [...names].sort(); return k.length === n.length && k.every((x, j) => x === n[j]); };
function pae(type, payload) {
  const t = Buffer.from(type, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload]);
}
function b64(s) { if (typeof s !== "string" || !B64.test(s)) throw new Error("b64"); return Buffer.from(s, "base64"); }

function openEnvelope(env, keys, expectType) { // env is a plain JS object (from JSON.parse) for the structure checks
  if (!isPlain(env) || !keysEq(env, ["payloadType", "payload", "signatures"]) || env.payloadType !== PAYLOAD_TYPE) throw new Reject("MALFORMED_ENVELOPE");
  const sigs = env.signatures;
  if (!Array.isArray(sigs) || sigs.length !== 1 || !isPlain(sigs[0]) || !keysEq(sigs[0], ["keyid", "sig"])) throw new Reject("MALFORMED_ENVELOPE", "signatures");
  let payload, sig;
  try { payload = b64(env.payload); sig = b64(sigs[0].sig); } catch { throw new Reject("MALFORMED_ENVELOPE", "base64"); }
  if (typeof sigs[0].keyid !== "string") throw new Reject("MALFORMED_ENVELOPE");
  const raw = keys.get(sigs[0].keyid);
  if (!raw) throw new Reject("UNTRUSTED_KEY");
  let ok = false;
  try { ok = edVerify(null, pae(PAYLOAD_TYPE, payload), createPublicKey({ key: Buffer.concat([SPKI_ED25519, raw]), format: "der", type: "spki" }), sig); } catch { ok = false; }
  if (!ok) throw new Reject("SIGNATURE_INVALID");
  let doc;
  try { doc = parseStrict(payload); } catch { throw new Reject("MALFORMED_PAYLOAD"); }
  if (!(doc instanceof Map) || doc.size !== 3 || !doc.has("type") || !doc.has("schema_version") || !doc.has("fields")
      || typeof doc.get("type") !== "string" || typeof doc.get("schema_version") !== "bigint" || !(doc.get("fields") instanceof Map)) throw new Reject("MALFORMED_PAYLOAD", "shape");
  const type = doc.get("type"), ver = doc.get("schema_version");
  if (type !== expectType) throw new Reject("WRONG_TYPE");
  if (!SCHEMAS[type][Number(ver)] || ver > 1000n) throw new Reject("UNSUPPORTED_SCHEMA_VERSION");
  const fields = validateObject(type, ver, doc.get("fields"));
  const recon = canonBytes(new Map([["type", type], ["schema_version", ver], ["fields", fields]]));
  if (!recon.equals(payload)) throw new Reject("NONCANONICAL_PAYLOAD");
  return { type, ver: Number(ver), f: fields, id: objectId(type, ver, fields) };
}

// ---------------------------------------------------------------- bundle verification
const RANK = { UNVERIFIED: 0, TRUSTED_LOCAL: 1, ISOLATED_VERIFIED: 2 };
export function verifyBundle(bundleBytes) {
  try { return { ...verifyInner(bundleBytes) }; } catch (e) { if (e instanceof Reject) return { valid: false, code: e.code, detail: e.detail }; throw e; }
}
function verifyInner(bytes) {
  let raw; // plain JS view for envelope structure checks; ints as numbers are fine there (no big values are read from it)
  try { raw = JSON.parse(Buffer.isBuffer(bytes) ? bytes.toString("utf8") : bytes); } catch { throw new Reject("MALFORMED_BUNDLE"); }
  if (!isPlain(raw) || !("bundle_version" in raw)) throw new Reject("MALFORMED_BUNDLE");
  if (typeof raw.bundle_version !== "number" || !Number.isInteger(raw.bundle_version)) throw new Reject("MALFORMED_BUNDLE");
  if (raw.bundle_version !== 1) throw new Reject("UNSUPPORTED_BUNDLE_VERSION");
  if (!keysEq(raw, ["bundle_version", "trusted_keys", "certificate_envelope", "evidence_envelope", "expect"])) throw new Reject("MALFORMED_BUNDLE");
  const ex = raw.expect;
  if (!isPlain(ex) || !["TRUSTED_LOCAL", "ISOLATED_VERIFIED"].includes(ex.require_trust)
      || !Object.keys(ex).every((k) => ["require_trust", "objective_id", "policy_id", "snapshot_id"].includes(k))
      || !Object.values(ex).every((v) => typeof v === "string") || !Array.isArray(raw.trusted_keys)) throw new Reject("MALFORMED_BUNDLE");
  const keys = new Map();
  for (const k of raw.trusted_keys) {
    if (!isPlain(k) || !keysEq(k, ["key_id", "public_key_hex"]) || typeof k.key_id !== "string" || typeof k.public_key_hex !== "string") throw new Reject("MALFORMED_BUNDLE");
    if (!/^([0-9a-fA-F]{2})*$/.test(k.public_key_hex)) throw new Reject("MALFORMED_BUNDLE");
    const rawKey = Buffer.from(k.public_key_hex, "hex");
    if (rawKey.length !== 32 || sha256(rawKey) !== k.key_id) throw new Reject("MALFORMED_BUNDLE", "key id");
    keys.set(k.key_id, rawKey);
  }
  const cert = openEnvelope(raw.certificate_envelope, keys, "Certificate");
  const ev = openEnvelope(raw.evidence_envelope, keys, "Evidence");
  // the evidence envelope digest is over the canonical form of the envelope object
  const evCanon = canonBytes(parseStrict(Buffer.from(JSON.stringify(raw.evidence_envelope), "utf8")));
  if (sha256(evCanon) !== cert.f.get("evidence_envelope_digest")) throw new Reject("EVIDENCE_DIGEST_MISMATCH");
  if (ev.id !== cert.f.get("evidence_id")) throw new Reject("IDENTITY_MISMATCH");
  for (const k of ["candidate_id", "objective_id", "snapshot_id", "policy_id"]) if (ev.f.get(k) !== cert.f.get(k)) throw new Reject("BINDING_MISMATCH", k);
  const evTrust = ev.ver >= 2 ? ev.f.get("trust_level") : (ev.f.get("isolation") === "NONE_TRUSTED_LOCAL" ? "TRUSTED_LOCAL" : "UNVERIFIED");
  let certTrust = evTrust;
  if (cert.ver >= 2) {
    if (cert.f.get("trust_level") !== evTrust || cert.f.get("evaluator_id") !== ev.f.get("evaluator_id")) throw new Reject("TRUST_BINDING_MISMATCH");
    certTrust = cert.f.get("trust_level");
  }
  if (evTrust === "UNVERIFIED" || RANK[certTrust] < RANK[ex.require_trust]) throw new Reject("TRUST_INSUFFICIENT");
  const n = (k) => ev.f.get(k);
  if (n("verdict") !== "PASS" || n("tests_passed") < 1n || n("tests_skipped") >= n("tests_run") || n("tests_failed") !== 0n) throw new Reject("EVIDENCE_NOT_PASSING");
  if (n("staged_tree_snapshot_id") !== cert.f.get("snapshot_id")) throw new Reject("EVIDENCE_SNAPSHOT_MISMATCH");
  for (const [f, code] of [["objective_id", "OBJECTIVE_MISMATCH"], ["policy_id", "POLICY_MISMATCH"], ["snapshot_id", "SNAPSHOT_MISMATCH"]])
    if (f in ex && ex[f] !== cert.f.get(f)) throw new Reject(code);
  return { valid: true, code: null, trust_level: certTrust, certificate_id: cert.id, snapshot_id: cert.f.get("snapshot_id") };
}

// ---------------------------------------------------------------- vector runner
function runVector(v) {
  if (v.op === "canonicalize") {
    try { return { valid: true, output_hex: canonBytes(parseStrict(Buffer.from(v.input_hex, "hex"))).toString("hex") }; } catch (e) { if (e instanceof Canon) return { valid: false }; throw e; }
  }
  if (v.op === "domain_hash") return { digest: domainHash(v.domain, Buffer.from(v.data_hex, "hex")) };
  if (v.op === "object_id") {
    // vector fields are re-parsed through the strict parser so integers keep full precision
    const fields = parseStrict(Buffer.from(v.fields_json, "utf8"));
    const type = v.type, ver = BigInt(v.schema_version);
    const env = new Map([["type", type], ["schema_version", ver], ["fields", fields]]);
    return { canonical_hex: canonBytes(env).toString("hex"), id: objectId(type, ver, fields) };
  }
  if (v.op === "verify_bundle") { const r = verifyBundle(v.bundle_json); return { valid: r.valid, code: r.code }; }
  throw new Error(`unknown op ${v.op}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, file] = process.argv.slice(2);
  if (cmd === "bundle") { console.log(JSON.stringify(verifyBundle(readFileSync(file)))); process.exit(0); }
  if (cmd !== "suite") { console.error("usage: verify.mjs suite <suite.json> | bundle <bundle.json>"); process.exit(2); }
  // The suite file is read twice: plain JSON for structure, and raw text spans so ints/objects keep exact bytes.
  const suite = JSON.parse(readFileSync(file, "utf8"));
  const rawSuite = parseStrict(readFileSync(file)); // Map form: exact integers, for object_id fields
  const rawVectors = rawSuite.get("vectors");
  let bad = 0;
  suite.vectors.forEach((v, idx) => {
    const rv = rawVectors[idx];
    const input = { ...v };
    if (v.op === "object_id") input.fields_json = canon(rv.get("fields"));
    if (v.op === "verify_bundle") input.bundle_json = canon(rv.get("bundle")); // exact, re-serialised canonically; envelope strings are unchanged by this
    const got = runVector(input);
    const ok = Object.entries(v.expect).every(([k, x]) => got[k] === x);
    if (!ok) { bad++; console.log(`DISAGREE ${v.id}: expected ${JSON.stringify(v.expect)} got ${JSON.stringify(got)} (${v.note})`); }
  });
  console.log(`${suite.vectors.length - bad}/${suite.vectors.length} vectors agree`);
  process.exit(bad ? 1 : 0);
}
