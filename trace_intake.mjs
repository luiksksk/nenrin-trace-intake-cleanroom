#!/usr/bin/env node
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const PROFILE = "tag:agentrust-io.com,2026:trace-v0.2";
const SUPERSEDED_PROFILE = "tag:agentrust.io,2026:trace-v0.1";
const REQUIRED = [
  "eat_profile", "iat", "subject", "model", "runtime", "policy",
  "data_class", "build_provenance", "appraisal", "cnf",
];
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

class Refusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const has = (value, key) => Object.hasOwn(value, key);

function checkString(value) {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Refusal("lone_surrogate");
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Refusal("lone_surrogate");
    }
  }
}

function canonical(value, depth = 0) {
  if (depth > 64) throw new Refusal("too_deep");
  if (typeof value === "string") {
    checkString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Refusal("non_finite_number");
    if (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new Refusal("unsafe_integer");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonical(item, depth + 1)).join(",")}]`;
  }
  if (isObject(value)) {
    const members = [];
    for (const key of Object.keys(value).sort()) {
      checkString(key);
      members.push(`${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`);
    }
    return `{${members.join(",")}}`;
  }
  return JSON.stringify(value);
}

function decodeBase64url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Refusal("bad_base64url");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) throw new Refusal("bad_base64url");
  return bytes;
}

function intake(bundle) {
  const vector = bundle?.vector;
  const record = isObject(vector) && has(vector, "record") && isObject(vector.record)
    ? vector.record
    : vector;
  if (!isObject(record)) throw new Refusal("record_not_object");

  const recordJcs = canonical(record);
  if (Buffer.byteLength(recordJcs, "utf8") > 65536) throw new Refusal("too_large");
  if (has(record, "cmcp_version") && has(record, "trace") && !has(record, "eat_profile")) {
    throw new Refusal("enveloped_form");
  }
  if (has(record, "eat_profile")) {
    if (record.eat_profile === SUPERSEDED_PROFILE) throw new Refusal("superseded_profile");
    if (record.eat_profile !== PROFILE) throw new Refusal("unsupported_profile");
  }
  if (REQUIRED.some((key) => !has(record, key))) throw new Refusal("missing_required");
  if (!Number.isInteger(record.iat) || record.iat < 1700000000) throw new Refusal("bad_iat");
  if (typeof record.subject !== "string" || record.subject.length === 0) {
    throw new Refusal("bad_subject");
  }
  if (!has(record, "signature")) throw new Refusal("no_embedded_signature");

  const signature = decodeBase64url(record.signature);
  if (signature.length !== 64) throw new Refusal("bad_signature_length");

  if (!isObject(record.cnf) || !isObject(record.cnf.jwk)) {
    throw new Refusal("no_confirmation_key");
  }
  const jwk = record.cnf.jwk;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new Refusal("unsupported_key_type");
  const publicBytes = decodeBase64url(jwk.x);
  if (publicBytes.length !== 32) throw new Refusal("bad_key_length");

  const unsigned = Object.fromEntries(Object.entries(record).filter(([key]) => key !== "signature"));
  const message = Buffer.from(canonical(unsigned), "utf8");
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicBytes]),
      format: "der",
      type: "spki",
    });
    if (!verify(null, message, publicKey, signature)) throw new Refusal("signature_invalid");
  } catch (error) {
    if (error instanceof Refusal) throw error;
    throw new Refusal("signature_invalid");
  }
  if (record.iat > bundle.now + 300) throw new Refusal("iat_in_future");
  return { verdict: "pinnable", refusals: [], findings: [] };
}

function signature(bundle) {
  try {
    return intake(bundle);
  } catch (error) {
    if (error instanceof Refusal) {
      return { verdict: "refused", refusals: [error.code], findings: [] };
    }
    throw error;
  }
}

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) {
  console.error("usage: node trace_intake.mjs <batch.json> <results.json>");
  process.exit(2);
}

const batch = JSON.parse(await readFile(inputPath, "utf8"));
const results = {};
for (const item of batch) {
  try {
    results[item.name] = signature(item.bundle);
  } catch (error) {
    results[item.name] = { error: String(error) };
  }
}
await writeFile(outputPath, `${JSON.stringify(results)}\n`);
