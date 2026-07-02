#!/usr/bin/env node

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const args = process.argv.slice(2);

function usage() {
  console.error("usage: cdx-deps.cjs <project-dir|bom.cdx.json> <package-name> [version] [--depth N] [--cdxgen-bin PATH]");
  process.exit(2);
}

let depth = 4;
let cdxgenBin = "cdxgen";
const positional = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === "--depth") {
    if (i + 1 >= args.length) usage();
    depth = Number(args[++i]);
    if (!Number.isFinite(depth) || depth < 0) usage();
  } else if (arg === "--cdxgen-bin") {
    if (i + 1 >= args.length) usage();
    cdxgenBin = args[++i];
  } else if (arg === "-h" || arg === "--help") {
    usage();
  } else {
    positional.push(arg);
  }
}

if (positional.length < 2 || positional.length > 3) usage();

const input = positional[0];
const queryName = positional[1];
const queryVersion = positional[2] || "";

const bom = readBOM(input);
const components = Array.isArray(bom.components) ? bom.components : [];
const dependencies = Array.isArray(bom.dependencies) ? bom.dependencies : [];
const byRef = new Map();
const parents = new Map();
const children = new Map();
const rootRefs = new Set();

for (const component of components) {
  if (component["bom-ref"]) byRef.set(component["bom-ref"], component);
}

if (bom.metadata && bom.metadata.component && bom.metadata.component["bom-ref"]) {
  rootRefs.add(bom.metadata.component["bom-ref"]);
}

for (const dep of dependencies) {
  if (!dep.ref) continue;
  const dependsOn = Array.isArray(dep.dependsOn) ? dep.dependsOn.filter(Boolean) : [];
  children.set(dep.ref, dependsOn);
  for (const child of dependsOn) {
    if (!parents.has(child)) parents.set(child, []);
    parents.get(child).push(dep.ref);
  }
}

const matches = components.filter((component) => componentMatches(component, queryName, queryVersion));
if (matches.length === 0) {
  console.error(`package not found: ${queryName}${queryVersion ? `@${queryVersion}` : ""}`);
  process.exit(1);
}

for (let i = 0; i < matches.length; i++) {
  const target = matches[i]["bom-ref"];
  if (!target) continue;
  if (matches.length > 1) {
    if (i > 0) console.log("");
    console.log(`match ${i + 1}/${matches.length}: ${label(target)}`);
  }
  printTarget(target);
}

function readBOM(inputPath) {
  const stat = fs.statSync(inputPath);
  if (stat.isDirectory()) {
    const out = path.join(os.tmpdir(), `cdx-deps-${process.pid}-${Date.now()}.json`);
    const run = spawnSync(cdxgenBin, ["-o", out, "--spec-version", "1.6", "--no-banner", inputPath], {
      stdio: ["ignore", "ignore", "inherit"],
      encoding: "utf8",
    });
    if (run.status !== 0) {
      removeFile(out);
      console.error(`cdxgen failed for ${inputPath}`);
      process.exit(run.status || 1);
    }
    try {
      return JSON.parse(fs.readFileSync(out, "utf8"));
    } finally {
      removeFile(out);
    }
  }
  return JSON.parse(fs.readFileSync(inputPath, "utf8"));
}

function removeFile(file) {
  try {
    fs.unlinkSync(file);
  } catch (_err) {}
}

function componentMatches(component, name, version) {
  const componentName = String(component.name || "");
  const componentVersion = String(component.version || "");
  const purl = String(component.purl || "");
  const ref = String(component["bom-ref"] || "");
  const nameMatch = componentName === name || purl.includes(`/${name}@`) || purl.endsWith(`/${name}`) || ref.includes(name);
  const versionMatch = version === "" || componentVersion === version || purl.endsWith(`@${version}`) || ref.endsWith(`@${version}`);
  return nameMatch && versionMatch;
}

function printTarget(target) {
  const paths = ancestorPaths(target);
  const targetChildren = children.get(target) || [];
  for (let i = 0; i < paths.length; i++) {
    if (i > 0) console.log("");
    const prefix = paths[i].map(label).join(" -> ");
    if (targetChildren.length === 0 || depth === 0) {
      console.log(prefix);
      continue;
    }
    console.log(`${prefix} -> \\`);
    printChildren(target, "  ", new Set([target]), depth);
  }
}

function ancestorPaths(target) {
  const out = [];
  const seen = new Set();

  function walk(ref, stack) {
    const usableParents = (parents.get(ref) || []).filter((parent) => !rootRefs.has(parent) && !stack.includes(parent));
    if (usableParents.length === 0) {
      out.push([...stack].reverse());
      return;
    }
    for (const parent of usableParents) {
      walk(parent, [...stack, parent]);
    }
  }

  walk(target, [target]);
  const unique = [];
  for (const item of out) {
    const key = item.join("\0");
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(item);
  }
  unique.sort((a, b) => a.length - b.length || a.join(">").localeCompare(b.join(">")));
  return unique.length ? unique : [[target]];
}

function printChildren(ref, indent, stack, remainingDepth) {
  if (remainingDepth <= 0) return;
  for (const child of children.get(ref) || []) {
    console.log(`${indent}-> ${label(child)}`);
    if (stack.has(child)) continue;
    stack.add(child);
    printChildren(child, `${indent}   `, stack, remainingDepth - 1);
    stack.delete(child);
  }
}

function label(ref) {
  const component = byRef.get(ref);
  if (!component) return cleanRef(ref);
  const name = component.name || cleanRef(ref);
  const version = component.version || "";
  return version ? `${name} (${version})` : name;
}

function cleanRef(ref) {
  return String(ref || "").replace(/^pkg:[^/]+\//, "");
}
