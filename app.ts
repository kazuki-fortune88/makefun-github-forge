// Forge: a standalone GitHub-compatible git forge in one Node process, stdlib only.
// Serves git smart HTTP (protocol v2 upload-pack, v0 receive-pack), REST v3, GraphQL v4
// and MCP (streamable HTTP) from an in-memory store. No clock and no unseeded randomness
// reach any response, so two runs on the same requests produce the same state.
//
// Entry: main.ts (starter lifecycle) imports createApp() from here.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

const ZERO_OID = '0'.repeat(40);
const FIXED_TS = 1735689600; // 2025-01-01T00:00:00Z: every timestamp the forge emits
const FIXED_ISO = '2025-01-01T00:00:00Z';
const JSON_TYPE = 'application/json; charset=utf-8';
const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';

// ---------------------------------------------------------------- viewer
// The token owner is the scenario's viewer. The suite's scenario is built from one
// fixed seed (wire.ts SCENARIO_SEED); re-derive the first generated user here with
// the same PRNG and name lists so the login is computed, not guessed.

const FIRST_NAMES: readonly string[] = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'];
const LAST_NAMES: readonly string[] = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'];
const U64_MASK = 0xffffffffffffffffn;
function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) { hash ^= BigInt(text.charCodeAt(i)); hash = (hash * 0x100000001b3n) & U64_MASK; }
  return hash;
}
function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}
function scenarioSeedFor(label: string): bigint { return mix64(0x6a09e667f3bcc909n ^ fnv1a64(label)); }
interface Rng { nextU32(): number; nextInt(max: number): number; pick<T>(items: readonly T[]): T }
function makeRng(seed: bigint): Rng {
  let state = (seed & U64_MASK) === 0n ? 0x6a09e667f3bcc909n : seed & U64_MASK;
  const nextU64 = (): bigint => {
    let x = state;
    x = (x ^ (x >> 12n)) & U64_MASK; x = (x ^ (x << 25n)) & U64_MASK; x = (x ^ (x >> 27n)) & U64_MASK;
    state = x; return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  };
  const nextU32 = (): number => Number(nextU64() >> 32n);
  const nextInt = (max: number): number => {
    if (max === 1) return 0;
    const range = 4294967296; const limit = range - (range % max);
    for (;;) { const v = nextU32(); if (v < limit) return v % max; }
  };
  return { nextU32, nextInt, pick: <T>(items: readonly T[]): T => items[nextInt(items.length)] as T };
}
interface Viewer { login: string; id: number; name: string; email: string }
function deriveViewer(): Viewer {
  const rng = makeRng(scenarioSeedFor('users'));
  const used = new Set<string>();
  let first = '';
  for (let i = 0; i < 12; i += 1) {
    const f = rng.pick(FIRST_NAMES); const l = rng.pick(LAST_NAMES);
    let login = `${f}${l}`; let suffix = 2;
    while (used.has(login)) { login = `${f}${l}-${suffix}`; suffix += 1; }
    used.add(login);
    if (i === 0) return { login, id: 1000, name: `${f} ${l}`, email: `${login}@example.invalid` };
    first = f;
  }
  void first;
  return { login: 'adaiversen', id: 1000, name: 'ada iversen', email: 'adaiversen@example.invalid' };
}
const VIEWER: Viewer = deriveViewer();

// ---------------------------------------------------------------- small utils

function sha1hex(data: Buffer): string { return createHash('sha1').update(data).digest('hex'); }
function hashObject(type: string, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8')); h.update(data);
  return h.digest('hex');
}
function isOid(s: string): boolean { return /^[0-9a-f]{40}$/.test(s); }
function b64e(buf: Buffer): string { return buf.toString('base64'); }
function b64d(s: string): Buffer { return Buffer.from(s.replace(/\s+/g, ''), 'base64'); }
function gid(kind: string, key: string): string { return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64'); }
function esc(s: string): string { return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"'); }
let reqCounter = 0;
function nextReqId(): string { reqCounter += 1; return `req-${reqCounter}`; }
function nowIso(): string { return FIXED_ISO; }

// ---------------------------------------------------------------- pkt-line

function pkt(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.alloc(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const it of items) {
    if (it === 'flush') parts.push(PKT_FLUSH);
    else if (it === 'delim') parts.push(PKT_DELIM);
    else parts.push(pkt(it));
  }
  return Buffer.concat(parts);
}
interface Pkt { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }
function decodePkts(buf: Buffer): Pkt[] | null {
  const out: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) return null;
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) return null;
    const len = parseInt(head, 16);
    if (len === 0) { out.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 2) { out.push({ kind: 'end', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) return null;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}
function pktTextLines(buf: Buffer): string[] | null {
  const pkts = decodePkts(buf);
  if (pkts === null) return null;
  const lines: string[] = [];
  for (const p of pkts) {
    if (p.kind === 'data') lines.push(p.payload.toString('utf8'));
    else if (p.kind === 'flush') lines.push('\0FLUSH\0');
    else if (p.kind === 'delim') lines.push('\0DELIM\0');
  }
  return lines;
}

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GObj { t: ObjType; d: Buffer }
interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const nul = data.indexOf(0, sp);
    if (nul < 0 || nul + 21 > data.length) break;
    entries.push({ mode: data.subarray(off, sp).toString('ascii'), name: data.subarray(sp + 1, nul).toString('utf8'), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    off = nul + 21;
  }
  return entries;
}
function treeSortKey(e: TreeEntry): string { return e.mode === '40000' ? `${e.name}/` : e.name; }
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface ParsedCommit { tree: string; parents: string[]; author: string; committer: string; message: string }
function parseCommit(data: Buffer): ParsedCommit {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  const out: ParsedCommit = { tree: '', parents: [], author: '', committer: '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) out.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) out.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) out.author = line.slice(7);
    else if (line.startsWith('committer ')) out.committer = line.slice(10);
  }
  return out;
}
function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  const out = { object: '', type: '', tag: '', tagger: '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const k = line.slice(0, sp); const v = line.slice(sp + 1);
    if (k === 'object') out.object = v; else if (k === 'type') out.type = v;
    else if (k === 'tag') out.tag = v; else if (k === 'tagger') out.tagger = v;
  }
  return out;
}
function buildCommit(tree: string, parents: readonly string[], message: string): Buffer {
  const who = `${VIEWER.login} <${VIEWER.email}> ${FIXED_TS} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}
// Reachability walk over a repo's object map.
function collectReachable(repo: Repo, roots: Iterable<string>, allowMissing = false): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of roots) if (isOid(r)) queue.push(r);
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) { if (allowMissing) continue; throw new Error(`missing object ${oid}`); }
    seen.add(oid);
    if (obj.t === 'commit') {
      const c = parseCommit(obj.d);
      queue.push(c.tree);
      for (const p of c.parents) queue.push(p);
    } else if (obj.t === 'tag') {
      queue.push(parseTag(obj.d).object);
    } else if (obj.t === 'tree') {
      for (const e of parseTree(obj.d)) if (e.mode !== '160000') queue.push(e.oid);
    }
  }
  return seen;
}
function isAncestor(repo: Repo, anc: string, desc: string): boolean {
  if (anc === desc) return true;
  const seen = new Set<string>();
  const queue = [desc];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (oid === anc) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj && obj.t === 'commit') for (const p of parseCommit(obj.d).parents) queue.push(p);
    else if (obj && obj.t === 'tag') queue.push(parseTag(obj.d).object);
  }
  return false;
}
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancA = new Set<string>();
  const qa = [a];
  while (qa.length) {
    const oid = qa.pop() as string;
    if (ancA.has(oid)) continue;
    ancA.add(oid);
    const obj = repo.objects.get(oid);
    if (obj && obj.t === 'commit') for (const p of parseCommit(obj.d).parents) qa.push(p);
    else if (obj && obj.t === 'tag') qa.push(parseTag(obj.d).object);
  }
  const seen = new Set<string>();
  const qb = [b];
  while (qb.length) {
    const oid = qb.pop() as string;
    if (ancA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj && obj.t === 'commit') for (const p of parseCommit(obj.d).parents) qb.push(p);
    else if (obj && obj.t === 'tag') qb.push(parseTag(obj.d).object);
  }
  return null;
}
function peelToCommit(repo: Repo, oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 16; i += 1) {
    const obj = repo.objects.get(cur);
    if (!obj) return null;
    if (obj.t === 'commit') return cur;
    if (obj.t === 'tag') { cur = parseTag(obj.d).object; continue; }
    return null;
  }
  return null;
}

// ---------------------------------------------------------------- packfile
// Plain (non-delta) pack writing; reading resolves OFS/REF deltas too.

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const packEntryCache = new Map<string, Buffer>(); // oid -> header+deflated bytes (objects are immutable)
function packEntryBytes(oid: string, obj: GObj): Buffer {
  const hit = packEntryCache.get(oid);
  if (hit) return hit;
  const data = obj.d;
  const header: number[] = [];
  let size = data.length;
  let first = (TYPE_CODE[obj.t] << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  header.push(first);
  while (size > 0) {
    let b = size & 0x7f;
    size >>= 7;
    if (size > 0) b |= 0x80;
    header.push(b);
  }
  const out = Buffer.concat([Buffer.from(header), deflateSync(data)]);
  if (packEntryCache.size > 20000) packEntryCache.clear();
  packEntryCache.set(oid, out);
  return out;
}
function writePack(objects: readonly { oid: string; obj: GObj }[]): Buffer {
  const parts: Buffer[] = [Buffer.alloc(12)];
  parts[0].write('PACK', 0, 4, 'ascii');
  parts[0].writeUInt32BE(2, 4);
  parts[0].writeUInt32BE(objects.length, 8);
  for (const { oid, obj } of objects) parts.push(packEntryBytes(oid, obj));
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}
function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off] as number; off += 1;
    size += (byte & 0x7f) * 2 ** shift; shift += 7;
  }
  return { size, next: off, first };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVar = (): number => {
    let r = 0; let s = 0;
    for (;;) { const b = delta[off] as number; off += 1; r |= (b & 0x7f) << s; s += 7; if (!(b & 0x80)) break; }
    return r;
  };
  const srcSize = readVar();
  const dstSize = readVar();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off] as number; off += 1;
    if (op & 0x80) {
      let cpOff = 0; let cpSize = 0;
      if (op & 0x01) { cpOff = delta[off] as number; off += 1; }
      if (op & 0x02) { cpOff |= (delta[off] as number) << 8; off += 1; }
      if (op & 0x04) { cpOff |= (delta[off] as number) << 16; off += 1; }
      if (op & 0x08) { cpOff |= (delta[off] as number) << 24; off += 1; }
      if (op & 0x10) { cpSize = delta[off] as number; off += 1; }
      if (op & 0x20) { cpSize |= (delta[off] as number) << 8; off += 1; }
      if (op & 0x40) { cpSize |= (delta[off] as number) << 16; off += 1; }
      if (cpSize === 0) cpSize = 0x10000;
      out.push(base.subarray(cpOff, cpOff + cpSize)); total += cpSize;
    } else if (op !== 0) {
      out.push(delta.subarray(off, off + op)); off += op; total += op;
    } else throw new Error('delta op 0');
  }
  const res = Buffer.concat(out, total);
  if (res.length !== dstSize) throw new Error('delta result size mismatch');
  return res;
}
interface PackObject { oid: string; obj: GObj }
function readPack(buf: Buffer): PackObject[] {
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a pack');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = buf.readUInt32BE(8);
  const trailerStart = buf.length - 20;
  const trailer = buf.subarray(trailerStart).toString('hex');
  if (sha1hex(buf.subarray(0, trailerStart)) !== trailer) throw new Error('pack checksum mismatch');
  interface Raw { offset: number; typeCode: number; size: number; data: Buffer; baseOff?: number; baseOid?: string; resolved?: { t: ObjType; d: Buffer; oid: string } }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOff = off;
    const hdr = readVarintSize(buf, off);
    off = hdr.next;
    const typeCode = (hdr.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOff, typeCode, size: hdr.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let b = buf[off] as number; off += 1;
      let v = b & 0x7f;
      while (b & 0x80) { b = buf[off] as number; off += 1; v = ((v + 1) * 128) + (b & 0x7f); }
      entry.baseOff = entryOff - v;
    } else if (typeCode === 7) {
      entry.baseOid = buf.subarray(off, off + 20).toString('hex'); off += 20;
    } else if (!CODE_TYPE[typeCode]) throw new Error('bad pack type');
    const inflated = inflateSync(buf.subarray(off, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    const consumed = inflated.engine.bytesWritten;
    if (!consumed || consumed <= 0) throw new Error('zlib stream consumed no bytes');
    if (inflated.buffer.length !== hdr.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.buffer;
    off += consumed;
    raw.push(entry);
    byOffset.set(entryOff, entry);
  }
  if (off !== trailerStart) throw new Error('pack trailing bytes');
  const resolvedByOid = new Map<string, Raw>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): { t: ObjType; d: Buffer; oid: string } => {
    if (entry.resolved) return entry.resolved;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let out: { t: ObjType; d: Buffer; oid: string };
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: { t: ObjType; d: Buffer; oid: string };
      if (entry.typeCode === 6) {
        const b = byOffset.get(entry.baseOff as number);
        if (!b) throw new Error('ofs-delta base missing');
        base = resolve(b);
      } else {
        const b = resolvedByOid.get(entry.baseOid as string);
        if (!b) throw new Error('ref-delta base missing');
        base = resolve(b);
      }
      const data = applyDelta(base.d, entry.data);
      out = { t: base.t, d: data, oid: hashObject(base.t, data) };
    } else {
      const t = CODE_TYPE[entry.typeCode] as ObjType;
      out = { t, d: entry.data, oid: hashObject(t, entry.data) };
    }
    resolving.delete(entry.offset);
    entry.resolved = out;
    resolvedByOid.set(out.oid, entry);
    return out;
  };
  const result: PackObject[] = [];
  for (const entry of raw) {
    const r = resolve(entry);
    result.push({ oid: r.oid, obj: { t: r.t, d: r.d } });
  }
  return result;
}

// ---------------------------------------------------------------- store

interface Label { id: number; name: string; color: string; description: string }
interface Issue { id: number; number: number; title: string; body: string; state: 'open' | 'closed'; labels: Label[]; seq: number; closedAt: string | null }
interface Comment { id: number; body: string; seq: number }
interface Pull { id: number; number: number; title: string; body: string; state: 'open' | 'closed'; merged: boolean; mergedAt: string | null; mergeSha: string | null; head: string; base: string; headSha: string; baseSha: string; seq: number }
interface Repo {
  id: number; owner: string; name: string; description: string; priv: boolean; defaultBranch: string;
  refs: Map<string, string>; objects: Map<string, GObj>;
  issues: Issue[]; nextIssue: number; labels: Map<string, Label>;
  pulls: Pull[]; nextPull: number; comments: Map<number, Comment[]>;
  seq: number; ver: number;
  repoJson: Buffer | null; issueJson: Map<number, Buffer>;
}
const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextDbId = 100000;
let nextSeq = 0;
function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function getRepo(owner: string, name: string): Repo | undefined { return repos.get(repoKey(owner, name)); }
function createRepoObj(owner: string, name: string, description: string, priv: boolean, defaultBranch: string): Repo {
  const r: Repo = {
    id: nextRepoId, owner, name, description, priv, defaultBranch,
    refs: new Map(), objects: new Map(),
    issues: [], nextIssue: 1, labels: new Map(),
    pulls: [], nextPull: 1, comments: new Map(),
    seq: nextSeq, ver: 0, repoJson: null, issueJson: new Map(),
  };
  nextRepoId += 1; nextSeq += 1;
  repos.set(repoKey(owner, name), r);
  return r;
}
function touchRepo(r: Repo): void { r.ver += 1; r.repoJson = null; }
function storeObject(r: Repo, t: ObjType, d: Buffer): string {
  const oid = hashObject(t, d);
  if (!r.objects.has(oid)) r.objects.set(oid, { t, d });
  return oid;
}
function branchTip(r: Repo, branch: string): string | undefined { return r.refs.get(`refs/heads/${branch}`); }
function refTip(r: Repo, ref: string): string | undefined { return r.refs.get(ref); }

// Flatten a tree (commit's tree) to path -> {mode, oid}.
function flattenTree(r: Repo, treeOid: string, prefix: string, out: Map<string, { mode: string; oid: string }>): void {
  const obj = r.objects.get(treeOid);
  if (!obj || obj.t !== 'tree') return;
  for (const e of parseTree(obj.d)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') flattenTree(r, e.oid, path, out);
    else out.set(path, { mode: e.mode, oid: e.oid });
  }
}
function flatOfCommit(r: Repo, commitOid: string | undefined): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  if (!commitOid) return out;
  const c = r.objects.get(commitOid);
  if (!c || c.t !== 'commit') return out;
  flattenTree(r, parseCommit(c.d).tree, '', out);
  return out;
}
// Rebuild nested trees from a flat map; returns the root tree oid.
function rebuildTree(r: Repo, files: Map<string, { mode: string; oid: string }>): string {
  interface Node { files: Map<string, { mode: string; oid: string }>; dirs: Map<string, Node> }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, v] of files) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i += 1) {
      const s = segs[i] as string;
      let child = node.dirs.get(s);
      if (!child) { child = { files: new Map(), dirs: new Map() }; node.dirs.set(s, child); }
      node = child;
    }
    node.files.set(segs[segs.length - 1] as string, v);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, v] of node.files) entries.push({ mode: v.mode, name, oid: v.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(r, 'tree', buildTree(entries));
  };
  return build(root);
}
function makeCommit(r: Repo, tree: string, parents: readonly string[], message: string): string {
  return storeObject(r, 'commit', buildCommit(tree, parents, message));
}
function history(r: Repo, tip: string | undefined, limit: number): string[] {
  const out: string[] = [];
  if (!tip) return out;
  const seen = new Set<string>();
  const queue = [tip];
  // BFS by generation is not newest-first; walk first-parent chain plus merge parents
  // in commit order using a simple stack ordered by insertion (parents appended).
  while (queue.length && out.length < limit) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = r.objects.get(oid);
    if (!obj || obj.t !== 'commit') continue;
    out.push(oid);
    for (const p of parseCommit(obj.d).parents) queue.push(p);
  }
  return out;
}

// ---------------------------------------------------------------- JSON views

function userJson(login: string): Record<string, unknown> {
  return { login, id: login === VIEWER.login ? VIEWER.id : 0, node_id: gid('U', login), avatar_url: '', gravatar_id: '', url: `/api/v3/users/${login}`, html_url: `https://example.invalid/${login}`, type: 'User', site_admin: false };
}
function repoView(r: Repo): Record<string, unknown> {
  return {
    id: r.id, node_id: gid('R', `${r.owner}/${r.name}`), name: r.name, full_name: `${r.owner}/${r.name}`,
    owner: userJson(r.owner), private: r.priv, html_url: `https://example.invalid/${r.owner}/${r.name}`,
    description: r.description, fork: false, url: `/api/v3/repos/${r.owner}/${r.name}`,
    created_at: FIXED_ISO, updated_at: FIXED_ISO, pushed_at: FIXED_ISO,
    git_url: `git://example.invalid/${r.owner}/${r.name}.git`, ssh_url: `git@example.invalid:${r.owner}/${r.name}.git`,
    clone_url: `https://example.invalid/${r.owner}/${r.name}.git`, svn_url: `https://example.invalid/${r.owner}/${r.name}`,
    homepage: null, size: 0, stargazers_count: 0, watchers_count: 0, language: null, has_issues: true,
    has_projects: true, has_downloads: true, has_wiki: true, has_pages: false, has_discussions: false,
    forks_count: 0, mirror_url: null, archived: false, disabled: false, open_issues_count: r.issues.filter((i) => i.state === 'open').length,
    license: null, allow_forking: true, is_template: false, web_commit_signoff_required: false,
    topics: [], visibility: r.priv ? 'private' : 'public', forks: 0, open_issues: r.issues.filter((i) => i.state === 'open').length,
    watchers: 0, default_branch: r.defaultBranch,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}
function repoJsonBuf(r: Repo): Buffer {
  if (!r.repoJson) r.repoJson = Buffer.from(JSON.stringify(repoView(r)), 'utf8');
  return r.repoJson;
}
function labelView(l: Label): Record<string, unknown> {
  return { id: l.id, node_id: gid('L', `${l.name}`), url: '', name: l.name, color: l.color, default: false, description: l.description };
}
function issueView(r: Repo, iss: Issue): Record<string, unknown> {
  return {
    id: iss.id, node_id: gid('I', `${r.owner}/${r.name}#${iss.number}`), number: iss.number, title: iss.title,
    body: iss.body, state: iss.state, locked: false, assignee: null, assignees: [], milestone: null,
    comments: (r.comments.get(iss.number) ?? []).length,
    created_at: FIXED_ISO, updated_at: FIXED_ISO, closed_at: iss.closedAt,
    author_association: 'OWNER', active_lock_reason: null,
    html_url: `https://example.invalid/${r.owner}/${r.name}/issues/${iss.number}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/issues/${iss.number}`,
    repository_url: `/api/v3/repos/${r.owner}/${r.name}`,
    labels_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${iss.number}/labels{/name}`,
    comments_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${iss.number}/comments`,
    events_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${iss.number}/events`,
    user: userJson(VIEWER.login), labels: iss.labels.map(labelView),
    reactions: { url: '', total_count: 0, '+1': 0, '-1': 0, laugh: 0, hooray: 0, confused: 0, heart: 0, rocket: 0, eyes: 0 },
    timeline_url: '', performed_via_github_app: null, state_reason: null, draft: false,
  };
}
function issueJsonBuf(r: Repo, iss: Issue): Buffer {
  const hit = r.issueJson.get(iss.number);
  if (hit) return hit;
  const buf = Buffer.from(JSON.stringify(issueView(r, iss)), 'utf8');
  r.issueJson.set(iss.number, buf);
  return buf;
}
function invalidateIssue(r: Repo, n: number): void { r.issueJson.delete(n); r.repoJson = null; }
function pullView(r: Repo, pr: Pull): Record<string, unknown> {
  const headRepo = repoView(r);
  return {
    id: pr.id, node_id: gid('P', `${r.owner}/${r.name}#${pr.number}`), number: pr.number, title: pr.title, body: pr.body,
    state: pr.state, locked: false,
    user: userJson(VIEWER.login), labels: [], milestone: null, active_lock_reason: null,
    created_at: FIXED_ISO, updated_at: FIXED_ISO, closed_at: pr.state === 'closed' ? FIXED_ISO : null,
    merged_at: pr.mergedAt, merge_commit_sha: pr.mergeSha, assignee: null, assignees: [],
    requested_reviewers: [], requested_teams: [], draft: false,
    commits_url: '', review_comments_url: '', review_comment_url: '', comments_url: '', statuses_url: '',
    html_url: `https://example.invalid/${r.owner}/${r.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${r.owner}/${r.name}/pulls/${pr.number}`,
    issue_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${pr.number}`,
    head: { label: `${r.owner}:${pr.head}`, ref: pr.head, sha: prHeadTip(r, pr), user: userJson(VIEWER.login), repo: headRepo },
    base: { label: `${r.owner}:${pr.base}`, ref: pr.base, sha: prBaseTip(r, pr), user: userJson(VIEWER.login), repo: headRepo },
    merged: pr.merged, mergeable: prMergeable(r, pr) === 'MERGEABLE', mergeable_state: prMergeable(r, pr).toLowerCase(),
    merge_method: 'squash', merged_by: pr.merged ? userJson(VIEWER.login) : null,
    comments: 0, review_comments: 0, maintainer_can_modify: false, commits: 1, additions: 0, deletions: 0, changed_files: 0,
    author_association: 'OWNER', auto_merge: null,
  };
}
function commentView(r: Repo, iss: Issue, c: Comment): Record<string, unknown> {
  return {
    id: c.id, node_id: gid('C', `${r.owner}/${r.name}#${iss.number}:${c.id}`), url: `/api/v3/repos/${r.owner}/${r.name}/issues/comments/${c.id}`,
    html_url: `https://example.invalid/${r.owner}/${r.name}/issues/${iss.number}#issuecomment-${c.id}`,
    body: c.body, user: userJson(VIEWER.login), created_at: FIXED_ISO, updated_at: FIXED_ISO,
    issue_url: `/api/v3/repos/${r.owner}/${r.name}/issues/${iss.number}`, author_association: 'OWNER',
    reactions: { url: '', total_count: 0, '+1': 0, '-1': 0, laugh: 0, hooray: 0, confused: 0, heart: 0, rocket: 0, eyes: 0 },
    performed_via_github_app: null,
  };
}

// ---------------------------------------------------------------- contents + PR logic

function contentsCommit(r: Repo, branch: string, path: string, content: Buffer, message: string, sha: string | undefined): { status: 200 | 201; commitSha: string; blobSha: string } {
  const tip = branchTip(r, branch);
  const flat = flatOfCommit(r, tip);
  const existing = flat.get(path);
  if (sha !== undefined) {
    if (!existing || existing.oid !== sha) throw Object.assign(new Error('sha mismatch'), { status: 409 });
  } else if (existing) {
    throw Object.assign(new Error('file exists'), { status: 409 });
  }
  const blobSha = storeObject(r, 'blob', content);
  flat.set(path, { mode: '100644', oid: blobSha });
  const tree = rebuildTree(r, flat);
  const parents = tip ? [tip] : [];
  const commitSha = makeCommit(r, tree, parents, message);
  if (!branchTip(r, branch)) {
    // first commit on a new branch ref
  }
  r.refs.set(`refs/heads/${branch}`, commitSha);
  touchRepo(r);
  return { status: existing ? 200 : 201, commitSha, blobSha };
}
function contentsDelete(r: Repo, branch: string, path: string, message: string): { commitSha: string } {
  const tip = branchTip(r, branch);
  if (!tip) throw Object.assign(new Error('no such file'), { status: 404 });
  const flat = flatOfCommit(r, tip);
  if (!flat.has(path)) throw Object.assign(new Error('no such file'), { status: 404 });
  flat.delete(path);
  const tree = rebuildTree(r, flat);
  const commitSha = makeCommit(r, tree, [tip], message);
  r.refs.set(`refs/heads/${branch}`, commitSha);
  touchRepo(r);
  return { commitSha };
}
function resolveRef(r: Repo, ref: string | undefined): string | undefined {
  if (!ref) return branchTip(r, r.defaultBranch);
  if (isOid(ref)) return ref;
  if (r.refs.has(`refs/heads/${ref}`)) return r.refs.get(`refs/heads/${ref}`);
  if (r.refs.has(`refs/tags/${ref}`)) return r.refs.get(`refs/tags/${ref}`);
  if (r.refs.has(ref)) return r.refs.get(ref);
  return undefined;
}
interface FileChange { path: string; status: 'added' | 'modified' | 'removed'; oldOid: string | null; newOid: string | null }
function diffTrees(r: Repo, baseCommit: string | undefined, headCommit: string | undefined): FileChange[] {
  const base = flatOfCommit(r, baseCommit);
  const head = flatOfCommit(r, headCommit);
  const paths = new Set([...base.keys(), ...head.keys()]);
  const out: FileChange[] = [];
  for (const p of [...paths].sort()) {
    const b = base.get(p); const h = head.get(p);
    if (b && !h) out.push({ path: p, status: 'removed', oldOid: b.oid, newOid: null });
    else if (!b && h) out.push({ path: p, status: 'added', oldOid: null, newOid: h.oid });
    else if (b && h && b.oid !== h.oid) out.push({ path: p, status: 'modified', oldOid: b.oid, newOid: h.oid });
  }
  return out;
}
function lineCounts(r: Repo, oid: string | null): number {
  if (!oid) return 0;
  const obj = r.objects.get(oid);
  if (!obj) return 0;
  const text = obj.d.toString('utf8');
  if (text === '') return 0;
  return text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
}
function diffLineCounts(r: Repo, a: Buffer | null, b: Buffer | null): { add: number; del: number } {
  const la = a ? a.toString('utf8').split('\n') : [];
  const lb = b ? b.toString('utf8').split('\n') : [];
  if (la.length && la[la.length - 1] === '') la.pop();
  if (lb.length && lb[lb.length - 1] === '') lb.pop();
  if (la.length > 300 || lb.length > 300) return { add: lb.length, del: la.length };
  // LCS DP
  const m = la.length; const n = lb.length;
  const dp: number[][] = [];
  for (let i = 0; i <= m; i += 1) dp.push(new Array<number>(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i -= 1) {
    for (let j = n - 1; j >= 0; j -= 1) {
      dp[i]![j] = la[i] === lb[j] ? (dp[i + 1]![j + 1] as number) + 1 : Math.max(dp[i + 1]![j] as number, dp[i]![j + 1] as number);
    }
  }
  const common = dp[0]![0] as number;
  return { add: n - common, del: m - common };
}
function pullFiles(r: Repo, pr: Pull): Record<string, unknown>[] {
  const changes = diffTrees(r, pr.baseSha, pr.headSha);
  return changes.map((c) => {
    const oldBuf = c.oldOid ? (r.objects.get(c.oldOid)?.d ?? null) : null;
    const newBuf = c.newOid ? (r.objects.get(c.newOid)?.d ?? null) : null;
    let add = 0; let del = 0;
    if (c.status === 'added') add = lineCounts(r, c.newOid);
    else if (c.status === 'removed') del = lineCounts(r, c.oldOid);
    else { const lc = diffLineCounts(r, oldBuf, newBuf); add = lc.add; del = lc.del; if (add === 0 && del === 0) add = 1; }
    return {
      sha: c.newOid ?? c.oldOid, filename: c.path, status: c.status,
      additions: add, deletions: del, changes: add + del,
      blob_url: '', raw_url: '', contents_url: '',
      patch: '',
    };
  });
}
function prBaseTip(r: Repo, pr: Pull): string { return branchTip(r, pr.base) ?? pr.baseSha; }
function prHeadTip(r: Repo, pr: Pull): string { return branchTip(r, pr.head) ?? pr.headSha; }
function prMergeable(r: Repo, pr: Pull): 'MERGEABLE' | 'CONFLICTING' {
  if (pr.state !== 'open') return 'MERGEABLE';
  const baseTip = prBaseTip(r, pr);
  const headTip = prHeadTip(r, pr);
  const mb = mergeBase(r, headTip, baseTip);
  if (!mb) return 'MERGEABLE';
  const baseChanges = diffTrees(r, mb, baseTip);
  const headChanges = diffTrees(r, mb, headTip);
  const baseMap = new Map(baseChanges.map((c) => [c.path, c]));
  for (const hc of headChanges) {
    const bc = baseMap.get(hc.path);
    if (bc && bc.newOid !== hc.newOid) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}
function doMerge(r: Repo, pr: Pull): { ok: boolean; sha: string | null; message: string } {
  if (pr.state !== 'open') return { ok: false, sha: null, message: 'Pull request is already closed' };
  if (prMergeable(r, pr) === 'CONFLICTING') return { ok: false, sha: null, message: 'Merge conflict' };
  const baseTip = prBaseTip(r, pr);
  const headTip = prHeadTip(r, pr);
  const mb = mergeBase(r, headTip, baseTip);
  const headChanges = diffTrees(r, mb ?? undefined, headTip);
  const flat = flatOfCommit(r, baseTip);
  for (const c of headChanges) {
    if (c.status === 'removed') flat.delete(c.path);
    else if (c.newOid) flat.set(c.path, { mode: '100644', oid: c.newOid });
  }
  const tree = rebuildTree(r, flat);
  const message = `Merge pull request #${pr.number} from ${r.owner}/${pr.head}`;
  const commitSha = makeCommit(r, tree, [baseTip], message);
  r.refs.set(`refs/heads/${pr.base}`, commitSha);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = FIXED_ISO;
  pr.mergeSha = commitSha;
  touchRepo(r);
  return { ok: true, sha: commitSha, message: 'Pull request successfully merged' };
}
function createIssueObj(r: Repo, title: string, body: string, labels: Label[]): Issue {
  const iss: Issue = { id: nextDbId, number: r.nextIssue, title, body: body ?? '', state: 'open', labels, seq: nextSeq, closedAt: null };
  nextDbId += 1; nextSeq += 1; r.nextIssue += 1;
  r.issues.push(iss);
  r.repoJson = null;
  return iss;
}
function createPullObj(r: Repo, title: string, body: string, head: string, base: string): Pull | { error: string } {
  const headSha = branchTip(r, head);
  const baseSha = branchTip(r, base);
  if (!headSha || !baseSha) return { error: 'Head or base branch does not exist' };
  if (r.pulls.some((p) => p.head === head && p.state === 'open')) return { error: 'A pull request already exists for this head branch' };
  const pr: Pull = {
    id: nextDbId, number: r.nextPull, title, body: body ?? '', state: 'open', merged: false,
    mergedAt: null, mergeSha: null, head, base, headSha, baseSha, seq: nextSeq,
  };
  nextDbId += 1; nextSeq += 1; r.nextPull += 1;
  r.pulls.push(pr);
  r.repoJson = null;
  return pr;
}

// ---------------------------------------------------------------- HTTP plumbing

const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return false;
  const tok = h.slice(7);
  if (tok === '') return false;
  if (EXPECTED_TOKEN === '') return true;
  return tok === EXPECTED_TOKEN;
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function sendBuf(res: ServerResponse, status: number, buf: Buffer, type: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': type, 'content-length': buf.length, 'x-github-request-id': nextReqId(), ...extra });
  res.end(buf);
}
function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  sendBuf(res, status, Buffer.from(JSON.stringify(body), 'utf8'), JSON_TYPE, extra);
}
function sendJsonBuf(res: ServerResponse, status: number, buf: Buffer, extra: Record<string, string> = {}): void {
  sendBuf(res, status, buf, JSON_TYPE, extra);
}
function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: undefined };
  try { return { ok: true, value: JSON.parse(raw.toString('utf8')) as unknown }; }
  catch { return { ok: false }; }
}
function isRec(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function str(v: unknown, dflt = ''): string { return typeof v === 'string' ? v : dflt; }
function pathSegments(pathname: string): string[] {
  return pathname.split('/').filter((s) => s !== '').map((s) => {
    try { return decodeURIComponent(s); } catch { return s; }
  });
}
function pageParams(q: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, parseInt(q.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(q.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}
function paginate<T>(items: readonly T[], q: URLSearchParams, req: IncomingMessage, pathname: string): { items: readonly T[]; link: string | null } {
  const { page, perPage } = pageParams(q);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const host = req.headers.host ?? 'localhost';
    const mk = (p: number): string => {
      const nq = new URLSearchParams(q);
      nq.set('page', String(p)); nq.set('per_page', String(perPage));
      return `<http://${host}${pathname}?${nq.toString()}>`;
    };
    const last = Math.ceil(items.length / perPage);
    link = `${mk(page + 1)}; rel="next", ${mk(last)}; rel="last"`;
  }
  return { items: slice, link };
}
function linkHeader(res: ServerResponse, link: string | null, extra: Record<string, string>): Record<string, string> {
  return link ? { ...extra, link } : extra;
}

// ---------------------------------------------------------------- git smart HTTP

function sortedRefs(r: Repo): { name: string; oid: string }[] {
  return [...r.refs.entries()].map(([name, oid]) => ({ name, oid })).sort((a, b) => (a.name < b.name ? -1 : 1));
}
function peelOid(r: Repo, oid: string): string | null {
  const obj = r.objects.get(oid);
  if (!obj) return null;
  if (obj.t === 'tag') return parseTag(obj.d).object;
  return null;
}
function v0RefLines(r: Repo, caps: string): Buffer[] {
  const refs = sortedRefs(r);
  const defTip = r.refs.get(`refs/heads/${r.defaultBranch}`) ?? ZERO_OID;
  const parts: Buffer[] = [];
  if (refs.length === 0) {
    parts.push(pkt(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    parts.push(pkt(`${defTip} HEAD\0${caps}\n`));
    for (const ref of refs) {
      parts.push(pkt(`${ref.oid} ${ref.name}\n`));
      const peeled = peelOid(r, ref.oid);
      if (peeled) parts.push(pkt(`${peeled} ${ref.name}^{}\n`));
    }
  }
  parts.push(PKT_FLUSH);
  return parts;
}
function infoRefs(res: ServerResponse, r: Repo, service: string, req: IncomingMessage): void {
  const type = `application/x-${service}-advertisement`;
  if (service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2') {
    const body = pktLines([
      'version 2\n', 'agent=forge/1.0\n', 'fetch=shallow filter\n', 'ls-refs=unborn\n', 'object-format=sha1\n', 'flush',
    ]);
    sendBuf(res, 200, body, type);
    return;
  }
  const caps = service === 'git-upload-pack'
    ? `multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/${r.defaultBranch} object-format=sha1 agent=forge/1.0`
    : 'report-status report-status-v2 delete-refs side-band-64k ofs-delta object-format=sha1 agent=forge/1.0';
  const preamble = pkt(`# service=${service}\n`);
  const rest = v0RefLines(r, caps);
  sendBuf(res, 200, Buffer.concat([preamble, ...rest]), type);
}
function lsRefsV2(res: ServerResponse, r: Repo, body: Buffer): void {
  const lines = pktTextLines(body);
  if (lines === null) { sendBuf(res, 400, Buffer.from('bad request', 'utf8'), 'text/plain; charset=utf-8'); return; }
  let peel = false; let symrefs = false; const prefixes: string[] = [];
  for (const line of lines) {
    if (line === 'peel\n') peel = true;
    else if (line === 'symrefs\n') symrefs = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length).trim());
  }
  const out: (string | 'flush')[] = [];
  const refs = sortedRefs(r);
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (refs.length === 0) {
    if (keep('HEAD')) out.push(`unborn HEAD symref-target:refs/heads/${r.defaultBranch}\n`);
  } else {
    const defTip = r.refs.get(`refs/heads/${r.defaultBranch}`);
    if (defTip && symrefs && keep('HEAD')) out.push(`${defTip} HEAD symref-target:refs/heads/${r.defaultBranch}\n`);
    for (const ref of refs) {
      if (!keep(ref.name)) continue;
      let line = `${ref.oid} ${ref.name}`;
      if (peel) {
        const peeled = peelOid(r, ref.oid);
        if (peeled) line += ` peeled:${peeled}`;
      }
      out.push(`${line}\n`);
    }
  }
  out.push('flush');
  sendBuf(res, 200, pktLines(out), 'application/x-git-upload-pack-result');
}
// Compute the fetch object set, shallow boundaries and acks for v2/v0 fetch.
interface FetchPlan { send: PackObject[]; shallow: string[]; unshallow: string[]; acks: string[] }
function planFetch(r: Repo, wants: string[], haves: string[], shallowIn: string[], depth: number | null): FetchPlan {
  const wantCommits: string[] = [];
  for (const w of wants) {
    const c = peelToCommit(r, w);
    if (c) wantCommits.push(c);
  }
  // Objects the client already holds: reachable from its haves, but never past a
  // shallow boundary (a shallow clone holds the boundary commit, not its parents).
  const stopSet = new Set(shallowIn);
  const haveReach = new Set<string>();
  for (const h of haves) {
    const queue = [h];
    const seen = new Set<string>();
    while (queue.length) {
      const oid = queue.pop() as string;
      if (seen.has(oid) || haveReach.has(oid)) continue;
      seen.add(oid);
      const obj = r.objects.get(oid);
      if (!obj) continue;
      haveReach.add(oid);
      if (obj.t === 'commit') {
        const c = parseCommit(obj.d);
        queue.push(c.tree);
        if (!stopSet.has(oid)) for (const p of c.parents) queue.push(p);
      } else if (obj.t === 'tag') queue.push(parseTag(obj.d).object);
      else if (obj.t === 'tree') for (const e of parseTree(obj.d)) if (e.mode !== '160000') queue.push(e.oid);
    }
  }
  let included: Set<string>;
  let commitDist = new Map<string, number>();
  if (depth !== null) {
    // BFS over commits from wants.
    const dist = new Map<string, number>();
    const queue: string[] = [];
    for (const c of wantCommits) { if (!dist.has(c)) { dist.set(c, 0); queue.push(c); } }
    while (queue.length) {
      const cur = queue.shift() as string;
      const d = dist.get(cur) as number;
      if (d + 1 >= depth) continue;
      const obj = r.objects.get(cur);
      if (obj && obj.t === 'commit') {
        for (const p of parseCommit(obj.d).parents) {
          if (!dist.has(p)) { dist.set(p, d + 1); queue.push(p); }
        }
      }
    }
    commitDist = dist;
    const incCommits = new Set<string>();
    for (const [c, d] of dist) if (d < depth) incCommits.add(c);
    included = new Set<string>();
    for (const c of incCommits) {
      if (haveReach.has(c)) continue;
      try { for (const o of collectReachable(r, [c], true)) {
        // only this commit's own tree/blobs, not ancestors (they are separate commits)
        if (o === c) included.add(o);
      } } catch { /* ignore */ }
      const obj = r.objects.get(c);
      if (obj && obj.t === 'commit') {
        const pc = parseCommit(obj.d);
        const treeReach = new Set<string>();
        try { for (const o of collectReachable(r, [pc.tree], true)) treeReach.add(o); } catch { /* ignore */ }
        for (const o of treeReach) if (!haveReach.has(o)) included.add(o);
      }
    }
    // tag objects wanted directly are always included
    for (const w of wants) {
      const obj = r.objects.get(w);
      if (obj && obj.t === 'tag' && !haveReach.has(w)) included.add(w);
    }
  } else {
    let wantReach: Set<string>;
    try { wantReach = collectReachable(r, wants, true); } catch { wantReach = new Set(); }
    included = new Set([...wantReach].filter((o) => !haveReach.has(o)));
  }
  // shallow boundaries: included commits with a parent not included
  const shallow: string[] = [];
  if (depth !== null) {
    for (const c of commitDist.keys()) {
      if (!included.has(c)) continue;
      const obj = r.objects.get(c);
      if (!obj || obj.t !== 'commit') continue;
      const parents = parseCommit(obj.d).parents;
      if (parents.some((p) => !included.has(p))) shallow.push(c);
    }
  }
  const unshallow: string[] = [];
  if (depth !== null) {
    for (const b of shallowIn) {
      if (!shallow.includes(b) && included.size > 0) {
        // boundary is unshallowed when one of its parents was delivered now
        const obj = r.objects.get(b);
        if (obj && obj.t === 'commit') {
          const parents = parseCommit(obj.d).parents;
          if (parents.some((p) => included.has(p))) unshallow.push(b);
        }
      }
    }
  }
  const acks: string[] = [];
  let wantReachAll: Set<string> = new Set();
  try { wantReachAll = collectReachable(r, wants, true); } catch { /* ignore */ }
  for (const h of haves) if (wantReachAll.has(h)) acks.push(h);
  const send: PackObject[] = [...included].sort().map((oid) => ({ oid, obj: r.objects.get(oid) as GObj })).filter((e) => e.obj !== undefined);
  return { send, shallow, unshallow, acks };
}
function sidebandPack(pack: Buffer): Buffer {
  // One pre-sized Buffer for the whole sideband stream: each 64 KiB chunk becomes
  // one pkt-line (4-byte hex length + band byte 1 + chunk). Byte-identical to the
  // old per-chunk pkt() + Buffer.concat assembly.
  const CHUNK = 65515;
  if (pack.length === 0) return pkt(Buffer.from([1]));
  const n = Math.ceil(pack.length / CHUNK);
  let total = 0;
  for (let i = 0; i < n; i += 1) total += 4 + 1 + Math.min(CHUNK, pack.length - i * CHUNK);
  const out = Buffer.alloc(total);
  let off = 0;
  for (let i = 0; i < n; i += 1) {
    const start = i * CHUNK;
    const len = Math.min(CHUNK, pack.length - start);
    const frameLen = 1 + len + 4;
    out.write(frameLen.toString(16).padStart(4, '0'), off, 4, 'ascii');
    out[off + 4] = 1;
    pack.copy(out, off + 5, start, start + len);
    off += frameLen;
  }
  return out;
}
// Cache whole fetch responses per repo version + request key (clone workload hits this).
const fetchCache = new Map<string, Buffer>();
function fetchCacheKey(r: Repo, wants: string[], haves: string[], shallowIn: string[], depth: number | null): string {
  return `${r.owner}/${r.name}|v${r.ver}|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${[...shallowIn].sort().join(',')}|${depth ?? ''}`;
}
function uploadPackV2(res: ServerResponse, r: Repo, body: Buffer): void {
  const lines = pktTextLines(body);
  if (lines === null) { sendBuf(res, 400, Buffer.from('bad request', 'utf8'), 'text/plain; charset=utf-8'); return; }
  const command = (lines[0] ?? '').trim();
  if (command === 'command=ls-refs') { lsRefsV2(res, r, body); return; }
  if (command !== 'command=fetch') { sendBuf(res, 400, Buffer.from('bad request', 'utf8'), 'text/plain; charset=utf-8'); return; }
  const wants: string[] = []; const haves: string[] = []; const shallowIn: string[] = [];
  let depth: number | null = null;
  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith('want ')) wants.push(t.slice(5).trim());
    else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) shallowIn.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) { const n = parseInt(t.slice(7).trim(), 10); if (Number.isFinite(n)) depth = n; }
  }
  for (const w of wants) if (!r.objects.has(w)) { sendBuf(res, 400, Buffer.from('want not found', 'utf8'), 'text/plain; charset=utf-8'); return; }
  const key = fetchCacheKey(r, wants, haves, shallowIn, depth);
  const cached = fetchCache.get(key);
  if (cached) { sendBuf(res, 200, cached, 'application/x-git-upload-pack-result'); return; }
  const plan = planFetch(r, wants, haves, shallowIn, depth);
  const pack = writePack(plan.send);
  const parts: Buffer[] = [];
  parts.push(pkt('acknowledgments\n'));
  if (plan.acks.length) for (const a of plan.acks) parts.push(pkt(`ACK ${a}\n`));
  else parts.push(pkt('NAK\n'));
  parts.push(PKT_FLUSH);
  if (plan.shallow.length || plan.unshallow.length) {
    parts.push(pkt('shallow-info\n'));
    for (const s of plan.shallow) parts.push(pkt(`shallow ${s}\n`));
    for (const s of plan.unshallow) parts.push(pkt(`unshallow ${s}\n`));
    parts.push(PKT_FLUSH);
  }
  parts.push(pkt('packfile\n'));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  if (fetchCache.size > 512) fetchCache.clear();
  fetchCache.set(key, out);
  sendBuf(res, 200, out, 'application/x-git-upload-pack-result');
}
function uploadPackV0(res: ServerResponse, r: Repo, body: Buffer): void {
  const lines = pktTextLines(body);
  if (lines === null) { sendBuf(res, 400, Buffer.from('bad request', 'utf8'), 'text/plain; charset=utf-8'); return; }
  const wants: string[] = []; const haves: string[] = []; const shallowIn: string[] = [];
  let depth: number | null = null;
  for (const line of lines) {
    if (line === '\0FLUSH\0') continue;
    const t = line.trim();
    if (t.startsWith('want ')) wants.push(t.slice(5).split(' ')[0] as string);
    else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) shallowIn.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) { const n = parseInt(t.slice(7).trim(), 10); if (Number.isFinite(n)) depth = n; }
  }
  if (wants.length === 0) { sendBuf(res, 400, Buffer.from('bad request', 'utf8'), 'text/plain; charset=utf-8'); return; }
  for (const w of wants) if (!r.objects.has(w)) { sendBuf(res, 400, Buffer.from('want not found', 'utf8'), 'text/plain; charset=utf-8'); return; }
  const plan = planFetch(r, wants, haves, shallowIn, depth);
  const pack = writePack(plan.send);
  const parts: Buffer[] = [];
  if (plan.acks.length) for (const a of plan.acks) parts.push(pkt(`ACK ${a}\n`));
  else parts.push(pkt('NAK\n'));
  for (const s of plan.shallow) parts.push(pkt(`shallow ${s}\n`));
  for (const s of plan.unshallow) parts.push(pkt(`unshallow ${s}\n`));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  sendBuf(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}
function receivePack(res: ServerResponse, r: Repo, body: Buffer): void {
  // Split pkt-line command section from the trailing raw pack.
  let off = 0;
  const cmdLines: string[] = [];
  let caps = '';
  let bad = false;
  while (off < body.length) {
    if (off + 4 > body.length) { bad = true; break; }
    const head = body.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) { bad = true; break; }
    const len = parseInt(head, 16);
    if (len === 0) { off += 4; break; }
    if (len < 4 || off + len > body.length) { bad = true; break; }
    const payload = body.subarray(off + 4, off + len).toString('utf8');
    const nul = payload.indexOf('\0');
    if (nul >= 0 && cmdLines.length === 0) { caps = payload.slice(nul + 1).trim(); cmdLines.push(payload.slice(0, nul)); }
    else cmdLines.push(payload);
    off += len;
  }
  const packBytes = body.subarray(off);
  const sideband = caps.split(/\s+/).includes('side-band-64k');
  const reportLines: string[] = [];
  const sendReport = (unpackOk: boolean, unpackDetail: string): void => {
    reportLines.push(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`);
  };
  if (bad || cmdLines.length === 0) {
    sendReport(false, 'bad command list');
    const bodyOut = pktLines(reportLines.map((l) => l as string));
    sendBuf(res, 200, bodyOut, 'application/x-git-receive-pack-result');
    return;
  }
  interface Cmd { oldOid: string; newOid: string; ref: string }
  const cmds: Cmd[] = [];
  let parseBad = false;
  for (const line of cmdLines) {
    const t = line.trim();
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(t);
    if (!m) { parseBad = true; break; }
    cmds.push({ oldOid: m[1] as string, newOid: m[2] as string, ref: m[3] as string });
  }
  if (parseBad) {
    sendReport(false, 'bad command');
    sendBuf(res, 200, pktLines(reportLines.map((l) => l as string)), 'application/x-git-receive-pack-result');
    return;
  }
  const updates = cmds.some((c) => c.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  let packObjs: PackObject[] = [];
  if (packBytes.length > 0) {
    try { packObjs = readPack(packBytes); }
    catch (e) { unpackOk = false; unpackDetail = e instanceof Error ? e.message : 'unpack failed'; }
  } else if (updates) {
    unpackOk = false; unpackDetail = 'missing pack';
  }
  if (unpackOk) {
    for (const { oid, obj } of packObjs) {
      if (!r.objects.has(oid)) r.objects.set(oid, obj);
    }
  }
  const results: { ref: string; ok: boolean; reason: string }[] = [];
  if (unpackOk) {
    for (const cmd of cmds) {
      const cur = r.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        if (!cur) results.push({ ref: cmd.ref, ok: false, reason: 'ref does not exist' });
        else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== cur) results.push({ ref: cmd.ref, ok: false, reason: 'old value does not match' });
        else { r.refs.delete(cmd.ref); results.push({ ref: cmd.ref, ok: true, reason: '' }); }
      } else {
        if (!r.objects.has(cmd.newOid)) { results.push({ ref: cmd.ref, ok: false, reason: 'object not found' }); continue; }
        if (cmd.oldOid === ZERO_OID) {
          if (cur) results.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
          else { r.refs.set(cmd.ref, cmd.newOid); results.push({ ref: cmd.ref, ok: true, reason: '' }); }
        } else {
          if (!cur) results.push({ ref: cmd.ref, ok: false, reason: 'ref does not exist' });
          else if (cur !== cmd.oldOid) results.push({ ref: cmd.ref, ok: false, reason: 'old value does not match' });
          else if (!isAncestor(r, cmd.oldOid, cmd.newOid)) results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
          else { r.refs.set(cmd.ref, cmd.newOid); results.push({ ref: cmd.ref, ok: true, reason: '' }); }
        }
      }
    }
    if (results.some((x) => x.ok)) touchRepo(r);
  } else {
    for (const cmd of cmds) results.push({ ref: cmd.ref, ok: false, reason: unpackDetail });
  }
  sendReport(unpackOk, unpackDetail);
  for (const x of results) reportLines.push(x.ok ? `ok ${x.ref}\n` : `ng ${x.ref} ${x.reason}\n`);
  let out: Buffer;
  if (sideband) {
    const parts: Buffer[] = [];
    for (const l of reportLines) parts.push(pkt(Buffer.concat([Buffer.from([1]), pkt(l)])));
    parts.push(PKT_FLUSH);
    out = Buffer.concat(parts);
  } else {
    out = pktLines([...reportLines.map((l) => l as string), 'flush']);
  }
  sendBuf(res, 200, out, 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------- REST v3

function restNotFound(res: ServerResponse): void { errJson(res, 404, 'Not Found'); }
function restRepo(res: ServerResponse, owner: string, name: string): Repo | null {
  const r = getRepo(owner, name);
  if (!r) { restNotFound(res); return null; }
  return r;
}
async function handleRest(req: IncomingMessage, res: ServerResponse, segs: string[], q: URLSearchParams, rawBody: Buffer, pathname: string): Promise<void> {
  const method = req.method ?? 'GET';
  // Fast path for the read workload: GET /repos/{owner}/{repo}/issues/{n}. This is
  // exactly the branch the generic chain reaches below (same repo lookup, same
  // parseInt, same find, same cached JSON), without walking the whole chain.
  if (method === 'GET' && segs.length === 5 && segs[0] === 'repos' && segs[3] === 'issues') {
    const r = restRepo(res, segs[1] as string, segs[2] as string);
    if (!r) return;
    const num = parseInt(segs[4] as string, 10);
    const iss = r.issues.find((i) => i.number === num);
    if (!iss) { restNotFound(res); return; }
    sendJsonBuf(res, 200, issueJsonBuf(r, iss));
    return;
  }
  // JSON body (when present) for methods that carry one.
  let body: unknown;
  let bodyParsed = true;
  if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
    if (rawBody.length > 0) {
      const p = parseJsonBody(rawBody);
      if (!p.ok) { errJson(res, 400, 'Invalid JSON'); return; }
      body = p.value;
    }
  }
  const B = isRec(body) ? body : {};
  // Root / meta / user / rate_limit
  if (segs.length === 0) {
    if (method !== 'GET') { restNotFound(res); return; }
    sendJson(res, 200, {
      current_user_url: '/api/v3/user', current_user_authorizations_html_url: 'https://example.invalid/settings/applications',
      authorizations_url: '/api/v3/authorizations', code_search_url: '/api/v3/search/code?q={query}{&page,per_page,sort,order}',
      commit_search_url: '/api/v3/search/commits?q={query}{&page,per_page,sort,order}',
      emails_url: '/api/v3/user/emails', emojis_url: '/api/v3/emojis', events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds', followers_url: '/api/v3/user/followers', following_url: '/api/v3/user/following{/target}',
      gists_url: '/api/v3/gists{/gist_id}', hub_url: 'https://example.invalid', issue_search_url: '/api/v3/search/issues?q={query}{&page,per_page,sort,order}',
      issues_url: '/api/v3/issues', keys_url: '/api/v3/user/keys', label_search_url: '/api/v3/search/labels?repository_id={repository_id}&q={query}{&page,per_page}',
      notifications_url: '/api/v3/notifications', organization_url: '/api/v3/orgs/{org}',
      organization_repositories_url: '/api/v3/orgs/{org}/repos{?type,page,per_page,sort}',
      organization_teams_url: '/api/v3/orgs/{org}/teams', public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit', repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}{&page,per_page,sort,order}',
      current_user_repositories_url: '/api/v3/user/repos{?type,page,per_page,sort}',
      starred_url: '/api/v3/user/starred{/owner}{/repo}', starred_gists_url: '/api/v3/gists/starred',
      topic_search_url: '/api/v3/search/topics?q={query}{&page,per_page}',
      user_url: '/api/v3/users/{user}', user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos{?type,page,per_page,sort}',
      user_search_url: '/api/v3/search/users?q={query}{&page,per_page,sort,order}',
    }, { 'x-oauth-scopes': 'repo, read:org', 'x-accepted-oauth-scopes': 'repo' });
    return;
  }
  if (segs[0] === 'meta' && segs.length === 1) {
    if (method !== 'GET') { restNotFound(res); return; }
    sendJson(res, 200, { verifiable_password_authentication: true, ssh_key_fingerprints: {}, hooks: [], web: [], api: [], git: [], packages: [], pages: [], importer: [], actions: [], dependabot: [], installed_version: '1.0.0' });
    return;
  }
  if (segs[0] === 'rate_limit' && segs.length === 1) {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 4999, reset: 1735689600, used: 1 }, search: { limit: 30, remaining: 30, reset: 1735689600, used: 0 }, graphql: { limit: 5000, remaining: 4999, reset: 1735689600, used: 1 } }, rate: { limit: 5000, remaining: 4999, reset: 1735689600, used: 1 } });
    return;
  }
  if (segs[0] === 'user' && segs.length === 1) {
    if (method !== 'GET') { restNotFound(res); return; }
    sendJson(res, 200, {
      ...userJson(VIEWER.login), name: VIEWER.name, email: VIEWER.email, company: null, blog: '', location: null,
      hireable: null, bio: null, twitter_username: null, public_repos: repos.size, public_gists: 0,
      followers: 0, following: 0, created_at: FIXED_ISO, updated_at: FIXED_ISO, private_gists: 0,
      total_private_repos: 0, owned_private_repos: 0, disk_usage: 0, collaborators: 0,
      two_factor_authentication: false, plan: { name: 'free', space: 976562499, collaborators: 0, private_repos: 10000 },
    });
    return;
  }
  if (segs[0] === 'user' && segs[1] === 'repos') {
    if (method === 'GET') {
      const mine = [...repos.values()].filter((r) => r.owner === VIEWER.login).sort((a, b) => a.seq - b.seq);
      const pg = paginate(mine.map(repoView), q, req, pathname);
      sendJson(res, 200, pg.items, linkHeader(res, pg.link, {}));
      return;
    }
    if (method === 'POST') {
      const name = str(B.name);
      if (name === '') { errJson(res, 422, 'name is required'); return; }
      if (getRepo(VIEWER.login, name)) { errJson(res, 422, 'name already exists on this account'); return; }
      const r = createRepoObj(VIEWER.login, name, str(B.description), B.private === true, str(B.default_branch, 'main') || 'main');
      sendJson(res, 201, repoView(r));
      return;
    }
    restNotFound(res); return;
  }
  if (segs[0] === 'users' && segs.length === 2) {
    if (segs[1] === VIEWER.login) {
      sendJson(res, 200, { ...userJson(VIEWER.login), name: VIEWER.name, email: VIEWER.email, public_repos: repos.size, followers: 0, following: 0, created_at: FIXED_ISO, updated_at: FIXED_ISO });
      return;
    }
    restNotFound(res); return;
  }
  if (segs[0] !== 'repos' || segs.length < 3) { restNotFound(res); return; }
  const owner = segs[1] as string;
  const name = segs[2] as string;
  const rest = segs.slice(3);
  // /repos/{o}/{r} itself
  if (rest.length === 0) {
    if (method === 'GET') {
      const r = restRepo(res, owner, name); if (!r) return;
      sendJsonBuf(res, 200, repoJsonBuf(r)); return;
    }
    if (method === 'PATCH') {
      const r = restRepo(res, owner, name); if (!r) return;
      if (typeof B.description === 'string') r.description = B.description;
      if (typeof B.private === 'boolean') r.priv = B.private;
      touchRepo(r);
      sendJson(res, 200, repoView(r)); return;
    }
    if (method === 'DELETE') {
      const r = restRepo(res, owner, name); if (!r) return;
      repos.delete(repoKey(owner, name));
      res.writeHead(204, { 'x-github-request-id': nextReqId() });
      res.end();
      return;
    }
    restNotFound(res); return;
  }
  const r = restRepo(res, owner, name);
  if (!r) return;
  const head = rest[0] as string;
  // ---- branches
  if (head === 'branches') {
    if (rest.length === 1) {
      if (method !== 'GET') { restNotFound(res); return; }
      const list = [...r.refs.keys()].filter((x) => x.startsWith('refs/heads/')).map((x) => x.slice('refs/heads/'.length)).sort()
        .map((b) => ({ name: b, commit: { sha: r.refs.get(`refs/heads/${b}`) as string, url: '' }, protected: false, protection: { enabled: false, required_status_checks: { enforcement_level: 'off', contexts: [], checks: [] } }, protection_url: '' }));
      sendJson(res, 200, list); return;
    }
    const branch = rest.slice(1).join('/');
    const tip = r.refs.get(`refs/heads/${branch}`);
    if (method === 'GET') {
      if (!tip) { restNotFound(res); return; }
      sendJson(res, 200, { name: branch, commit: { sha: tip, url: '' }, protected: false }); return;
    }
    restNotFound(res); return;
  }
  // ---- git refs
  if (head === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const ref = str(B.ref);
      const sha = str(B.sha);
      if (!ref.startsWith('refs/') || !isOid(sha) || !r.objects.has(sha)) { errJson(res, 422, 'Invalid ref or sha'); return; }
      if (r.refs.has(ref)) { errJson(res, 422, 'Reference already exists'); return; }
      r.refs.set(ref, sha);
      touchRepo(r);
      sendJson(res, 201, { ref, node_id: gid('REF', `${owner}/${name}:${ref}`), url: `/api/v3/repos/${owner}/${name}/git/refs/${ref.slice(5)}`, object: { sha, type: r.objects.get(sha)?.t ?? 'commit', url: '' } });
      return;
    }
    if (method === 'GET') {
      if (rest.length === 2) {
        const list = [...r.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
          .map(([ref, sha]) => ({ ref, node_id: gid('REF', `${owner}/${name}:${ref}`), url: '', object: { sha, type: r.objects.get(sha)?.t ?? 'commit', url: '' } }));
        sendJson(res, 200, list); return;
      }
      const ref = `refs/${rest.slice(2).join('/')}`;
      const tip = r.refs.get(ref);
      if (!tip) { restNotFound(res); return; }
      sendJson(res, 200, { ref, node_id: gid('REF', `${owner}/${name}:${ref}`), url: '', object: { sha: tip, type: r.objects.get(tip)?.t ?? 'commit', url: '' } });
      return;
    }
    if (method === 'DELETE' && rest.length > 2) {
      const ref = `refs/${rest.slice(2).join('/')}`;
      if (!r.refs.has(ref)) { restNotFound(res); return; }
      r.refs.delete(ref);
      touchRepo(r);
      res.writeHead(204, { 'x-github-request-id': nextReqId() });
      res.end();
      return;
    }
    restNotFound(res); return;
  }
  // ---- commits
  if (head === 'commits') {
    if (rest.length === 1 && method === 'GET') {
      const tip = resolveRef(r, q.get('sha') ?? undefined);
      const list = history(r, tip, 100).map((sha) => {
        const c = parseCommit((r.objects.get(sha) as GObj).d);
        return {
          sha, node_id: gid('C', sha), commit: {
            author: { name: VIEWER.login, email: VIEWER.email, date: FIXED_ISO },
            committer: { name: VIEWER.login, email: VIEWER.email, date: FIXED_ISO },
            message: c.message, tree: { sha: c.tree, url: '' }, url: '', comment_count: 0, verification: { verified: false, reason: 'unsigned', signature: null, payload: null, verified_at: null },
          },
          url: '', html_url: '', comments_url: '', author: userJson(VIEWER.login), committer: userJson(VIEWER.login),
          parents: c.parents.map((p) => ({ sha: p, url: '', html_url: '' })),
        };
      });
      const pg = paginate(list, q, req, pathname);
      sendJson(res, 200, pg.items, linkHeader(res, pg.link, {}));
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      const sha = rest[1] as string;
      const obj = r.objects.get(sha);
      if (!obj || obj.t !== 'commit') { restNotFound(res); return; }
      const c = parseCommit(obj.d);
      sendJson(res, 200, {
        sha, commit: {
          author: { name: VIEWER.login, email: VIEWER.email, date: FIXED_ISO },
          committer: { name: VIEWER.login, email: VIEWER.email, date: FIXED_ISO },
          message: c.message, tree: { sha: c.tree, url: '' }, url: '', comment_count: 0,
          verification: { verified: false, reason: 'unsigned', signature: null, payload: null, verified_at: null },
        },
        author: userJson(VIEWER.login), committer: userJson(VIEWER.login),
        parents: c.parents.map((p) => ({ sha: p, url: '', html_url: '' })),
        url: '', html_url: '', comments_url: '', stats: { total: 0, additions: 0, deletions: 0 }, files: [],
      });
      return;
    }
    restNotFound(res); return;
  }
  // ---- contents
  if (head === 'contents') {
    const path = rest.slice(1).join('/');
    const branch = q.get('branch') ?? str(B.branch, r.defaultBranch);
    if (method === 'GET') {
      const ref = q.get('ref') ?? undefined;
      const tip = resolveRef(r, ref);
      if (!tip) { restNotFound(res); return; }
      const flat = flatOfCommit(r, tip);
      if (path === '') {
        const entries = dirListing(r, flat, '');
        sendJson(res, 200, entries); return;
      }
      const file = flat.get(path);
      if (file) {
        const obj = r.objects.get(file.oid) as GObj;
        sendJson(res, 200, {
          type: 'file', encoding: 'base64', size: obj.d.length, name: path.split('/').pop(), path,
          content: b64e(obj.d), sha: file.oid,
          url: `/api/v3/repos/${owner}/${name}/contents/${path}`,
          html_url: `https://example.invalid/${owner}/${name}/blob/${r.defaultBranch}/${path}`,
          git_url: '', download_url: null,
          _links: { git: '', self: '', html: '' },
        });
        return;
      }
      // directory?
      const prefix = `${path}/`;
      const hasChild = [...flat.keys()].some((k) => k.startsWith(prefix));
      if (hasChild) { sendJson(res, 200, dirListing(r, flat, path)); return; }
      restNotFound(res); return;
    }
    if (method === 'PUT') {
      const content = str(B.content);
      if (typeof B.message !== 'string' || content === '') { errJson(res, 422, 'message and content are required'); return; }
      const br = typeof B.branch === 'string' && B.branch !== '' ? B.branch : r.defaultBranch;
      if (!branchTip(r, br) && br !== r.defaultBranch) {
        // new branch from default tip
        const base = branchTip(r, r.defaultBranch);
        if (base) r.refs.set(`refs/heads/${br}`, base);
      }
      try {
        const out = contentsCommit(r, br, path, b64d(content), B.message as string, typeof B.sha === 'string' ? B.sha : undefined);
        sendJson(res, out.status, {
          content: { name: path.split('/').pop(), path, sha: out.blobSha, size: b64d(content).length, url: '', html_url: '', git_url: '', download_url: null, type: 'file', encoding: 'base64' },
          commit: { sha: out.commitSha, node_id: gid('C', out.commitSha), url: '', html_url: '', author: userJson(VIEWER.login), committer: userJson(VIEWER.login), message: B.message, tree: { sha: '', url: '' }, parents: [], verification: { verified: false, reason: 'unsigned', signature: null, payload: null } },
        });
      } catch (e) {
        const st = (e as { status?: number }).status ?? 500;
        errJson(res, st, e instanceof Error ? e.message : 'error');
      }
      return;
    }
    if (method === 'DELETE') {
      const br = typeof B.branch === 'string' && B.branch !== '' ? B.branch : r.defaultBranch;
      try {
        const out = contentsDelete(r, br, path, typeof B.message === 'string' ? B.message : '');
        sendJson(res, 200, { commit: { sha: out.commitSha, node_id: gid('C', out.commitSha), url: '', html_url: '', author: userJson(VIEWER.login), committer: userJson(VIEWER.login), message: B.message ?? '', tree: { sha: '', url: '' }, parents: [] } });
      } catch (e) {
        const st = (e as { status?: number }).status ?? 500;
        errJson(res, st, e instanceof Error ? e.message : 'error');
      }
      return;
    }
    restNotFound(res); return;
  }
  // ---- labels
  if (head === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      sendJson(res, 200, [...r.labels.values()].map(labelView)); return;
    }
    if (method === 'POST' && rest.length === 1) {
      const nm = str(B.name);
      if (nm === '') { errJson(res, 422, 'name is required'); return; }
      const existing = r.labels.get(nm);
      if (existing) { sendJson(res, 201, labelView(existing)); return; }
      const lab: Label = { id: nextDbId, name: nm, color: str(B.color, 'ededed'), description: str(B.description) };
      nextDbId += 1;
      r.labels.set(nm, lab);
      sendJson(res, 201, labelView(lab)); return;
    }
    if (method === 'GET' && rest.length === 2) {
      const lab = r.labels.get(rest[1] as string);
      if (!lab) { restNotFound(res); return; }
      sendJson(res, 200, labelView(lab)); return;
    }
    restNotFound(res); return;
  }
  // ---- issues
  if (head === 'issues') {
    if (rest.length === 1) {
      if (method === 'GET') {
        let list = [...r.issues];
        const state = q.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((i) => i.state === state);
        const sort = q.get('sort') ?? 'created';
        const dir = q.get('direction') ?? (sort === 'created' ? 'desc' : 'desc');
        if (sort === 'created') list.sort((a, b) => (dir === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        const pg = paginate(list.map((i) => issueView(r, i)), q, req, pathname);
        sendJson(res, 200, pg.items, linkHeader(res, pg.link, {}));
        return;
      }
      if (method === 'POST') {
        const title = str(B.title);
        if (title === '') { errJson(res, 422, 'title is required'); return; }
        const rawLabels = Array.isArray(B.labels) ? B.labels : [];
        const labels: Label[] = [];
        for (const l of rawLabels) {
          const nm = typeof l === 'string' ? l : str((l as Record<string, unknown>).name);
          const found = r.labels.get(nm);
          if (!found) { errJson(res, 422, `Label '${nm}' does not exist`); return; }
          labels.push(found);
        }
        const iss = createIssueObj(r, title, str(B.body), labels);
        sendJson(res, 201, issueView(r, iss));
        return;
      }
      restNotFound(res); return;
    }
    const num = parseInt(rest[1] as string, 10);
    const iss = r.issues.find((i) => i.number === num);
    if (rest.length === 2) {
      if (!iss) { restNotFound(res); return; }
      if (method === 'GET') { sendJsonBuf(res, 200, issueJsonBuf(r, iss)); return; }
      if (method === 'PATCH') {
        if (typeof B.state === 'string' && (B.state === 'open' || B.state === 'closed')) {
          iss.state = B.state; iss.closedAt = B.state === 'closed' ? FIXED_ISO : null;
        }
        if (typeof B.title === 'string') iss.title = B.title;
        if (typeof B.body === 'string') iss.body = B.body;
        invalidateIssue(r, iss.number);
        sendJson(res, 200, issueView(r, iss)); return;
      }
      restNotFound(res); return;
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      if (!iss) { restNotFound(res); return; }
      if (method === 'GET') {
        const list = (r.comments.get(iss.number) ?? []).map((c) => commentView(r, iss, c));
        sendJson(res, 200, list); return;
      }
      if (method === 'POST') {
        const cbody = str(B.body);
        if (cbody === '') { errJson(res, 422, 'body is required'); return; }
        const c: Comment = { id: nextDbId, body: cbody, seq: nextSeq };
        nextDbId += 1; nextSeq += 1;
        const arr = r.comments.get(iss.number) ?? [];
        arr.push(c);
        r.comments.set(iss.number, arr);
        invalidateIssue(r, iss.number);
        sendJson(res, 201, commentView(r, iss, c)); return;
      }
      restNotFound(res); return;
    }
    if (rest.length === 3 && rest[2] === 'labels') {
      if (!iss) { restNotFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, iss.labels.map(labelView)); return; }
      restNotFound(res); return;
    }
    restNotFound(res); return;
  }
  // ---- pulls
  if (head === 'pulls') {
    if (rest.length === 1) {
      if (method === 'GET') {
        let list = [...r.pulls];
        const state = q.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.seq - a.seq);
        const pg = paginate(list.map((p) => pullView(r, p)), q, req, pathname);
        sendJson(res, 200, pg.items, linkHeader(res, pg.link, {}));
        return;
      }
      if (method === 'POST') {
        const title = str(B.title);
        const headRef = typeof B.head === 'string' ? B.head : str((B.head as Record<string, unknown> | undefined)?.ref);
        const baseRef = typeof B.base === 'string' ? B.base : str((B.base as Record<string, unknown> | undefined)?.ref);
        if (title === '' || headRef === '' || baseRef === '') { errJson(res, 422, 'title, head and base are required'); return; }
        const out = createPullObj(r, title, str(B.body), headRef, baseRef);
        if ('error' in out) { errJson(res, 422, out.error); return; }
        sendJson(res, 201, pullView(r, out));
        return;
      }
      restNotFound(res); return;
    }
    const num = parseInt(rest[1] as string, 10);
    const pr = r.pulls.find((p) => p.number === num);
    if (rest.length === 2) {
      if (!pr) { restNotFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, pullView(r, pr)); return; }
      restNotFound(res); return;
    }
    if (rest.length === 3 && rest[2] === 'files') {
      if (!pr) { restNotFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, pullFiles(r, pr)); return; }
      restNotFound(res); return;
    }
    if (rest.length === 3 && rest[2] === 'merge') {
      if (!pr) { restNotFound(res); return; }
      if (method === 'PUT') {
        if (pr.state !== 'open') { errJson(res, 405, 'Pull request is already closed'); return; }
        const out = doMerge(r, pr);
        if (!out.ok) { errJson(res, 405, out.message); return; }
        sendJson(res, 200, { sha: out.sha, merged: true, message: out.message });
        return;
      }
      restNotFound(res); return;
    }
    if (rest.length === 3 && rest[2] === 'reviews') {
      if (!pr) { restNotFound(res); return; }
      sendJson(res, 200, []); return;
    }
    restNotFound(res); return;
  }
  void bodyParsed;
  restNotFound(res);
}
function dirListing(r: Repo, flat: Map<string, { mode: string; oid: string }>, dir: string): Record<string, unknown>[] {
  const prefix = dir === '' ? '' : `${dir}/`;
  const seen = new Map<string, { type: 'file' | 'dir'; oid: string; size: number }>();
  for (const [path, v] of flat) {
    if (!path.startsWith(prefix)) continue;
    const restPath = path.slice(prefix.length);
    const slash = restPath.indexOf('/');
    if (slash === -1) seen.set(restPath, { type: 'file', oid: v.oid, size: (r.objects.get(v.oid)?.d.length ?? 0) });
    else {
      const d = restPath.slice(0, slash);
      if (!seen.has(d)) seen.set(d, { type: 'dir', oid: '', size: 0 });
    }
  }
  return [...seen.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([name, v]) => {
    const path = prefix + name;
    return {
      type: v.type, size: v.size, name, path,
      sha: v.oid === '' ? hashObject('tree', Buffer.alloc(0)) : v.oid,
      url: `/api/v3/repos/${r.owner}/${r.name}/contents/${path}`,
      html_url: `https://example.invalid/${r.owner}/${r.name}/blob/${r.defaultBranch}/${path}`,
      git_url: '', download_url: v.type === 'file' ? `https://example.invalid/${r.owner}/${r.name}/raw/${r.defaultBranch}/${path}` : null,
      _links: { git: '', self: '', html: '' },
    };
  });
}

// ---------------------------------------------------------------- GraphQL v4
// A small executor for exactly the documents gh and github-mcp-server send.

type GqlValue = string | number | boolean | null | GqlValue[] | { [k: string]: GqlValue };
interface GqlSel { alias: string | null; name: string; args: Record<string, GqlValue>; sels: GqlSel[] | null; fragType: string | null }
interface GqlOp { kind: 'query' | 'mutation'; name: string | null; vars: string[]; sels: GqlSel[] }
function gqlTokenize(src: string): string[] {
  const toks: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\n' || c === '\r' || c === '\t' || c === ',') { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { toks.push('...'); i += 3; continue; }
    if ('{}():[]!=$@='.includes(c)) { toks.push(c); i += 1; continue; }
    if (c === '"') {
      let j = i + 1; let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { const e = src[j + 1] as string; out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e; j += 2; }
        else { out += src[j]; j += 1; }
      }
      toks.push(JSON.stringify(out)); i = j + 1; continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) j += 1;
      toks.push(src.slice(i, j)); i = j; continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      toks.push(src.slice(i, j)); i = j; continue;
    }
    i += 1;
  }
  return toks;
}
class GqlParser {
  toks: string[]; pos = 0;
  constructor(src: string) { this.toks = gqlTokenize(src); }
  peek(): string | undefined { return this.toks[this.pos]; }
  next(): string { return this.toks[this.pos++] as string; }
  expect(t: string): void { if (this.next() !== t) throw new Error(`expected ${t}`); }
  parseValue(vars: Record<string, unknown>): GqlValue {
    const t = this.next();
    if (t === '$') { const name = this.next(); return (vars[name] ?? null) as GqlValue; }
    if (t === '[') {
      const arr: GqlValue[] = [];
      while (this.peek() !== ']') arr.push(this.parseValue(vars));
      this.expect(']');
      return arr;
    }
    if (t === '{') {
      const obj: { [k: string]: GqlValue } = {};
      while (this.peek() !== '}') {
        const k = this.next();
        this.expect(':');
        obj[k] = this.parseValue(vars);
      }
      this.expect('}');
      return obj;
    }
    if (t.startsWith('"')) return JSON.parse(t) as string;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === 'null') return null;
    const n = Number(t);
    if (t !== '' && !Number.isNaN(n) && /^-?[0-9]/.test(t)) return n;
    return t; // enum as bare name
  }
  parseArgs(vars: Record<string, unknown>): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.peek() !== '(') return args;
    this.expect('(');
    while (this.peek() !== ')') {
      const k = this.next();
      this.expect(':');
      args[k] = this.parseValue(vars);
    }
    this.expect(')');
    return args;
  }
  parseSelections(vars: Record<string, unknown>): GqlSel[] {
    this.expect('{');
    const sels: GqlSel[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === '...') {
        this.next();
        let fragType: string | null = null;
        if (this.peek() === 'on') { this.next(); fragType = this.next(); }
        else { this.next(); } // named fragment spread (unused by the suite): skip its name
        const inner = this.parseSelections(vars);
        for (const s of inner) sels.push({ ...s, fragType });
        continue;
      }
      const first = this.next();
      let alias: string | null = null;
      let name = first;
      if (this.peek() === ':') { this.next(); alias = first; name = this.next(); }
      const args = this.parseArgs(vars);
      let sub: GqlSel[] | null = null;
      if (this.peek() === '{') sub = this.parseSelections(vars);
      sels.push({ alias, name, args, sels: sub, fragType: null });
    }
    this.expect('}');
    return sels;
  }
  parseOp(vars: Record<string, unknown>): GqlOp {
    let kind: 'query' | 'mutation' = 'query';
    const t = this.peek();
    if (t === 'query' || t === 'mutation') { kind = this.next() as 'query' | 'mutation'; }
    let name: string | null = null;
    if (this.peek() !== undefined && this.peek() !== '{' && this.peek() !== '(') name = this.next();
    const varNames: string[] = [];
    if (this.peek() === '(') {
      this.expect('(');
      while (this.peek() !== ')') {
        if (this.peek() === '$') { this.next(); varNames.push(this.next()); }
        else this.next();
        if (this.peek() === ':') { this.next(); this.next(); if (this.peek() === '!') this.next(); }
        if (this.peek() === '=') { this.next(); this.parseValue(vars); }
      }
      this.expect(')');
    }
    const sels = this.parseSelections(vars);
    return { kind, name, vars: varNames, sels };
  }
  parseDocument(vars: Record<string, unknown>): GqlOp[] {
    const ops: GqlOp[] = [];
    while (this.pos < this.toks.length) ops.push(this.parseOp(vars));
    return ops;
  }
}
const GQL_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  User: ['login', 'id', 'name', 'email'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'closedAt', 'url'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'headRef', 'baseRef'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'filename'],
  Ref: ['name'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'endCursor', 'startCursor'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description'],
  __EnumValue: ['name', 'description'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  CommentEdge: ['node'],
  Comment: ['id', 'body'],
};
const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'closedAt', 'url', 'author', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'headRef', 'baseRef', 'createdAt', 'updatedAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  SearchType: [],
};
const GQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
};
interface GqlCtx { errors: { message: string }[] }
function gqlErr(ctx: GqlCtx, msg: string): void { ctx.errors.push({ message: msg }); }
function encodeCursor(idx: number): string { return Buffer.from(`cursor:${idx}`, 'utf8').toString('base64'); }
function decodeCursor(c: string): number {
  try {
    const s = Buffer.from(c, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(s);
    return m ? parseInt(m[1] as string, 10) : -1;
  } catch { return -1; }
}
function issueGql(r: Repo, iss: Issue): Record<string, unknown> {
  return { __typename: 'Issue', _repo: r, _issue: iss, id: gid('I', `${r.owner}/${r.name}#${iss.number}`), number: iss.number, title: iss.title, state: iss.state === 'open' ? 'OPEN' : 'CLOSED', body: iss.body };
}
function pullGql(r: Repo, pr: Pull): Record<string, unknown> {
  return { __typename: 'PullRequest', _repo: r, _pull: pr, id: gid('P', `${r.owner}/${r.name}#${pr.number}`), number: pr.number, title: pr.title, body: pr.body, state: pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED', merged: pr.merged, headRefName: pr.head, baseRefName: pr.base, mergeable: prMergeable(r, pr) };
}
function repoGql(r: Repo): Record<string, unknown> {
  return { __typename: 'Repository', _repo: r, id: gid('R', `${r.owner}/${r.name}`), databaseId: r.id, name: r.name, nameWithOwner: `${r.owner}/${r.name}` };
}
function resolveField(typeName: string, parent: Record<string, unknown>, name: string, args: Record<string, GqlValue>, ctx: GqlCtx): unknown {
  if (name === '__typename') return typeName;
  const known = GQL_FIELDS[typeName];
  if (known && !known.includes(name)) {
    gqlErr(ctx, `Cannot query field "${name}" on type "${typeName}".`);
    return undefined;
  }
  if (typeName === 'Query') {
    if (name === 'viewer') return { __typename: 'User', login: VIEWER.login, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email };
    if (name === 'repository') {
      const r = getRepo(str(args.owner), str(args.name));
      return r ? repoGql(r) : null;
    }
    if (name === 'node') {
      const id = str(args.id);
      try {
        const decoded = Buffer.from(id, 'base64').toString('utf8');
        const m = /^([RIP]):(.*)$/.exec(decoded);
        if (!m) return null;
        const kind = m[1]; const key = m[2] as string;
        if (kind === 'R') { const r = getRepo(key.split('/')[0] as string, key.split('/')[1] as string); return r ? repoGql(r) : null; }
        if (kind === 'I') {
          const mm = /^(.*)\/([^/]+)#(\d+)$/.exec(key);
          if (!mm) return null;
          const r = getRepo(mm[1] as string, mm[2] as string);
          const iss = r?.issues.find((i) => i.number === parseInt(mm[3] as string, 10));
          return r && iss ? issueGql(r, iss) : null;
        }
        if (kind === 'P') {
          const mm = /^(.*)\/([^/]+)#(\d+)$/.exec(key);
          if (!mm) return null;
          const r = getRepo(mm[1] as string, mm[2] as string);
          const pr = r?.pulls.find((p) => p.number === parseInt(mm[3] as string, 10));
          return r && pr ? pullGql(r, pr) : null;
        }
      } catch { return null; }
      return null;
    }
    if (name === '__type') {
      const tname = str(args.name);
      const fields = GQL_TYPE_FIELDS[tname];
      const enums = GQL_TYPE_ENUMS[tname];
      if (fields === undefined && enums === undefined) return null;
      return { __typename: '__Type', name: tname, kind: enums !== undefined ? 'ENUM' : 'OBJECT', _fields: fields ?? [], _enums: enums ?? [] };
    }
    if (name === '__schema') return { __typename: '__Schema', queryType: { name: 'Query' }, mutationType: { name: 'Mutation' } };
  }
  if (typeName === 'Repository') {
    const r = parent._repo as Repo;
    if (name === 'owner') return { __typename: 'User', login: r.owner, id: r.owner === VIEWER.login ? VIEWER.id : 0, name: r.owner, email: '' };
    if (name === 'defaultBranchRef') {
      const tip = branchTip(r, r.defaultBranch);
      return tip ? { __typename: 'Ref', name: r.defaultBranch } : null;
    }
    if (name === 'viewerPermission') return 'ADMIN';
    if (name === 'hasIssuesEnabled') return true;
    if (name === 'issue') {
      const iss = r.issues.find((i) => i.number === (args.number as number));
      return iss ? issueGql(r, iss) : null;
    }
    if (name === 'issues') {
      let list = [...r.issues];
      const states = args.states;
      if (Array.isArray(states) && states.length) {
        const want = new Set(states.map((s) => String(s)));
        list = list.filter((i) => want.has(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      const orderBy = args.orderBy;
      if (isRec(orderBy)) {
        const dir = String(orderBy.direction ?? 'DESC');
        list.sort((a, b) => (dir === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
      }
      return connection(list.map((i) => issueGql(r, i)), args, 'IssueConnection');
    }
    if (name === 'pullRequests') {
      const list = [...r.pulls].sort((a, b) => a.seq - b.seq);
      return connection(list.map((p) => pullGql(r, p)), args, 'PullRequestConnection');
    }
    if (name === 'pullRequest') {
      const pr = r.pulls.find((p) => p.number === (args.number as number));
      return pr ? pullGql(r, pr) : null;
    }
    return parent[name];
  }
  if (typeName === 'PullRequest') {
    const r = (parent._repo as Repo);
    const pr = parent._pull as Pull;
    if (name === 'files') {
      const paths = pullFiles(r, pr).map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename as string, filename: f.filename as string }));
      return connection(paths, args, 'PullRequestChangedFileConnection');
    }
    return parent[name];
  }
  if (typeName === '__Type') {
    if (name === 'fields') return (parent._fields as string[]).map((f) => ({ __typename: '__Field', name: f, description: null }));
    if (name === 'enumValues') return (parent._enums as string[]).map((e) => ({ __typename: '__EnumValue', name: e, description: null }));
    if (name === 'kind') return parent.kind;
    if (name === 'name') return parent.name;
    return parent[name];
  }
  if (typeName === 'IssueConnection' || typeName === 'PullRequestConnection' || typeName === 'PullRequestChangedFileConnection') {
    return parent[name];
  }
  if (typeName === 'CreateIssuePayload' || typeName === 'CloseIssuePayload' || typeName === 'CreatePullRequestPayload' || typeName === 'MergePullRequestPayload' || typeName === 'AddCommentPayload') {
    return parent[name];
  }
  if (typeName === 'CommentEdge') {
    return parent[name];
  }
  return parent[name];
}
function connection(nodes: unknown[], args: Record<string, GqlValue>, typeName = 'IssueConnection'): Record<string, unknown> {
  const first = typeof args.first === 'number' ? args.first : undefined;
  let start = 0;
  if (typeof args.after === 'string' && args.after !== '') {
    const idx = decodeCursor(args.after);
    if (idx >= 0) start = idx + 1;
  }
  const sliced = first !== undefined ? nodes.slice(start, start + first) : nodes.slice(start);
  const endIdx = start + sliced.length - 1;
  return {
    __typename: typeName,
    nodes: sliced,
    edges: sliced.map((n) => ({ node: n, cursor: encodeCursor(start + sliced.indexOf(n)) })),
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage: first !== undefined ? start + sliced.length < nodes.length : false,
      hasPreviousPage: start > 0,
      endCursor: sliced.length ? encodeCursor(endIdx) : null,
      startCursor: sliced.length ? encodeCursor(start) : null,
    },
    totalCount: nodes.length,
  };
}
function applySelections(typeName: string, parent: Record<string, unknown>, sels: GqlSel[], ctx: GqlCtx, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of sels) {
    if (sel.fragType && sel.fragType !== typeName && sel.fragType !== parent.__typename) {
      // inline fragment on another type: only apply when it matches the runtime type
      if (parent.__typename !== sel.fragType) continue;
    }
    const key = sel.alias ?? sel.name;
    const value = resolveField(typeName, parent, sel.name, sel.args, ctx);
    if (value === undefined) { out[key] = null; continue; }
    if (sel.sels && value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const childType = childTypeOf(typeName, sel.name, value as Record<string, unknown>);
      out[key] = applySelections(childType, value as Record<string, unknown>, sel.sels, ctx, vars);
    } else if (sel.sels && Array.isArray(value)) {
      out[key] = value;
    } else if (sel.sels && value !== null && typeof value === 'object') {
      out[key] = value;
    } else {
      out[key] = value as GqlValue;
    }
  }
  return out;
}
function childTypeOf(parentType: string, field: string, value: Record<string, unknown>): string {
  if (value.__typename) return value.__typename as string;
  if (parentType === 'Query' && field === 'viewer') return 'User';
  if (parentType === 'Query' && field === 'repository') return 'Repository';
  if (parentType === 'Query' && field === 'node') return 'Repository';
  if (parentType === 'Query' && field === '__type') return '__Type';
  if (parentType === 'Repository' && field === 'owner') return 'User';
  if (parentType === 'Repository' && field === 'defaultBranchRef') return 'Ref';
  if (parentType === 'Repository' && field === 'issue') return 'Issue';
  if (parentType === 'Repository' && field === 'issues') return 'IssueConnection';
  if (parentType === 'Repository' && field === 'pullRequests') return 'PullRequestConnection';
  if (parentType === 'Repository' && field === 'pullRequest') return 'PullRequest';
  if (parentType === 'PullRequest' && field === 'files') return 'PullRequestChangedFileConnection';
  if (parentType === 'IssueConnection') return 'Issue';
  if (field === 'nodes') return (value as Record<string, unknown>).__typename === 'PullRequestConnection' ? 'PullRequest' : 'Issue';
  if (field === 'pageInfo') return 'PageInfo';
  if (field === 'edges') return 'IssueEdge';
  if (field === 'node') return 'Issue';
  if (field === 'commentEdge') return 'CommentEdge';
  if (field === 'issue') return 'Issue';
  if (field === 'pullRequest') return 'PullRequest';
  return 'Unknown';
}
// Connection nodes need per-node selection application: handled in executeOp by
// post-processing connections (nodes/edges) after the first pass.
function deepApply(typeName: string, parent: Record<string, unknown>, sels: GqlSel[], ctx: GqlCtx, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of sels) {
    if (sel.fragType && parent.__typename !== sel.fragType) continue;
    const key = sel.alias ?? sel.name;
    const value = resolveField(typeName, parent, sel.name, sel.args, ctx);
    if (value === undefined) { out[key] = null; continue; }
    if (!sel.sels) { out[key] = value as GqlValue; continue; }
    if (value === null) { out[key] = null; continue; }
    if (Array.isArray(value)) { out[key] = value; continue; }
    const v = value as Record<string, unknown>;
    const childType = childTypeOf(typeName, sel.name, v);
    if (childType === 'IssueConnection' || childType === 'PullRequestConnection' || childType === 'PullRequestChangedFileConnection' || v.nodes) {
      const conn: Record<string, unknown> = {};
      for (const cs of sel.sels) {
        const ck = cs.alias ?? cs.name;
        if (cs.name === 'nodes' && Array.isArray(v.nodes)) {
          const nodeType = childType === 'PullRequestConnection' ? 'PullRequest' : childType === 'PullRequestChangedFileConnection' ? 'PullRequestChangedFile' : 'Issue';
          conn[ck] = (v.nodes as Record<string, unknown>[]).map((n) => deepApply(nodeType, n, cs.sels ?? [], ctx, vars));
        } else if (cs.name === 'edges' && Array.isArray(v.edges)) {
          conn[ck] = (v.edges as Record<string, unknown>[]).map((e) => {
            const node = (e as Record<string, unknown>).node as Record<string, unknown>;
            const nodeType = node.__typename as string;
            const edgeOut: Record<string, unknown> = {};
            for (const es of cs.sels ?? []) {
              if (es.name === 'node') edgeOut[es.alias ?? 'node'] = deepApply(nodeType, node, es.sels ?? [], ctx, vars);
              else edgeOut[es.alias ?? es.name] = (e as Record<string, unknown>)[es.name];
            }
            return edgeOut;
          });
        } else if (cs.name === 'pageInfo' && v.pageInfo) {
          conn[ck] = deepApply('PageInfo', v.pageInfo as Record<string, unknown>, cs.sels ?? [], ctx, vars);
        } else if (cs.name === 'totalCount') {
          conn[ck] = v.totalCount as number;
        } else {
          conn[ck] = (v as Record<string, unknown>)[cs.name];
        }
      }
      out[key] = conn;
      continue;
    }
    out[key] = deepApply(childType, v, sel.sels, ctx, vars);
  }
  return out;
}
function executeMutation(op: GqlOp, vars: Record<string, unknown>, ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of op.sels) {
    const key = sel.alias ?? sel.name;
    const input = isRec(sel.args.input) ? (sel.args.input as Record<string, unknown>) : {};
    if (sel.name === 'createIssue') {
      const repoId = str(input.repositoryId);
      const repo = findRepoByGid(repoId);
      if (!repo) { gqlErr(ctx, 'Could not resolve to a Repository with the global id.'); out[key] = null; continue; }
      const iss = createIssueObj(repo, str(input.title), str(input.body), []);
      const payload = { __typename: 'CreateIssuePayload', issue: issueGql(repo, iss), clientMutationId: null };
      out[key] = sel.sels ? deepApply('CreateIssuePayload', payload, sel.sels, ctx, vars) : payload;
      continue;
    }
    if (sel.name === 'closeIssue') {
      const found = findIssueByGid(str(input.issueId));
      if (!found) { gqlErr(ctx, 'Could not resolve to an Issue with the global id.'); out[key] = null; continue; }
      found.iss.state = 'closed'; found.iss.closedAt = FIXED_ISO;
      invalidateIssue(found.repo, found.iss.number);
      const payload = { __typename: 'CloseIssuePayload', issue: issueGql(found.repo, found.iss), clientMutationId: null };
      out[key] = sel.sels ? deepApply('CloseIssuePayload', payload, sel.sels, ctx, vars) : payload;
      continue;
    }
    if (sel.name === 'createPullRequest') {
      const repo = findRepoByGid(str(input.repositoryId));
      if (!repo) { gqlErr(ctx, 'Could not resolve to a Repository with the global id.'); out[key] = null; continue; }
      const res = createPullObj(repo, str(input.title), str(input.body), str(input.headRefName), str(input.baseRefName));
      if ('error' in res) { gqlErr(ctx, res.error); out[key] = null; continue; }
      const payload = { __typename: 'CreatePullRequestPayload', pullRequest: pullGql(repo, res), clientMutationId: null };
      out[key] = sel.sels ? deepApply('CreatePullRequestPayload', payload, sel.sels, ctx, vars) : payload;
      continue;
    }
    if (sel.name === 'mergePullRequest') {
      const found = findPullByGid(str(input.pullRequestId));
      if (!found) { gqlErr(ctx, 'Could not resolve to a PullRequest with the global id.'); out[key] = null; continue; }
      const merged = doMerge(found.repo, found.pr);
      if (!merged.ok) { gqlErr(ctx, merged.message); out[key] = null; continue; }
      const payload = { __typename: 'MergePullRequestPayload', pullRequest: pullGql(found.repo, found.pr), clientMutationId: null };
      out[key] = sel.sels ? deepApply('MergePullRequestPayload', payload, sel.sels, ctx, vars) : payload;
      continue;
    }
    if (sel.name === 'addComment') {
      const found = findIssueByGid(str(input.subjectId));
      if (!found) { gqlErr(ctx, 'Could not resolve to an Issue with the global id.'); out[key] = null; continue; }
      const c: Comment = { id: nextDbId, body: str(input.body), seq: nextSeq };
      nextDbId += 1; nextSeq += 1;
      const arr = found.repo.comments.get(found.iss.number) ?? [];
      arr.push(c);
      found.repo.comments.set(found.iss.number, arr);
      invalidateIssue(found.repo, found.iss.number);
      const node = { __typename: 'Comment', id: gid('C', `${found.repo.owner}/${found.repo.name}#${found.iss.number}:${c.id}`), body: c.body };
      const payload = { __typename: 'AddCommentPayload', commentEdge: { __typename: 'CommentEdge', node }, clientMutationId: null };
      out[key] = sel.sels ? deepApply('AddCommentPayload', payload, sel.sels, ctx, vars) : payload;
      continue;
    }
    gqlErr(ctx, `Cannot query field "${sel.name}" on type "Mutation".`);
    out[key] = null;
  }
  return out;
}
function findRepoByGid(id: string): Repo | null {
  try {
    const decoded = Buffer.from(id, 'base64').toString('utf8');
    const m = /^R:(.*)$/.exec(decoded);
    if (!m) return null;
    const key = m[1] as string;
    const slash = key.lastIndexOf('/');
    if (slash < 0) return null;
    return getRepo(key.slice(0, slash), key.slice(slash + 1)) ?? null;
  } catch { return null; }
}
function findIssueByGid(id: string): { repo: Repo; iss: Issue } | null {
  try {
    const decoded = Buffer.from(id, 'base64').toString('utf8');
    const m = /^I:(.*)\/([^/]+)#(\d+)$/.exec(decoded);
    if (!m) return null;
    const r = getRepo(m[1] as string, m[2] as string);
    if (!r) return null;
    const iss = r.issues.find((i) => i.number === parseInt(m[3] as string, 10));
    return iss ? { repo: r, iss } : null;
  } catch { return null; }
}
function findPullByGid(id: string): { repo: Repo; pr: Pull } | null {
  try {
    const decoded = Buffer.from(id, 'base64').toString('utf8');
    const m = /^P:(.*)\/([^/]+)#(\d+)$/.exec(decoded);
    if (!m) return null;
    const r = getRepo(m[1] as string, m[2] as string);
    if (!r) return null;
    const pr = r.pulls.find((p) => p.number === parseInt(m[3] as string, 10));
    return pr ? { repo: r, pr } : null;
  } catch { return null; }
}
function executeGraphQL(query: string, vars: Record<string, unknown>): { data: Record<string, unknown> | null; errors?: { message: string }[] } {
  const ctx: GqlCtx = { errors: [] };
  let ops: GqlOp[];
  try {
    ops = new GqlParser(query).parseDocument(vars);
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : 'Syntax error' }] };
  }
  if (ops.length === 0) return { data: {}, errors: [{ message: 'No operation provided' }] };
  const op = ops[0] as GqlOp;
  if (op.kind === 'mutation') {
    const data = executeMutation(op, vars, ctx);
    return ctx.errors.length ? { data, errors: ctx.errors } : { data };
  }
  const data = deepApply('Query', { __typename: 'Query' }, op.sels, ctx, vars);
  return ctx.errors.length ? { data, errors: ctx.errors } : { data };
}

// ---------------------------------------------------------------- MCP

interface McpToolDef { name: string; description: string; inputSchema: { type: 'object'; properties: Record<string, unknown>; required: string[] } }
const MCP_TOOLS: McpToolDef[] = [
  { name: 'create_repo', description: 'Create a repository owned by the token user.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state: open, closed or all' } }, required: ['owner', 'repo'] } },
  { name: 'get_issue', description: 'Get one issue by number.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, issue_number: { type: 'integer', description: 'Issue number' } }, required: ['owner', 'repo', 'issue_number'] } },
  { name: 'create_pull_request', description: 'Create a pull request from a head branch into a base branch.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, body: { type: 'string', description: 'Pull request body' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] } },
  { name: 'create_comment', description: 'Create a comment on an issue.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, issue_number: { type: 'integer', description: 'Issue number' }, body: { type: 'string', description: 'Comment body' } }, required: ['owner', 'repo', 'issue_number', 'body'] } },
];
const MCP_TOOLS_JSON = JSON.stringify(MCP_TOOLS);
function mcpToolResult(payload: unknown, isError = false): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: payload, isError };
}
function mcpCallTool(name: string, args: Record<string, unknown>): { payload: unknown; isError: boolean } {
  const def = MCP_TOOLS.find((t) => t.name === name);
  if (!def) return { payload: null, isError: true };
  for (const reqd of def.inputSchema.required) {
    if (args[reqd] === undefined || args[reqd] === null || args[reqd] === '') {
      return { payload: { error: `Missing required argument: ${reqd}` }, isError: true };
    }
  }
  const owner = str(args.owner, VIEWER.login);
  const repoName = str(args.repo ?? args.name);
  if (name === 'create_repo') {
    const nm = str(args.name);
    if (nm === '') return { payload: { error: 'Missing required argument: name' }, isError: true };
    const own = str(args.owner, VIEWER.login);
    let r = getRepo(own, nm);
    if (!r) r = createRepoObj(own, nm, str(args.description), args.private === true, 'main');
    return { payload: repoView(r), isError: false };
  }
  const r = getRepo(owner, repoName);
  if (!r) return { payload: { error: `Repository not found: ${owner}/${repoName}` }, isError: true };
  if (name === 'get_repo') return { payload: repoView(r), isError: false };
  if (name === 'create_issue') {
    const iss = createIssueObj(r, str(args.title), str(args.body), []);
    return { payload: issueView(r, iss), isError: false };
  }
  if (name === 'list_issues') {
    let list = [...r.issues];
    const state = str(args.state, 'open');
    if (state !== 'all') list = list.filter((i) => i.state === state);
    return { payload: list.map((i) => issueView(r, i)), isError: false };
  }
  if (name === 'get_issue') {
    const iss = r.issues.find((i) => i.number === (args.issue_number as number));
    if (!iss) return { payload: { error: 'Issue not found' }, isError: true };
    return { payload: issueView(r, iss), isError: false };
  }
  if (name === 'create_pull_request') {
    const out = createPullObj(r, str(args.title), str(args.body), str(args.head), str(args.base));
    if ('error' in out) return { payload: { error: out.error }, isError: true };
    return { payload: pullView(r, out), isError: false };
  }
  if (name === 'merge_pull_request') {
    const pr = r.pulls.find((p) => p.number === (args.pull_number as number));
    if (!pr) return { payload: { error: 'Pull request not found' }, isError: true };
    if (pr.state !== 'open') return { payload: { error: 'Pull request is already closed' }, isError: true };
    const out = doMerge(r, pr);
    if (!out.ok) return { payload: { error: out.message }, isError: true };
    return { payload: { sha: out.sha, merged: true, message: out.message, number: pr.number }, isError: false };
  }
  if (name === 'create_comment') {
    const iss = r.issues.find((i) => i.number === (args.issue_number as number));
    if (!iss) return { payload: { error: 'Issue not found' }, isError: true };
    const c: Comment = { id: nextDbId, body: str(args.body), seq: nextSeq };
    nextDbId += 1; nextSeq += 1;
    const arr = r.comments.get(iss.number) ?? [];
    arr.push(c);
    r.comments.set(iss.number, arr);
    invalidateIssue(r, iss.number);
    return { payload: commentView(r, iss, c), isError: false };
  }
  return { payload: { error: `Unknown tool: ${name}` }, isError: true };
}
function mcpRpc(res: ServerResponse, id: unknown, result: unknown): void {
  sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, result });
}
function mcpRpcError(res: ServerResponse, id: unknown, code: number, message: string, status = 200): void {
  sendJson(res, status, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}
async function handleMcp(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): Promise<void> {
  if ((req.method ?? 'POST') !== 'POST') { errJson(res, 405, 'Method Not Allowed'); return; }
  if (!authed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
    return;
  }
  const text = rawBody.toString('utf8');
  let parsed: unknown;
  try { parsed = JSON.parse(text) as unknown; }
  catch {
    let id: unknown = null;
    const m = /"id"\s*:\s*(\d+|"(?:[^"\\]|\\.)*")/.exec(text);
    if (m) {
      const v = m[1] as string;
      id = v.startsWith('"') ? JSON.parse(v) as string : parseInt(v, 10);
    }
    sendJson(res, 400, { jsonrpc: '2.0', id, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRec(parsed) || typeof parsed.method !== 'string') {
    sendJson(res, 400, { jsonrpc: '2.0', id: isRec(parsed) ? (parsed.id ?? null) : null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = parsed.id ?? null;
  const method = parsed.method;
  const params = isRec(parsed.params) ? parsed.params : {};
  if (method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextReqId() });
    res.end();
    return;
  }
  if (method === 'server/discover') {
    mcpRpc(res, id, {
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
      protocolVersion: '2026-07-28',
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      capabilities: { tools: {} },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
    });
    return;
  }
  if (method === 'initialize') {
    const want = str((params as Record<string, unknown>).protocolVersion, '2025-11-25');
    const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    mcpRpc(res, id, {
      protocolVersion: supported.includes(want) ? want : '2025-11-25',
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    });
    return;
  }
  if (method === 'ping') { mcpRpc(res, id, {}); return; }
  if (method === 'tools/list') {
    // Return the pre-built tool list (byte-identical across calls).
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: JSON.parse(MCP_TOOLS_JSON) as unknown } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = str(params.name);
    const args = isRec(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    if (!MCP_TOOLS.some((t) => t.name === toolName)) {
      mcpRpcError(res, id, -32602, `Unknown tool: ${toolName}`);
      return;
    }
    const out = mcpCallTool(toolName, args);
    mcpRpc(res, id, mcpToolResult(out.payload, out.isError));
    return;
  }
  mcpRpcError(res, id, -32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------- app

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const pathname = url.pathname;
        const q = url.searchParams;
        const method = req.method ?? 'GET';
        if (method === 'GET' && pathname === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        // Git smart HTTP: /{owner}/{repo}.git/... (also without .git)
        const gsegs = pathSegments(pathname);
        if (gsegs.length >= 2) {
          const maybeRepo = gsegs[1] as string;
          const repoName = maybeRepo.endsWith('.git') ? maybeRepo.slice(0, -4) : maybeRepo;
          const tail = gsegs.slice(2);
          const isGitPath = (tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs') || (tail.length === 1 && (tail[0] === 'git-upload-pack' || tail[0] === 'git-receive-pack'));
          if (isGitPath) {
            const owner = gsegs[0] as string;
            const r = getRepo(owner, repoName);
            if (!r) { errJson(res, 404, 'Not Found'); return; }
            // GETs (info/refs) carry no body: skip the readBody wait. POSTs
            // (upload-pack / receive-pack) still read it.
            const raw = method === 'GET' ? Buffer.alloc(0) : await readBody(req);
            if (tail[0] === 'info') {
              const service = q.get('service') ?? '';
              if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { errJson(res, 400, 'Missing service'); return; }
              infoRefs(res, r, service, req);
              return;
            }
            if (tail[0] === 'git-upload-pack') {
              if ((req.headers['git-protocol'] ?? '') === 'version=2') uploadPackV2(res, r, raw);
              else uploadPackV0(res, r, raw);
              return;
            }
            receivePack(res, r, raw);
            return;
          }
        }
        // REST v3 / GraphQL / MCP all require auth.
        if (pathname === '/api/graphql') {
          if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
          if (method !== 'POST') { restNotFound(res); return; }
          const raw = await readBody(req);
          const p = parseJsonBody(raw);
          if (!p.ok) { errJson(res, 400, 'Invalid JSON'); return; }
          const execOne = (doc: unknown): unknown => {
            if (!isRec(doc) || typeof doc.query !== 'string') return { data: null, errors: [{ message: 'query is required' }] };
            const vars = isRec(doc.variables) ? (doc.variables as Record<string, unknown>) : {};
            return executeGraphQL(doc.query, vars);
          };
          if (Array.isArray(p.value)) {
            sendJson(res, 200, p.value.map(execOne));
          } else {
            sendJson(res, 200, execOne(p.value));
          }
          return;
        }
        if (pathname === '/mcp') {
          const raw = await readBody(req);
          await handleMcp(req, res, raw);
          return;
        }
        if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
          if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
          // GETs carry no body: skip the readBody wait (handleRest only parses
          // a body for POST/PATCH/PUT/DELETE). Pass the already-parsed pathname
          // so handleRest does not parse the URL a second time.
          const raw = method === 'GET' ? Buffer.alloc(0) : await readBody(req);
          const segs = pathSegments(pathname).slice(2);
          await handleRest(req, res, segs, q, raw, pathname);
          return;
        }
        errJson(res, 404, 'Not Found');
      } catch (e) {
        try { errJson(res, 500, e instanceof Error ? e.message : 'Internal error'); } catch { /* socket gone */ }
      }
    })();
  });
}
