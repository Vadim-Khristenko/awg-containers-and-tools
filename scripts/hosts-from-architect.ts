// Writes the host database the mimicry profiles draw from, out of Any Tech
// ARCHITECT's own `src/shared/domains.ts`, so the two tools name the same
// hosts for the same reasons and a fact established by Architect's probe is
// not copied by hand.
//
// usage: bun scripts/hosts-from-architect.ts <path to amneziawg-architect>
//
// The output is crates/awg-core/src/mimic/hosts.tsv: one host per line, its
// facts kept as yes / no / unknown rather than resolved into roles here, so
// the role rules live in one place (crates/awg-core/src/mimic/hostdb.rs) and
// `allow unknown` can still widen a query at run time.
import { resolve } from "node:path";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: bun scripts/hosts-from-architect.ts <architect dir>");
  process.exit(2);
}

type Fact = "yes" | "no" | "unknown" | undefined;
interface DomainRecord {
  host: string;
  regions: readonly string[];
  tls13: Fact;
  h2: Fact;
  h3: Fact;
  serves: Fact;
  cdn: string;
  dnsAnswers?: readonly string[];
  services?: Partial<Record<"dtls" | "sip" | "stun" | "dns", Fact>> & {
    dnsTypes?: readonly string[];
  };
  whitelistedIn?: readonly string[];
  checked?: string;
}

const { DOMAINS } = (await import(resolve(dir, "src/shared/domains.ts"))) as {
  DOMAINS: readonly DomainRecord[];
};

const git = Bun.spawnSync(["git", "-C", dir, "describe", "--tags", "--always", "--dirty"]);
const rev = git.stdout.toString().trim() || "unknown";

const fact = (f: Fact) => (f === "yes" ? "y" : f === "no" ? "n" : "?");
const list = (xs: readonly string[] | undefined) => (xs?.length ? xs.join(",") : "-");

const out: string[] = [
  `# Generated from Any Tech ARCHITECT ${rev}, src/shared/domains.ts,`,
  "# by scripts/hosts-from-architect.ts. Do not edit: rerun the script.",
  "#",
  "# facts: tls13 h2 h3 serves dtls sip stun dns, each y (yes), n (no) or ? (unknown)",
  "# host\tregions\tfacts\tcdn\tdns_answers\tresolver_types\twhitelisted_in",
];

for (const d of DOMAINS) {
  const s = d.services ?? {};
  const facts = [d.tls13, d.h2, d.h3, d.serves, s.dtls, s.sip, s.stun, s.dns].map(fact).join("");
  out.push(
    [d.host, list(d.regions), facts, d.cdn, list(d.dnsAnswers), list(s.dnsTypes), list(d.whitelistedIn)].join("\t"),
  );
}

const target = resolve(import.meta.dir, "../crates/awg-core/src/mimic/hosts.tsv");
await Bun.write(target, out.join("\n") + "\n");
console.log(`${DOMAINS.length} hosts from ${rev} -> ${target}`);
