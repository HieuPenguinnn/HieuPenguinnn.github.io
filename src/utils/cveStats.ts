import vulncheck from '../data/vulncheck-cve.json';

type VcEntry = { cves: string[]; severity: string };

// Total published CVE IDs tracked in the VulnCheck list (one entry may carry several IDs).
export const VULNCHECK_CVE_IDS = (vulncheck as VcEntry[]).reduce(
  (n, e) => n + e.cves.length,
  0,
);

export const VULNCHECK_CRITICAL = (vulncheck as VcEntry[]).filter(
  (e) => e.severity === 'critical',
).length;

// Grand total of published CVEs = VulnCheck IDs + the Patchstack write-ups (1 CVE each).
export function totalCveCount(patchstackPublished: number): number {
  return VULNCHECK_CVE_IDS + patchstackPublished;
}
