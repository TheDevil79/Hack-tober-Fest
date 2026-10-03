export const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function isResolved(finding) {
  return ['present', 'fixed', 'pass', 'secure', 'valid'].includes(String(finding?.status || '').toLowerCase());
}

export function activeFindings(findings = []) {
  return findings.filter(finding => !isResolved(finding));
}

export function securityScore(findings = []) {
  const weights = { critical: 24, high: 15, medium: 8, low: 3, info: 1 };
  const deduction = activeFindings(findings).reduce(
    (total, finding) => total + (weights[String(finding.severity).toLowerCase()] || 3),
    0
  );
  return Math.max(0, 100 - deduction);
}

export function formatDate(value) {
  if (!value) return 'Just now';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString();
}

export function downloadReport(scan) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = `patchlens-${scan.scanId || 'report'}.json`;
  anchor.click();
  URL.revokeObjectURL(href);
}
