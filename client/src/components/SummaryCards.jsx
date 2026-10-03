import { AlertTriangle, CheckCircle2, Database, ShieldCheck } from 'lucide-react';
import { activeFindings, securityScore } from '../utils';

export default function SummaryCards({ scan }) {
  const findings = scan.findings || [];
  const active = activeFindings(findings);
  const high = active.filter(item => ['critical', 'high'].includes(String(item.severity).toLowerCase())).length;
  const score = securityScore(findings);

  return (
    <div className="summary-grid">
      <article className="metric score-card">
        <span className="metric-icon"><ShieldCheck size={20} /></span>
        <div><strong>{score}</strong><span>Assessment score</span></div>
        <small>Based on checks performed</small>
      </article>
      <article className="metric">
        <span className="metric-icon amber"><AlertTriangle size={20} /></span>
        <div><strong>{active.length}</strong><span>Open findings</span></div>
        <small>{high} high-priority</small>
      </article>
      <article className="metric">
        <span className="metric-icon blue"><CheckCircle2 size={20} /></span>
        <div><strong>{findings.length - active.length}</strong><span>Checks passing</span></div>
        <small>{findings.length} total observations</small>
      </article>
      <article className="metric">
        <span className="metric-icon violet"><Database size={20} /></span>
        <div><strong>{scan.persistence?.storage === 'mongodb' ? 'Cloud' : 'Local'}</strong><span>Scan storage</span></div>
        <small>{scan.persistence?.available ? 'Persistent history' : 'Until server restart'}</small>
      </article>
    </div>
  );
}
