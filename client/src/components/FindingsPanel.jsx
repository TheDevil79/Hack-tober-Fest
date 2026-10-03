import { ChevronDown, ChevronUp, CircleCheck, CircleX, ExternalLink, Sparkles } from 'lucide-react';
import { isResolved, severityOrder } from '../utils';

function Remediation({ finding }) {
  const remediation = finding.remediation;
  if (!remediation) {
    return (
      <div className="remediation unavailable">
        <Sparkles size={18} />
        <div>
          <strong>AI guidance unavailable</strong>
          <p>{finding.aiError || 'Configure Gemini to generate grounded remediation guidance.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="remediation">
      <div className="remediation-title"><Sparkles size={17} /><span>Grounded remediation</span></div>
      <div className="remediation-grid">
        <section><h4>What this means</h4><p>{remediation.explanation}</p></section>
        <section><h4>Why it matters</h4><p>{remediation.whyItMatters}</p></section>
        <section className="wide"><h4>Recommended fix</h4><p>{remediation.remediation}</p></section>
        <section className="wide code-guidance"><h4>Implementation</h4><p>{remediation.implementation}</p></section>
        {remediation.verification?.length > 0 && (
          <section className="wide">
            <h4>Verify the improvement</h4>
            <ol>{remediation.verification.map(item => <li key={item}>{item}</li>)}</ol>
          </section>
        )}
      </div>
      <div className="remediation-foot">
        <span>Confidence: {remediation.confidence || 'not stated'}</span>
        {remediation.limitations && <span>{remediation.limitations}</span>}
      </div>
      {remediation.sources?.length > 0 && (
        <div className="sources">
          {remediation.sources.map(source => (
            <a key={`${source.title}-${source.source}`} href={source.source} target="_blank" rel="noreferrer">
              {source.title}<ExternalLink size={12} />
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

export default function FindingsPanel({ findings = [], selectedId, onSelect }) {
  const sorted = [...findings].sort((a, b) => {
    if (isResolved(a) !== isResolved(b)) return isResolved(a) ? 1 : -1;
    return (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
  });

  if (sorted.length === 0) {
    return <div className="empty-state"><CircleCheck size={30} /><h3>No findings returned</h3><p>No issues were detected by the checks performed.</p></div>;
  }

  return (
    <div className="finding-list">
      {sorted.map(finding => {
        const open = selectedId === finding.id;
        const resolved = isResolved(finding);
        return (
          <article className={`finding ${open ? 'open' : ''}`} key={`${finding.id}-${finding.name}`}>
            <button className="finding-summary" onClick={() => onSelect(open ? null : finding.id)} aria-expanded={open}>
              <span className={`finding-state ${resolved ? 'resolved' : ''}`}>
                {resolved ? <CircleCheck size={18} /> : <CircleX size={18} />}
              </span>
              <span className="finding-copy">
                <span className="finding-name">{finding.name}</span>
                <span className="finding-evidence">{finding.evidence || 'No additional evidence recorded.'}</span>
              </span>
              <span className={`severity ${finding.severity || 'info'}`}>{finding.severity || 'info'}</span>
              <span className="status-pill">{finding.status || 'observed'}</span>
              {open ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
            </button>
            {open && <Remediation finding={finding} />}
          </article>
        );
      })}
    </div>
  );
}
