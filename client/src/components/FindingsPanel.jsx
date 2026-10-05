import { useState } from 'react';
import {
  BookOpen, Check, ChevronDown, ChevronUp, CircleCheck, CircleX,
  Copy, ExternalLink, Eye, ListChecks, ShieldAlert, Sparkles, Wrench
} from 'lucide-react';
import { isResolved, severityOrder } from '../utils';

function Remediation({ finding }) {
  const remediation = finding.remediation;
  const [copied, setCopied] = useState(false);

  const copyImplementation = async () => {
    await navigator.clipboard.writeText(remediation.implementation || remediation.remediation || '');
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

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
      <header className="fix-plan-header">
        <span className="fix-plan-icon"><Sparkles size={20} /></span>
        <div>
          <span className="eyebrow">Remediation brief</span>
          <h3>Resolve {finding.name}</h3>
          <p>Prepared from the scanner evidence and trusted security guidance.</p>
        </div>
        <span className={`confidence-badge ${remediation.confidence || 'unknown'}`}>
          {remediation.confidence || 'Unknown'} confidence
        </span>
      </header>

      <div className="fix-flow" aria-label="Remediation workflow">
        <span><b>1</b> Understand</span><i />
        <span><b>2</b> Apply the fix</span><i />
        <span><b>3</b> Verify</span>
      </div>

      <div className="insight-grid">
        <section className="insight-card">
          <span className="insight-icon blue"><Eye size={18} /></span>
          <div><h4>What was detected</h4><p>{remediation.explanation}</p></div>
        </section>
        <section className="insight-card risk">
          <span className="insight-icon amber"><ShieldAlert size={18} /></span>
          <div><h4>Why you should care</h4><p>{remediation.whyItMatters}</p></div>
        </section>
      </div>

      <section className="recommended-action">
        <span className="action-number">01</span>
        <div><h4>Recommended action</h4><p>{remediation.remediation}</p></div>
      </section>

      <section className="implementation-card">
        <header>
          <div><Wrench size={17} /><span>How to implement it</span></div>
          <button onClick={copyImplementation} type="button">
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy instructions'}
          </button>
        </header>
        <p>{remediation.implementation}</p>
      </section>

      {remediation.verification?.length > 0 && (
        <section className="verification-section">
          <header><ListChecks size={18} /><div><h4>Verify the improvement</h4><p>Complete these checks after applying the fix.</p></div></header>
          <div className="verification-steps">
            {remediation.verification.map((item, index) => (
              <div key={item}><span>{index + 1}</span><p>{item}</p></div>
            ))}
          </div>
        </section>
      )}

      <div className="guidance-meta">
        {remediation.limitations && (
          <div className="limitations"><ShieldAlert size={15} /><div><strong>Keep in mind</strong><p>{remediation.limitations}</p></div></div>
        )}
        {remediation.sources?.length > 0 && (
          <div className="sources">
            <span><BookOpen size={14} /> Knowledge used</span>
            <div>
              {remediation.sources.map(source => {
                const isLink = /^https?:\/\//i.test(source.source || '');
                return isLink ? (
                  <a key={`${source.title}-${source.source}`} href={source.source} target="_blank" rel="noreferrer">
                    {source.title}<ExternalLink size={11} />
                  </a>
                ) : <span className="source-chip" key={`${source.title}-${source.source}`}>{source.title}</span>;
              })}
            </div>
          </div>
        )}
      </div>
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
