import { Check, CircleDashed, LoaderCircle } from 'lucide-react';

const steps = ['Validate target', 'Inspect transport', 'Analyze response', 'Enrich findings'];

export default function ScanProgress({ step }) {
  return (
    <section className="progress-card" aria-live="polite">
      <div className="progress-head">
        <div>
          <span className="eyebrow"><LoaderCircle className="spin" size={14} /> Scan in progress</span>
          <h2>Following the evidence trail</h2>
        </div>
        <span>{Math.min((step + 1) * 25, 95)}%</span>
      </div>
      <div className="progress-track"><span style={{ width: `${Math.min((step + 1) * 25, 95)}%` }} /></div>
      <div className="progress-steps">
        {steps.map((label, index) => (
          <div className={index <= step ? 'active' : ''} key={label}>
            {index < step ? <Check size={15} /> : <CircleDashed size={15} />}
            <span>{label}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
