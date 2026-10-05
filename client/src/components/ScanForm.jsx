import { ArrowRight, LockKeyhole, Radar } from 'lucide-react';

export default function ScanForm({ url, setUrl, authorized, setAuthorized, loading, onSubmit }) {
  return (
    <section className="scan-card" aria-labelledby="scan-heading">
      <div className="scan-copy">
        <span className="eyebrow"><Radar size={14} /> Authorized security review</span>
        <h1 id="scan-heading">Security findings.<br /><span>Made actionable.</span></h1>
        <p>Review the controls that matter, understand the evidence, and leave with a practical remediation plan.</p>
      </div>

      <form className="scan-form" onSubmit={onSubmit}>
        <label htmlFor="target-url">Website URL</label>
        <div className="url-control">
          <LockKeyhole size={18} aria-hidden="true" />
          <input
            id="target-url"
            type="url"
            value={url}
            onChange={event => setUrl(event.target.value)}
            placeholder="https://your-site.com"
            required
            disabled={loading}
          />
          <button type="submit" disabled={loading || !authorized}>
            {loading ? 'Assessing…' : 'Run assessment'}
            {!loading && <ArrowRight size={17} />}
          </button>
        </div>
        <label className="authorization-check">
          <input
            type="checkbox"
            checked={authorized}
            onChange={event => setAuthorized(event.target.checked)}
            disabled={loading}
          />
          <span>I own this site or have explicit permission to assess it.</span>
        </label>
      </form>
    </section>
  );
}
