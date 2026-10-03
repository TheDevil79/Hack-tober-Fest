import { ArrowRight, LockKeyhole, Radar } from 'lucide-react';

export default function ScanForm({ url, setUrl, authorized, setAuthorized, loading, onSubmit }) {
  return (
    <section className="scan-card" aria-labelledby="scan-heading">
      <div className="scan-copy">
        <span className="eyebrow"><Radar size={14} /> Authorized assessment</span>
        <h1 id="scan-heading">See the risk.<br /><span>Ship the fix.</span></h1>
        <p>Deterministic scanning meets grounded remediation guidance—without inventing vulnerabilities.</p>
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
            {loading ? 'Scanning…' : 'Scan site'}
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
