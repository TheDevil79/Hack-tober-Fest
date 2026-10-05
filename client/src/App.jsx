import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, Download, FileText, History, LayoutDashboard,
  RefreshCw, Search, Shield, TriangleAlert, Wifi, WifiOff
} from 'lucide-react';
import { api } from './api';
import { downloadReport, formatDate } from './utils';
import ScanForm from './components/ScanForm';
import ScanProgress from './components/ScanProgress';
import SummaryCards from './components/SummaryCards';
import FindingsPanel from './components/FindingsPanel';
import HistoryPanel from './components/HistoryPanel';
import ComparisonPanel from './components/ComparisonPanel';

const tabs = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: Search },
  { id: 'history', label: 'History', icon: History },
  { id: 'compare', label: 'Compare', icon: Activity }
];

export default function App() {
  const [url, setUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [backendOnline, setBackendOnline] = useState(null);
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [comparison, setComparison] = useState(null);
  const [comparing, setComparing] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [error, setError] = useState('');

  useEffect(() => {
    api.health().then(() => setBackendOnline(true)).catch(() => setBackendOnline(false));
  }, []);

  const loadHistory = useCallback(async target => {
    if (!target) return;
    try {
      const result = await api.history(target);
      setHistory(Array.isArray(result) ? result : []);
    } catch {
      setHistory([]);
    }
  }, []);

  const runScan = useCallback(async event => {
    event?.preventDefault();
    setError('');
    setLoading(true);
    setProgressStep(0);
    setComparison(null);

    const timer = window.setInterval(() => {
      setProgressStep(step => Math.min(step + 1, 3));
    }, 1300);

    try {
      const result = await api.scan(url.trim());
      setScan(result);
      setBackendOnline(true);
      setActiveTab('overview');
      setSelectedFinding(result.findings?.[0]?.id || null);
      await loadHistory(result.target);
    } catch (scanError) {
      setError(scanError.message);
      if (scanError.message.toLowerCase().includes('fetch')) setBackendOnline(false);
    } finally {
      window.clearInterval(timer);
      setLoading(false);
    }
  }, [loadHistory, url]);

  const openHistoricalScan = async id => {
    setError('');
    try {
      const result = await api.getScan(id);
      setScan(result);
      setActiveTab('overview');
      setSelectedFinding(result.findings?.[0]?.id || null);
    } catch (historyError) {
      setError(historyError.message);
    }
  };

  const compareScans = async (currentId, previousId) => {
    setComparing(true);
    setError('');
    try {
      setComparison(await api.compare(currentId, previousId));
      setActiveTab('compare');
    } catch (compareError) {
      setError(compareError.message);
    } finally {
      setComparing(false);
    }
  };

  const tlsLabel = useMemo(() => {
    if (!scan) return '';
    if (scan.tls?.valid) return `${scan.tls.protocol || 'TLS'} verified`;
    return scan.tls?.protocol === 'none' ? 'HTTPS not used' : 'TLS needs review';
  }, [scan]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="PatchLens home">
          <span className="brand-mark"><Shield size={19} /></span>
          <span>Patch<span>Lens</span></span>
        </a>
        <nav>
          <a href="#scanner">Scanner</a>
          <a href="#results">Results</a>
        </nav>
        <div className={`backend-status ${backendOnline === false ? 'offline' : ''}`}>
          {backendOnline === false ? <WifiOff size={14} /> : <Wifi size={14} />}
          {backendOnline === null ? 'Checking API' : backendOnline ? 'API online' : 'API offline'}
        </div>
      </header>

      <main id="top">
        <div id="scanner"><ScanForm {...{ url, setUrl, authorized, setAuthorized, loading, onSubmit: runScan }} /></div>

        {error && (
          <div className="error-banner" role="alert">
            <TriangleAlert size={18} />
            <div><strong>Request could not be completed</strong><span>{error}</span></div>
            <button onClick={() => setError('')} aria-label="Dismiss error">×</button>
          </div>
        )}

        {loading && <ScanProgress step={progressStep} />}

        {scan && !loading && (
          <section className="results" id="results">
            <header className="results-header">
              <div>
                <span className="eyebrow"><span className="pulse-dot" /> Review complete</span>
                <h2>{scan.target}</h2>
                <div className="result-meta">
                  <span>{formatDate(scan.timestamp || scan.createdAt)}</span>
                  <span>•</span><span>{tlsLabel}</span>
                  <span>•</span><span>{scan.technologies?.length || 0} technologies detected</span>
                </div>
              </div>
              <div className="result-actions">
                <button className="secondary-button" onClick={() => downloadReport(scan)}><Download size={16} /> JSON</button>
                <button className="secondary-button" onClick={() => window.print()}><FileText size={16} /> Report</button>
                <button className="primary-button" onClick={runScan}><RefreshCw size={16} /> Rescan</button>
              </div>
            </header>

            <SummaryCards scan={scan} />

            {scan.moduleErrors?.length > 0 && (
              <div className="partial-warning">
                <TriangleAlert size={17} />
                <span>Partial result: {scan.moduleErrors.map(item => item.message).join(' · ')}</span>
              </div>
            )}

            <div className="workspace">
              <aside className="tab-list" aria-label="Results sections">
                {tabs.map(tab => {
                  const Icon = tab.icon;
                  return (
                    <button key={tab.id} className={activeTab === tab.id ? 'active' : ''} onClick={() => setActiveTab(tab.id)}>
                      <Icon size={17} /><span>{tab.label}</span>
                      {tab.id === 'findings' && <small>{scan.findings?.length || 0}</small>}
                    </button>
                  );
                })}
              </aside>

              <div className="panel">
                {activeTab === 'overview' && (
                  <div className="overview-panel">
                    <div className="panel-heading"><div><span className="eyebrow">Evidence summary</span><h3>What the scanner observed</h3></div></div>
                    <div className="overview-grid">
                      <section>
                        <h4>Transport security</h4>
                        <dl><div><dt>Status</dt><dd>{scan.tls?.valid ? 'Valid' : 'Needs review'}</dd></div><div><dt>Protocol</dt><dd>{scan.tls?.protocol || 'Unknown'}</dd></div>{scan.tls?.issuer && <div><dt>Issuer</dt><dd>{scan.tls.issuer}</dd></div>}</dl>
                      </section>
                      <section>
                        <h4>Detected technologies</h4>
                        <div className="tech-list">
                          {scan.technologies?.length
                            ? scan.technologies.map(tech => <span key={`${tech.name}-${tech.version || ''}`}>{tech.name}{tech.version ? ` ${tech.version}` : ''}<small>{tech.confidence}</small></span>)
                            : <p>No technologies identified with sufficient confidence.</p>}
                        </div>
                      </section>
                    </div>
                    <button className="inline-link" onClick={() => setActiveTab('findings')}>Review all findings <span>→</span></button>
                  </div>
                )}
                {activeTab === 'findings' && <FindingsPanel findings={scan.findings} selectedId={selectedFinding} onSelect={setSelectedFinding} />}
                {activeTab === 'history' && <HistoryPanel history={history} currentId={scan.scanId} onOpen={openHistoricalScan} onCompare={compareScans} comparing={comparing} />}
                {activeTab === 'compare' && <ComparisonPanel comparison={comparison} />}
              </div>
            </div>
            <p className="scope-note">PatchLens reports only the checks performed. A clean result does not guarantee that a site has zero vulnerabilities.</p>
          </section>
        )}
      </main>

      <footer><span>PatchLens</span><p>Evidence-led web security assessment for authorized targets.</p></footer>
    </div>
  );
}
