import { Clock3, GitCompareArrows } from 'lucide-react';
import { activeFindings, formatDate } from '../utils';

export default function HistoryPanel({ history, currentId, onOpen, onCompare, comparing }) {
  if (!history.length) {
    return <div className="empty-state"><Clock3 size={30} /><h3>No scan history yet</h3><p>Run a scan to start tracking improvements over time.</p></div>;
  }

  return (
    <div className="history-list">
      {history.map((item, index) => (
        <article className={item.scanId === currentId ? 'current' : ''} key={item.scanId}>
          <div className="history-marker"><span /></div>
          <div className="history-content">
            <div>
              <strong>{index === 0 ? 'Latest assessment' : `Assessment ${history.length - index}`}</strong>
              <span>{formatDate(item.createdAt || item.timestamp)}</span>
            </div>
            <div className="history-stats">
              <span>{activeFindings(item.findings).length} open</span>
              <span>{item.findings?.length || 0} checks</span>
            </div>
            <button className="text-button" onClick={() => onOpen(item.scanId)}>Open</button>
          </div>
        </article>
      ))}
      {history.length >= 2 && (
        <button className="compare-action" onClick={() => onCompare(history[0].scanId, history[1].scanId)} disabled={comparing}>
          <GitCompareArrows size={17} />
          {comparing ? 'Comparing…' : 'Compare latest two scans'}
        </button>
      )}
    </div>
  );
}
