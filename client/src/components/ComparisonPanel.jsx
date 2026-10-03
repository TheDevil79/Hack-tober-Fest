import { ArrowRight, CircleCheck, CircleMinus, CirclePlus, GitCompareArrows } from 'lucide-react';

const groups = [
  { key: 'fixed', title: 'Fixed', icon: CircleCheck, className: 'fixed', empty: 'No findings were resolved between these scans.' },
  { key: 'unchanged', title: 'Unchanged', icon: CircleMinus, className: 'unchanged', empty: 'No findings remained unchanged.' },
  { key: 'newIssues', title: 'New issues', icon: CirclePlus, className: 'new', empty: 'No new issues were detected.' }
];

export default function ComparisonPanel({ comparison }) {
  if (!comparison) {
    return (
      <div className="empty-state">
        <GitCompareArrows size={30} />
        <h3>Compare two assessments</h3>
        <p>Open History and compare the latest scans to verify what changed.</p>
      </div>
    );
  }

  return (
    <div className="comparison-wrap">
      <div className="comparison-head">
        <span>{comparison.previousId}</span><ArrowRight size={16} /><span>{comparison.currentId}</span>
      </div>
      <div className="comparison-grid">
        {groups.map(group => {
          const Icon = group.icon;
          const items = comparison[group.key] || [];
          return (
            <section className={`compare-group ${group.className}`} key={group.key}>
              <header><Icon size={19} /><h3>{group.title}</h3><strong>{items.length}</strong></header>
              {items.length > 0
                ? <ul>{items.map(item => <li key={item}>{item}</li>)}</ul>
                : <p>{group.empty}</p>}
            </section>
          );
        })}
      </div>
    </div>
  );
}
