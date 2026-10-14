import React from 'react';
import { KeyRound } from 'lucide-react';

// SSH key distribution needs an agent module that does not exist yet (there is
// no sys.ssh). The old form called it anyway and reported success.
const AccessView = () => (
  <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
    <div style={{ marginBottom: '32px' }}>
      <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <KeyRound color="var(--accent-green)" /> Access Keys
      </h1>
    </div>
    <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
      SSH key distribution is not available yet: the agent has no <code>sys.ssh</code> module.
    </div>
  </div>
);

export default AccessView;
