import React from 'react';
import { Box } from 'lucide-react';

// The agent has a sys.containers module (gated by the allow_containers
// entitlement), but this view is not wired to it yet. It used to show
// hard-coded sample containers; it now says so instead.
const ContainersView = () => (
  <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
    <div style={{ marginBottom: '32px' }}>
      <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Box color="var(--accent-purple)" /> Containers
      </h1>
    </div>
    <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
      Container listing is not connected to the agent yet. Admins can call <code>sys.containers.list()</code> from the
      Sysscript IDE with the <code>allow_containers</code> entitlement.
    </div>
  </div>
);

export default ContainersView;
