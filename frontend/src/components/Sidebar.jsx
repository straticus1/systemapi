import React from 'react';
import { NavLink } from 'react-router-dom';
import { Terminal, ShieldAlert, Cpu, Settings, LogOut, Box, KeyRound } from 'lucide-react';
import { useAppStore } from '../store';

export const Sidebar = () => {
  const logout = useAppStore(state => state.logout);

  return (
    <aside className="sidebar">
      <div style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '12px', borderBottom: '1px solid var(--border-light)' }}>
        <ShieldAlert size={28} color="var(--accent-cyan)" />
        <span style={{ fontSize: '1.2rem', fontWeight: 600 }} className="text-gradient">SystemAPI</span>
      </div>

      <nav style={{ padding: '24px 12px', display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
        <SidebarLink to="/" icon={<Cpu size={20} />} label="Fleet Overview" />
        <SidebarLink to="/containers" icon={<Box size={20} />} label="Containers" />
        <SidebarLink to="/access" icon={<KeyRound size={20} />} label="Access Keys" />
        <SidebarLink to="/scripts" icon={<Terminal size={20} />} label="Sysscript IDE" />
        <SidebarLink to="/alerts" icon={<Settings size={20} />} label="Alerts" />
      </nav>

      <div style={{ padding: '24px' }}>
        <button onClick={logout} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start' }}>
          <LogOut size={18} /> Disconnect
        </button>
      </div>
    </aside>
  );
};

const SidebarLink = ({ to, icon, label }) => (
  <NavLink 
    to={to}
    style={({ isActive }) => ({
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      padding: '12px 16px',
      borderRadius: '8px',
      textDecoration: 'none',
      color: isActive ? 'white' : 'var(--text-muted)',
      background: isActive ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
      borderLeft: isActive ? '3px solid var(--accent-cyan)' : '3px solid transparent',
      transition: 'all 0.2s'
    })}
  >
    {icon} 
    <span style={{ fontWeight: 500 }}>{label}</span>
  </NavLink>
);

export default Sidebar;
