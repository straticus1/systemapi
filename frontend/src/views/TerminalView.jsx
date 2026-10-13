import React, { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Terminal as XTerm } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { useAppStore } from '../store';
import { FleetAPI } from '../api';
import { ArrowLeft, Terminal, Activity, AlertTriangle } from 'lucide-react';
import 'xterm/css/xterm.css';

const TerminalView = () => {
  const { hostId } = useParams();
  const navigate = useNavigate();
  const terminalRef = useRef(null);
  const { apiKey, hosts } = useAppStore();
  
  const host = hosts.find(h => h.host_id === hostId);
  const [status, setStatus] = useState('connecting'); // connecting, active, closed, error
  const [statusError, setStatusError] = useState('');
  const [statusHostId, setStatusHostId] = useState(hostId);
  if (statusHostId !== hostId) {
    setStatusHostId(hostId);
    setStatus('connecting');
    setStatusError('');
  }
  
  useEffect(() => {
    if (!apiKey) return;

    // 1. Initialize xterm.js
    const term = new XTerm({
      cursorBlink: true,
      theme: {
        background: '#0e1013', // matches var(--bg-darker)
        foreground: '#e4e7eb',
        cursor: '#4aa8b5',
        selection: 'rgba(74, 168, 181, 0.3)',
      },
      fontFamily: '"JetBrains Mono", monospace',
      fontSize: 14,
      scrollback: 5000
    });
    
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    
    term.open(terminalRef.current);
    fitAddon.fit();
    
    term.writeln('\x1b[36mInitiating Zero-Trust Secure Tunnel...\x1b[0m');

    let cancelled = false;
    let socket = null;
    let ptyActive = false;

    const showTicketError = (err) => {
      if (cancelled) return;
      const raw = err?.response?.data?.error || err?.message || 'Ticket request failed';
      const message = typeof raw === 'string' && !raw.includes('stk_') && !/api[_-]?key/i.test(raw)
        ? raw
        : 'Ticket request failed';
      setStatus('error');
      setStatusError(message);
      term.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
    };

    const attachSocket = (ticket) => {
      if (cancelled) return;
      const wsUrl = (import.meta.env.VITE_WS_URL || 'ws://localhost:3003') + '/api/v1/systems/terminal/' + encodeURIComponent(hostId) + '?ticket=' + encodeURIComponent(ticket);
      socket = new WebSocket(wsUrl);
      socket.binaryType = 'arraybuffer';

      socket.onopen = () => {
        if (cancelled) return;
        setStatus('connecting');
        term.writeln('\x1b[32mTunnel Established. Requesting PTY from Agent...\x1b[0m');
      };

      socket.onmessage = (event) => {
        if (cancelled) return;
        if (typeof event.data === 'string') {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'pty_status') {
              if (msg.payload.status === 'starting') {
                ptyActive = true;
                setStatus('active');
                term.reset();
                socket.send(JSON.stringify({ type: 'pty_resize', rows: term.rows, cols: term.cols }));
              } else if (msg.payload.status === 'exited' || msg.payload.status === 'disconnected') {
                setStatus('closed');
                term.writeln('\r\n\x1b[33mSession Terminated by Remote Host.\x1b[0m');
              } else if (msg.payload.error) {
                setStatus('error');
                term.writeln(`\r\n\x1b[31mError: ${msg.payload.error}\x1b[0m`);
              }
            }
          } catch (e) {
            console.error(e);
          }
        } else {
          const data = new Uint8Array(event.data);
          term.write(data);
        }
      };

      socket.onclose = () => {
        if (cancelled) return;
        setStatus('closed');
        term.writeln('\r\n\x1b[31mTunnel Disconnected.\x1b[0m');
      };

      socket.onerror = () => {
        if (cancelled) return;
        setStatus('error');
        term.writeln('\r\n\x1b[31mFailed to establish tunnel.\x1b[0m');
      };
    };

    FleetAPI.openTicket(hostId, 'terminal:open').then((opened) => {
      const ticket = opened && opened.ticket;
      if (cancelled) return;
      if (typeof ticket !== 'string' || ticket.length === 0) {
        showTicketError(new Error('Ticket request failed'));
        return;
      }
      attachSocket(ticket);
    }).catch((err) => {
      showTicketError(err);
    });

    const inputHandler = term.onData(data => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'pty_input', data: data }));
      }
    });

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      if (socket && socket.readyState === WebSocket.OPEN && ptyActive) {
        socket.send(JSON.stringify({ type: 'pty_resize', rows: term.rows, cols: term.cols }));
      }
    });
    resizeObserver.observe(terminalRef.current);

    return () => {
      cancelled = true;
      inputHandler.dispose();
      resizeObserver.disconnect();
      if (socket) socket.close();
      term.dispose();
    };
  }, [apiKey, hostId]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Terminal Header */}
      <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-light)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-panel)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button className="btn btn-ghost" onClick={() => navigate('/')} style={{ padding: '8px' }}>
            <ArrowLeft size={18} />
          </button>
          <div>
            <h2 style={{ fontSize: '1.1rem', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={18} color="var(--accent)" />
              {host?.hostname || hostId}
            </h2>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              {host?.os} {host?.platform} / PTY session
            </div>
          </div>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {status === 'active' && (
             <span style={{ fontSize: '0.85rem', color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: '6px' }}><Activity size={14}/> Connected</span>
          )}
          {status === 'connecting' && (
             <span style={{ fontSize: '0.85rem', color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: '6px' }}><Activity size={14} className="animate-spin"/> Negotiating Tunnel...</span>
          )}
          {(status === 'closed' || status === 'error') && (
             <span style={{ fontSize: '0.85rem', color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: '6px' }}><AlertTriangle size={14}/> {status === 'error' && statusError ? statusError : 'Disconnected'}</span>
          )}
        </div>
      </div>
      
      {/* Terminal Body */}
      <div style={{ flex: 1, padding: '16px', background: 'var(--bg-darker)' }}>
         <div ref={terminalRef} style={{ width: '100%', height: '100%' }} />
      </div>
    </div>
  );
};

export default TerminalView;
