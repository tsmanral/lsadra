import React, { useState, useEffect } from 'react';
import { MessageSquare, ThumbsUp, ThumbsDown, CheckCircle2, AlertTriangle, Clock, BarChart3, RefreshCw } from 'lucide-react';
import { getAnomalies, getIncidents, isTestUser } from '../services/api';

const FEEDBACK_MOCK = [
  { id: 'fb_001', anomaly_id: 'anom_1', analyst: 'admin', label: 'TRUE_POSITIVE',  note: 'Confirmed ransomware — WKS-112-X isolated, playbook executed.', ts: new Date(Date.now()-3600000).toISOString() },
  { id: 'fb_002', anomaly_id: 'anom_3', analyst: 'admin', label: 'TRUE_POSITIVE',  note: 'C2 callback to 185.15.202.13 confirmed via firewall logs.', ts: new Date(Date.now()-7200000).toISOString() },
  { id: 'fb_003', anomaly_id: 'anom_6', analyst: 'testuser', label: 'FALSE_POSITIVE', note: 'Dev team deployed after hours — scheduled maintenance window.', ts: new Date(Date.now()-14400000).toISOString() },
  { id: 'fb_004', anomaly_id: 'anom_4', analyst: 'testuser', label: 'TRUE_POSITIVE',  note: 'Brute force origin confirmed via Zeek conn logs.', ts: new Date(Date.now()-21600000).toISOString() },
  { id: 'fb_005', anomaly_id: 'anom_7', analyst: 'testuser', label: 'FALSE_POSITIVE', note: 'Internal network scan by IT ops for asset inventory.', ts: new Date(Date.now()-28800000).toISOString() },
];

const LABEL_COLORS: Record<string, string> = {
  TRUE_POSITIVE:  'text-[#FF4444] border-[rgba(255,68,68,0.4)]',
  FALSE_POSITIVE: 'text-[#05FFA1] border-[rgba(5,255,161,0.4)]',
  NEEDS_REVIEW:   'text-[#FFD700] border-[rgba(255,215,0,0.4)]',
};

const FeedbackLoop = () => {
  const [feedback, setFeedback] = useState<any[]>(() => (isTestUser() ? FEEDBACK_MOCK : []));
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [newNote, setNewNote]   = useState('');
  const [newLabel, setNewLabel] = useState('TRUE_POSITIVE');
  const [newAnom,  setNewAnom]  = useState('');
  const [saved, setSaved]       = useState(false);

  useEffect(() => {
    getAnomalies().then(r => { if (Array.isArray(r?.data)) setAnomalies(r.data); }).catch(() => {});
    getIncidents().then(r => { if (r?.data?.incidents) setIncidents(r.data.incidents); }).catch(() => {});
  }, []);

  const tp = feedback.filter(f => f.label === 'TRUE_POSITIVE').length;
  const fp = feedback.filter(f => f.label === 'FALSE_POSITIVE').length;
  const precision = feedback.length ? Math.round((tp / (tp + fp || 1)) * 100) : 0;

  const submitFeedback = () => {
    if (!newAnom || !newNote.trim()) return;
    const entry = {
      id: `fb_${Date.now()}`,
      anomaly_id: newAnom,
      analyst: localStorage.getItem('sentinel_username') || 'analyst',
      label: newLabel,
      note: newNote,
      ts: new Date().toISOString(),
    };
    setFeedback(prev => [entry, ...prev]);
    setNewNote(''); setNewAnom('');
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="flex flex-col h-full space-y-6 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <MessageSquare className="text-[var(--color-primary)] mr-3" size={28}/>
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Feedback Loop</h2>
          <p className="text-[var(--color-muted)] font-mono text-sm mt-1">Analyst label corrections feed back into model retraining pipeline.</p>
        </div>
      </header>

      {/* Summary KPIs */}
      <div className="grid grid-cols-4 gap-4 shrink-0">
        {[
          { label: 'Total Feedback',  value: feedback.length, icon: <MessageSquare size={18}/>, color: '#00F0FF' },
          { label: 'True Positives',  value: tp,              icon: <ThumbsUp size={18}/>,      color: '#FF4444' },
          { label: 'False Positives', value: fp,              icon: <ThumbsDown size={18}/>,    color: '#05FFA1' },
          { label: 'Model Precision', value: `${precision}%`, icon: <BarChart3 size={18}/>,     color: '#B026FF' },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="hud-panel p-4 border-l-2" style={{ borderLeftColor: color }}>
            <div className="flex items-center gap-2 text-[10px] font-mono text-[var(--color-muted)] uppercase mb-2">{icon}{label}</div>
            <div className="text-3xl font-display font-bold" style={{ color }}>{value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Submit Feedback */}
        <div className="col-span-4">
          <div className="hud-panel p-5">
            <h3 className="font-display text-base text-[var(--color-primary)] uppercase mb-4 flex items-center gap-2">
              <RefreshCw size={16}/> Submit Label Correction
            </h3>
            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">Anomaly / Incident ID</label>
                <select value={newAnom} onChange={e => setNewAnom(e.target.value)}
                  className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)]">
                  <option value="">Select anomaly…</option>
                  {anomalies.map(a => <option key={a.id} value={a.id}>{a.id} — {a.threat_type}</option>)}
                  {incidents.map(i => <option key={i.id} value={i.id}>{i.id} — {i.attack_type}</option>)}
                  {/* Fallbacks for testuser */}
                  {['anom_1','anom_2','anom_3','anom_4','anom_5','anom_6','anom_7'].map(id =>
                    <option key={id} value={id}>{id}</option>
                  )}
                </select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">Label</label>
                <select value={newLabel} onChange={e => setNewLabel(e.target.value)}
                  className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)]">
                  <option value="TRUE_POSITIVE">TRUE_POSITIVE — Confirmed Threat</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE — Benign Activity</option>
                  <option value="NEEDS_REVIEW">NEEDS_REVIEW — Escalate</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-[var(--color-muted)] uppercase block mb-1">Analyst Note</label>
                <textarea value={newNote} onChange={e => setNewNote(e.target.value)} rows={4}
                  placeholder="Describe your reasoning..."
                  className="w-full bg-[rgba(255,255,255,0.04)] border border-[rgba(0,240,255,0.2)] text-white text-xs font-mono px-3 py-2 focus:outline-none focus:border-[var(--color-primary)] resize-none"/>
              </div>
              <button onClick={submitFeedback}
                className="w-full hud-button bg-[var(--color-primary)] text-black font-bold flex items-center justify-center gap-2">
                {saved ? <><CheckCircle2 size={14}/> Submitted!</> : <><MessageSquare size={14}/> Submit Feedback</>}
              </button>
              <p className="text-[10px] font-mono text-[var(--color-muted)] text-center">
                Submissions queue for next model retraining cycle.
              </p>
            </div>
          </div>
        </div>

        {/* Feedback History */}
        <div className="col-span-8">
          <div className="hud-panel p-5 h-full">
            <h3 className="font-display text-base text-[var(--color-primary)] uppercase mb-4 flex items-center gap-2">
              <Clock size={16}/> Feedback History ({feedback.length} labels)
            </h3>
            <div className="space-y-3 overflow-y-auto max-h-[500px] custom-scrollbar pr-1">
              {feedback.map(f => (
                <div key={f.id} className="bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded p-4 hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                  <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-3">
                      <span className={`text-[10px] font-bold font-mono px-2 py-0.5 border ${LABEL_COLORS[f.label] || 'text-[var(--color-muted)]'}`}>
                        {f.label === 'TRUE_POSITIVE' ? <ThumbsUp size={10} className="inline mr-1"/> : <ThumbsDown size={10} className="inline mr-1"/>}
                        {f.label}
                      </span>
                      <span className="text-xs font-mono text-[var(--color-primary)]">{f.anomaly_id}</span>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] font-mono text-[var(--color-muted)]">{new Date(f.ts).toLocaleString()}</div>
                      <div className="text-[10px] font-mono text-gray-500">by {f.analyst}</div>
                    </div>
                  </div>
                  <p className="text-xs font-mono text-gray-400">{f.note}</p>
                </div>
              ))}
            </div>

            {/* Model impact notice */}
            <div className="mt-4 pt-4 border-t border-[rgba(255,255,255,0.05)] flex items-start gap-3">
              <AlertTriangle size={14} className="text-[#FFD700] flex-shrink-0 mt-0.5"/>
              <p className="text-[10px] font-mono text-[var(--color-muted)] leading-relaxed">
                These corrections are stored in the <span className="text-white">feedback_labels</span> table and used
                to weight training samples during the next <span className="text-white">Retrain Models</span> cycle (Model Analytics tab).
                False positive labels reduce the model's sensitivity for similar benign patterns.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FeedbackLoop;
