import { useCallback, useEffect, useState } from 'react';
import { getModelRegistry, getDrift, retrainModel, runDrift, getStats, isTestUser } from '../services/api';
import {
  dataOf,
  errorDetail,
  type ActionResult,
  type DriftByModel,
  type DriftPoint,
  type ModelRecord,
  type PipelineStats,
} from '../services/responseTypes';
import { Brain, Activity, RefreshCw, BarChart2, Wrench, Clock, ChevronDown, ChevronRight } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, ReferenceLine, Cell } from 'recharts';

// Demo-only fallbacks for test users. Built when the page module loads, not
// during render, so the timestamps stay stable across re-renders.
const DEMO_TRAINED_AT = new Date(Date.now() - 86400000 * 2).toISOString();
const DEMO_MEASURED_AT = new Date().toISOString();

const MOCK_MODELS: ModelRecord[] = [
  { model_name: 'ensemble',    model_type: 'Isolation Forest + LOF + OCSVM', event_count: 1543290, trained_at: DEMO_TRAINED_AT, version: 'v2.4.1', is_stale: false },
  { model_name: 'autoencoder', model_type: 'PyTorch Neural Autoencoder',     event_count: 1543290, trained_at: DEMO_TRAINED_AT, version: 'v1.8.0', is_stale: false },
];

const MOCK_DRIFT: DriftByModel = {
  ensemble: [
    { feature_name: 'bytes_sent', psi_value: 0.04, is_drifted: false, measured_at: DEMO_MEASURED_AT },
    { feature_name: 'login_hour', psi_value: 0.13, is_drifted: true,  measured_at: DEMO_MEASURED_AT },
    { feature_name: 'failed_logins', psi_value: 0.22, is_drifted: true,  measured_at: DEMO_MEASURED_AT },
    { feature_name: 'unique_ips',    psi_value: 0.07, is_drifted: false, measured_at: DEMO_MEASURED_AT },
    { feature_name: 'proc_count',    psi_value: 0.03, is_drifted: false, measured_at: DEMO_MEASURED_AT },
  ],
  autoencoder: [
    { feature_name: 'recon_error',   psi_value: 0.09, is_drifted: false, measured_at: DEMO_MEASURED_AT },
    { feature_name: 'latent_var',    psi_value: 0.18, is_drifted: true,  measured_at: DEMO_MEASURED_AT },
    { feature_name: 'bytes_recv',    psi_value: 0.05, is_drifted: false, measured_at: DEMO_MEASURED_AT },
  ],
};

const MOCK_STATS: PipelineStats = { normalized_events: 1543290, anomalies: 342, incidents: 12, devices: 45, model_registry: 2 };

const allExpanded = (mods: ModelRecord[]): Record<string, boolean> =>
  Object.fromEntries(mods.map((m) => [m.model_name, true]));

interface Snapshot {
  models: ModelRecord[];
  drift: DriftByModel;
  stats: PipelineStats;
}

/** Fetch models, drift and stats; test users fall back to demo data. */
const loadData = async (isTest: boolean): Promise<Snapshot | null> => {
  try {
    const [modRes, driftRes, statRes] = await Promise.all([
      getModelRegistry(), getDrift(), getStats()
    ]);
    const modData = dataOf<ModelRecord[]>(modRes);
    const driftData = dataOf<DriftByModel>(driftRes);
    const statData = dataOf<PipelineStats>(statRes);
    return {
      models: Array.isArray(modData) && modData.length > 0 ? modData : (isTest ? MOCK_MODELS : []),
      drift: driftData && (driftData.ensemble?.length || driftData.autoencoder?.length) ? driftData : (isTest ? MOCK_DRIFT : {}),
      stats: statData && Object.keys(statData).length > 0 ? statData : (isTest ? MOCK_STATS : {}),
    };
  } catch {
    return isTest ? { models: MOCK_MODELS, drift: MOCK_DRIFT, stats: MOCK_STATS } : null;
  }
};

const ModelAnalytics = () => {
  const [models, setModels] = useState<ModelRecord[]>([]);
  const [drift, setDrift] = useState<DriftByModel>({});
  const [stats, setStats] = useState<PipelineStats>({});
  const [loadingRetrain, setLoadingRetrain] = useState(false);
  const [loadingDrift, setLoadingDrift] = useState(false);
  const [expandedModels, setExpandedModels] = useState<Record<string, boolean>>({});

  const isTest = isTestUser();

  const applySnapshot = useCallback((snap: Snapshot | null) => {
    if (!snap) return;
    setModels(snap.models); setDrift(snap.drift); setStats(snap.stats);
    setExpandedModels(allExpanded(snap.models));
  }, []);

  const fetchData = () => loadData(isTest).then(applySnapshot);

  useEffect(() => {
    loadData(isTest).then(applySnapshot);
  }, [isTest, applySnapshot]);

  const handleRetrain = async () => {
    setLoadingRetrain(true);
    try {
      const res = dataOf<ActionResult>(await retrainModel());
      if (res?.status === 'ok' || res?.status === 'success') {
        alert(`✓ ${res.message || `Models retrained on ${res.events?.toLocaleString()} events!`}`);
        fetchData();
      } else { alert(`Retrain failed: ${res?.detail || res?.message || 'Unknown error'}`); }
    } catch (err) { alert('Retrain failed: ' + errorDetail(err)); }
    finally { setLoadingRetrain(false); }
  };

  const handleRunDrift = async () => {
    setLoadingDrift(true);
    try {
      const res = dataOf<ActionResult>(await runDrift());
      alert(`✓ ${res?.message || 'Drift detection complete!'}`);
      fetchData();
    } catch (err) { alert('Drift detection failed: ' + errorDetail(err)); }
    finally { setLoadingDrift(false); }
  };

  const toggleExpand = (name: string) => {
    setExpandedModels(prev => ({ ...prev, [name]: !prev[name] }));
  };

  const renderDriftChart = (modelName: string, data: DriftPoint[] | undefined) => {
    if (!data || data.length === 0) return <div className="text-[var(--color-muted)] text-sm font-mono mt-4">No drift data available for {modelName}</div>;
    
    // Sort and get latest per feature
    const sorted = [...data].sort((a, b) => new Date(b.measured_at).getTime() - new Date(a.measured_at).getTime());
    const latestMap = new Map<string, DriftPoint>();
    sorted.forEach(item => {
      if (!latestMap.has(item.feature_name)) {
        latestMap.set(item.feature_name, item);
      }
    });
    const latest = Array.from(latestMap.values());

    return (
      <div className="mt-6">
        <h4 className="text-white font-display mb-2 capitalize">{modelName}</h4>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={latest} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
              <XAxis dataKey="feature_name" stroke="#666" tick={{fill: '#999', fontSize: 12}} />
              <YAxis stroke="#666" tick={{fill: '#999', fontSize: 12}} />
              <RechartsTooltip 
                contentStyle={{ backgroundColor: 'rgba(10,15,25,0.95)', border: '1px solid rgba(0,240,255,0.3)', borderRadius: '4px' }}
                itemStyle={{ color: '#fff' }}
              />
              <ReferenceLine y={0.1} stroke="#FFD700" strokeDasharray="3 3" label={{ position: 'top', value: 'Threshold (0.1)', fill: '#FFD700', fontSize: 12 }} />
              <Bar dataKey="psi_value" radius={[2, 2, 0, 0]}>
                {
                  latest.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.is_drifted ? '#FF4444' : '#10B981'} />
                  ))
                }
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  };

  const totalEvents = stats.normalized_events || 0;
  const totalAnomalies = stats.anomalies || 0;
  const totalIncidents = stats.incidents || 0;
  const detectionRate = totalEvents > 0 ? (totalAnomalies / totalEvents * 100).toFixed(1) : "0.0";
  const groupingRatio = totalAnomalies > 0 ? (totalIncidents / totalAnomalies).toFixed(2) : "0.00";

  return (
    <div className="flex flex-col h-full space-y-8 overflow-y-auto pb-10 pr-2 custom-scrollbar">
      <header className="flex items-center border-b border-[rgba(0,240,255,0.3)] pb-4 shrink-0">
        <Brain className="text-[#FF44A8] mr-3" size={32} />
        <div>
          <h2 className="text-3xl font-display font-bold text-white tracking-widest uppercase">Model Analytics</h2>
        </div>
      </header>

      {/* Model Registry */}
      <section>
        <h3 className="text-xl font-display text-white mb-4">Model Registry</h3>
        {models.length === 0 ? (
          <div className="bg-[rgba(200,200,0,0.1)] border border-[#cccc00] p-4 text-[#cccc00] font-mono text-sm rounded">
            No models registered yet. Models are automatically trained when a device exceeds the baseline event threshold. Use the Retrain button below to trigger training manually.
          </div>
        ) : (
          <div className="space-y-4">
            {models.map((m, i) => {
              const isExpanded = expandedModels[m.model_name];
              const isStale = m.is_stale;
              return (
                <div key={i} className="border border-[rgba(0,240,255,0.15)] bg-[rgba(255,255,255,0.02)] rounded overflow-hidden">
                  <div 
                    className="flex justify-between items-center p-3 cursor-pointer hover:bg-[rgba(255,255,255,0.05)] transition-colors"
                    onClick={() => toggleExpand(m.model_name)}
                  >
                    <div className="flex items-center space-x-2">
                      {isExpanded ? <ChevronDown size={18} className="text-[var(--color-muted)]"/> : <ChevronRight size={18} className="text-[var(--color-muted)]"/>}
                      <span className="font-bold text-white capitalize">{m.model_name}</span>
                      <span className="text-[var(--color-muted)] mx-2">—</span>
                      <span className={isStale ? "text-[var(--color-critical)] text-sm font-bold flex items-center" : "text-[var(--color-safe)] text-sm font-bold flex items-center"}>
                        {isStale ? "⚠️ STALE" : "✅ Current"}
                      </span>
                    </div>
                  </div>
                  
                  {isExpanded && (
                    <div className="p-4 border-t border-[rgba(0,240,255,0.1)] bg-[rgba(0,0,0,0.2)]">
                      <div className="grid grid-cols-4 gap-4 mb-4">
                        <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] p-3 rounded">
                          <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Wrench size={12} className="mr-1 text-[#4A9EFF]"/> Type</div>
                          <div className="text-lg font-bold text-white">{m.model_type || '?'}</div>
                        </div>
                        <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] p-3 rounded">
                          <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><BarChart2 size={12} className="mr-1 text-[#10B981]"/> Training Events</div>
                          <div className="text-lg font-bold text-white">{m.event_count?.toLocaleString() || 0}</div>
                        </div>
                        <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] p-3 rounded">
                          <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center"><Clock size={12} className="mr-1 text-[#7C3AED]"/> Trained At</div>
                          <div className="text-lg font-bold text-white text-sm mt-1">{m.trained_at?.substring(0,16) || 'N/A'}</div>
                        </div>
                        <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] p-3 rounded">
                          <div className="text-xs text-[var(--color-muted)] mb-1 flex items-center">Status</div>
                          <div className={`text-lg font-bold ${isStale ? 'text-[var(--color-critical)]' : 'text-[var(--color-safe)]'}`}>{isStale ? "STALE" : "Current"}</div>
                        </div>
                      </div>
                      <div className="bg-[rgba(0,240,255,0.05)] border border-[rgba(0,240,255,0.2)] p-3 rounded text-sm text-[var(--color-primary)]">
                        <strong>Algorithm:</strong> {
                          m.model_name === 'ensemble' ? 'Isolation Forest + LOF + One-Class SVM majority-vote ensemble for multi-perspective anomaly detection.' :
                          m.model_name === 'autoencoder' ? 'PyTorch neural network autoencoder that detects anomalies via reconstruction error patterns.' :
                          'Machine learning model for anomaly detection.'
                        }
                      </div>
                      <div className="mt-2 text-xs text-[var(--color-muted)] font-mono">
                        Version: {m.version || '?'} | Last trained on {m.event_count?.toLocaleString() || 0} events
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      <div className="border-t border-[rgba(255,255,255,0.1)]"></div>

      {/* Feature Drift */}
      <section>
        <h3 className="text-xl font-display text-white mb-4">Feature Drift (PSI)</h3>
        {(!drift.ensemble?.length && !drift.autoencoder?.length) ? (
          <div className="bg-[rgba(0,150,255,0.1)] border border-[#0096FF] p-4 text-[#0096FF] font-mono text-sm rounded">
            No drift data available yet. Drift detection runs daily via the background scheduler. Click Run Drift Detection below to trigger it manually.
          </div>
        ) : (
          <div className="space-y-8">
            {renderDriftChart("ensemble", drift.ensemble)}
            {renderDriftChart("autoencoder", drift.autoencoder)}
          </div>
        )}
      </section>

      {localStorage.getItem('sentinel_role') === 'ADMIN' && (
        <>
          <div className="border-t border-[rgba(255,255,255,0.1)]"></div>

          {/* Model Management */}
          <section>
            <h3 className="text-xl font-display text-white mb-4">Model Management</h3>
            <div className="grid grid-cols-2 gap-8">
              <div>
                <h4 className="text-lg font-bold text-white flex items-center mb-1"><RefreshCw size={18} className="mr-2 text-[var(--color-primary)]"/> Manual Retrain</h4>
                <p className="text-sm text-[var(--color-muted)] mb-4 font-mono">Retrain all ML models on the latest event data from the database.</p>
                <button 
                  onClick={handleRetrain} 
                  disabled={loadingRetrain}
                  className="w-full bg-[#FF4444] text-white font-bold py-3 px-4 rounded hover:bg-[#FF6666] transition-colors disabled:opacity-50"
                >
                  {loadingRetrain ? 'Training...' : '🚀 Retrain Models Now'}
                </button>
              </div>
              <div>
                <h4 className="text-lg font-bold text-white flex items-center mb-1"><Activity size={18} className="mr-2 text-[var(--color-primary)]"/> Run Drift Detection</h4>
                <p className="text-sm text-[var(--color-muted)] mb-4 font-mono">Manually run PSI drift detection against the current model baselines.</p>
                <button 
                  onClick={handleRunDrift}
                  disabled={loadingDrift}
                  className="w-full bg-transparent border border-[rgba(255,255,255,0.2)] text-white font-bold py-3 px-4 rounded hover:bg-[rgba(255,255,255,0.05)] transition-colors disabled:opacity-50"
                >
                  {loadingDrift ? 'Running...' : '📊 Run Drift Detection Now'}
                </button>
              </div>
            </div>
          </section>

          <div className="border-t border-[rgba(255,255,255,0.1)]"></div>
        </>
      )}

      {/* Detection Pipeline Summary */}
      <section>
        <h3 className="text-xl font-display text-white mb-4">Detection Pipeline Summary</h3>
        <div className="grid grid-cols-4 gap-6">
          <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] border-l-4 border-l-[#4A9EFF] p-4 rounded">
            <div className="text-xs font-mono text-[var(--color-muted)] mb-1">Total Events</div>
            <div className="text-2xl font-bold text-white">{totalEvents.toLocaleString()}</div>
          </div>
          <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] border-l-4 border-l-[#FF8C00] p-4 rounded">
            <div className="text-xs font-mono text-[var(--color-muted)] mb-1">Total Anomalies</div>
            <div className="text-2xl font-bold text-white">{totalAnomalies.toLocaleString()}</div>
          </div>
          <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] border-l-4 border-l-[#7C3AED] p-4 rounded">
            <div className="text-xs font-mono text-[var(--color-muted)] mb-1">Detection Rate</div>
            <div className="text-2xl font-bold text-white">{detectionRate}%</div>
          </div>
          <div className="bg-[rgba(25,30,45,0.8)] border border-[rgba(0,240,255,0.15)] border-l-4 border-l-[#10B981] p-4 rounded">
            <div className="text-xs font-mono text-[var(--color-muted)] mb-1">Grouping Ratio</div>
            <div className="text-2xl font-bold text-white">{groupingRatio}</div>
          </div>
        </div>
      </section>

    </div>
  );
};

export default ModelAnalytics;
