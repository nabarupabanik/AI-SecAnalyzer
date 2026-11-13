import React from 'react';
import { Network, Activity } from 'lucide-react';

interface GraphControlsProps {
  currentView: 'stg' | 'ecg';
  onViewChange: (view: 'stg' | 'ecg') => void;
  statistics: {
    stg_nodes_count: number;
    stg_edges_count: number;
    ecg_nodes_count: number;
    ecg_edges_count: number;
    eliminated_edges_count: number;
    total_vulnerabilities: number;
    exploit_chain_score: number;
    eliminated_paths_count: number;
  };
}

const GraphControls: React.FC<GraphControlsProps> = ({ 
  currentView, 
  onViewChange, 
  statistics 
}) => {
  return (
    <div style={{ 
      backgroundColor: 'var(--bg-card)', 
      border: '1px solid var(--border)', 
      borderRadius: '12px', 
      padding: '16px', 
      marginBottom: '16px' 
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-primary)' }}>
            Exploit Graph Analysis
          </h2>
          
          {/* View Toggle */}
          <div style={{ 
            display: 'flex', 
            backgroundColor: 'var(--bg-secondary)', 
            borderRadius: '8px', 
            padding: '4px' 
          }}>
            <button
              onClick={() => onViewChange('stg')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: '500',
                transition: 'all 0.2s',
                backgroundColor: currentView === 'stg' ? 'var(--bg-card)' : 'transparent',
                color: currentView === 'stg' ? '#3B82F6' : 'var(--text-secondary)',
                boxShadow: currentView === 'stg' ? 'var(--shadow-sm)' : 'none',
                border: 'none',
                cursor: 'pointer'
              }}
            >
              <Network style={{ width: '16px', height: '16px' }} />
              STG View
            </button>
            <button
              onClick={() => onViewChange('ecg')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: '500',
                transition: 'all 0.2s',
                backgroundColor: currentView === 'ecg' ? 'var(--bg-card)' : 'transparent',
                color: currentView === 'ecg' ? '#3B82F6' : 'var(--text-secondary)',
                boxShadow: currentView === 'ecg' ? 'var(--shadow-sm)' : 'none',
                border: 'none',
                cursor: 'pointer'
              }}
            >
              <Activity style={{ width: '16px', height: '16px' }} />
              ECG View
            </button>
          </div>
        </div>

        {/* Statistics Summary */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px', fontSize: '14px' }}>
          {currentView === 'stg' ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '12px', height: '12px', backgroundColor: '#3B82F6', borderRadius: '50%' }}></div>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {statistics.stg_nodes_count} Nodes
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '12px', height: '12px', backgroundColor: '#9CA3AF', borderRadius: '50%' }}></div>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {statistics.stg_edges_count} Edges
                </span>
              </div>
            </>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '12px', height: '12px', backgroundColor: '#EF4444', borderRadius: '50%' }}></div>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {statistics.ecg_nodes_count} Nodes
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '12px', height: '12px', backgroundColor: '#10B981', borderRadius: '50%' }}></div>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {statistics.ecg_edges_count} Valid
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '12px', height: '12px', backgroundColor: '#F87171', borderRadius: '50%' }}></div>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {statistics.eliminated_edges_count} Eliminated
                </span>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Additional Statistics */}
      <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', fontSize: '14px' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-primary)' }}>
              {statistics.total_vulnerabilities}
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>Total Vulnerabilities</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-primary)' }}>
              {statistics.exploit_chain_score}
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>Exploit Chain Score</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-primary)' }}>
              {statistics.eliminated_paths_count}
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>Paths Eliminated</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-primary)' }}>
              {statistics.ecg_edges_count > 0 
                ? Math.round((1 - statistics.eliminated_edges_count / (statistics.ecg_edges_count + statistics.eliminated_edges_count)) * 100)
                : 0
              }%
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>Success Rate</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GraphControls;
