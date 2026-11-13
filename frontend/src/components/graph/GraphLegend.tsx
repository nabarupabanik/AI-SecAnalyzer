import React from 'react';
import { CheckCircle, XCircle, Package, Activity } from 'lucide-react';

interface LegendItem {
  type: 'valid' | 'eliminated' | 'dependency' | 'transaction';
  label: string;
  color: string;
  icon?: React.ReactNode;
}

const GraphLegend: React.FC = () => {
  const legendItems: LegendItem[] = [
    {
      type: 'valid',
      label: 'Valid Transition',
      color: '#22c55e',
      icon: <CheckCircle style={{ width: '16px', height: '16px' }} />
    },
    {
      type: 'eliminated',
      label: 'Eliminated (Constraint Failed)',
      color: '#ef4444',
      icon: <XCircle style={{ width: '16px', height: '16px' }} />
    },
    {
      type: 'dependency',
      label: 'Dependency Node',
      color: '#8b5cf6',
      icon: <Package style={{ width: '16px', height: '16px' }} />
    },
    {
      type: 'transaction',
      label: 'Transaction Node',
      color: '#3b82f6',
      icon: <Activity style={{ width: '16px', height: '16px' }} />
    }
  ];

  return (
    <div style={{
      position: 'absolute',
      top: '16px',
      right: '16px',
      backgroundColor: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '12px',
      boxShadow: 'var(--shadow-sm)',
      zIndex: 1000
    }}>
      <h4 style={{ 
        fontSize: '14px', 
        fontWeight: '600', 
        color: 'var(--text-primary)', 
        marginBottom: '8px' 
      }}>
        Legend
      </h4>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {legendItems.map((item) => (
          <div key={item.type} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              {item.icon}
              <div style={{
                width: '20px',
                height: '3px',
                backgroundColor: item.color,
                borderRadius: '2px',
                ...(item.type === 'eliminated' && {
                  borderStyle: 'dashed',
                  borderWidth: '1px',
                  borderColor: item.color,
                  backgroundColor: 'transparent'
                })
              }} />
            </div>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              {item.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default GraphLegend;
