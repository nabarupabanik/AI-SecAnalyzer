import React from 'react';
import { CheckCircle, XCircle } from 'lucide-react';

interface ConstraintData {
  dataFlow: boolean;
  executionOrder: boolean;
  privilege: boolean;
  reason?: string;
}

interface ConstraintTooltipProps {
  edge: any;
  x: number;
  y: number;
  visible: boolean;
}

const ConstraintTooltip: React.FC<ConstraintTooltipProps> = ({ edge, x, y, visible }) => {
  if (!visible || !edge) return null;

  const constraintData: ConstraintData = edge.data?.constraint_failed || {};
  const isEliminated = edge.data?.status === 'eliminated';
  
  const getConstraintIcon = (passed: boolean) => (
    passed 
      ? <CheckCircle style={{ width: '14px', height: '14px', color: '#22c55e' }} />
      : <XCircle style={{ width: '14px', height: '14px', color: '#ef4444' }} />
  );

  const getConstraintText = (passed: boolean) => (
    passed 
      ? <span style={{ color: '#22c55e', fontWeight: '500' }}>PASS</span>
      : <span style={{ color: '#ef4444', fontWeight: '500' }}>FAIL</span>
  );

  return (
    <div
      style={{
        position: 'absolute',
        left: x,
        top: y,
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        padding: '12px',
        boxShadow: 'var(--shadow-lg)',
        zIndex: 10000,
        minWidth: '200px',
        pointerEvents: 'none'
      }}
    >
      <div style={{ 
        fontSize: '12px', 
        fontWeight: '600', 
        color: 'var(--text-primary)', 
        marginBottom: '8px',
        borderBottom: '1px solid var(--border)',
        paddingBottom: '6px'
      }}>
        Edge: {edge.source} {isEliminated ? '×' : '×'} {edge.target}
      </div>
      
      {isEliminated && (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Data Flow:</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                {getConstraintIcon(constraintData.dataFlow)}
                {getConstraintText(constraintData.dataFlow)}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Execution Order:</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                {getConstraintIcon(constraintData.executionOrder)}
                {getConstraintText(constraintData.executionOrder)}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Privilege:</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                {getConstraintIcon(constraintData.privilege)}
                {getConstraintText(constraintData.privilege)}
              </div>
            </div>
          </div>
          
          {constraintData.reason && (
            <div style={{ 
              marginTop: '8px', 
              paddingTop: '8px', 
              borderTop: '1px solid var(--border)',
              fontSize: '11px',
              color: 'var(--text-tertiary)',
              fontStyle: 'italic'
            }}>
              Reason: {constraintData.reason}
            </div>
          )}
        </>
      )}
      
      {!isEliminated && (
        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          This transition satisfies all security constraints.
        </div>
      )}
    </div>
  );
};

export default ConstraintTooltip;
