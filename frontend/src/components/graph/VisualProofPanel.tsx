import React, { useState } from 'react';
import { XCircle, AlertCircle, CheckCircle, ChevronDown, ChevronUp, Search } from 'lucide-react';

interface VisualProofPanelProps {
  eliminatedEdges: any[];
  hasValidChains: boolean;
}

const VisualProofPanel: React.FC<VisualProofPanelProps> = ({ eliminatedEdges, hasValidChains }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const formatEdgeLabel = (edgeId: string) => {
    const parts = edgeId.split('-');
    if (parts.length >= 2) {
      return parts[1];
    }
    return edgeId;
  };

  const getConstraintIcon = (passed: boolean) => (
    passed 
      ? <CheckCircle style={{ width: '14px', height: '14px', color: '#22c55e' }} />
      : <XCircle style={{ width: '14px', height: '14px', color: '#ef4444' }} />
  );

  const getConstraintStatus = (constraintData: any) => {
    const constraints = constraintData || {};
    return {
      dataFlow: constraints.data_flow !== false,
      executionOrder: constraints.execution_order !== false,
      privilege: constraints.privilege !== false
    };
  };

  if (hasValidChains) {
    return null; // Don't show if valid chains exist
  }

  const filteredEdges = eliminatedEdges.filter(edge => {
    if (!searchQuery.trim()) return true;
    const label = `${formatEdgeLabel(edge.source || edge.from)} ${formatEdgeLabel(edge.target || edge.to)}`.toLowerCase();
    return label.includes(searchQuery.toLowerCase());
  });

  return (
    <div style={{
      backgroundColor: '#FEF3C7',
      border: '1px solid #FDE68A',
      borderRadius: '12px',
      padding: '16px 20px',
      marginTop: '20px',
      marginBottom: '20px',
      transition: 'all 0.3s ease'
    }}>
      {/* Compact Collapsible Header */}
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        style={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'space-between', 
          cursor: 'pointer',
          userSelect: 'none'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <AlertCircle style={{ width: '22px', height: '22px', color: '#D97706', flexShrink: 0 }} />
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: '600', color: '#92400E', margin: 0 }}>
              Visual Proof: Why No Valid Chains Exist
            </h3>
            <p style={{ color: '#B45309', fontSize: '13px', margin: '2px 0 0 0' }}>
              All {eliminatedEdges.length} potential exploit paths eliminated due to security constraint violations.
            </p>
          </div>
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            setIsExpanded(!isExpanded);
          }}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '6px 14px',
            borderRadius: '8px',
            border: '1px solid #FCD34D',
            backgroundColor: '#FFFBEB',
            color: '#92400E',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          {isExpanded ? (
            <>
              Hide Visual Proof <ChevronUp style={{ width: '16px', height: '16px' }} />
            </>
          ) : (
            <>
              View Proof ({eliminatedEdges.length} Paths) <ChevronDown style={{ width: '16px', height: '16px' }} />
            </>
          )}
        </button>
      </div>

      {/* Expandable Body */}
      {isExpanded && (
        <div style={{ marginTop: '16px', borderTop: '1px solid #FDE68A', paddingTop: '16px' }}>
          
          {/* Search Filter */}
          {eliminatedEdges.length > 5 && (
            <div style={{ position: 'relative', marginBottom: '12px' }}>
              <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '15px', height: '15px', color: '#B45309' }} />
              <input
                type="text"
                placeholder="Filter eliminated paths..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '8px 12px 8px 36px',
                  borderRadius: '6px',
                  border: '1px solid #FCD34D',
                  backgroundColor: 'white',
                  fontSize: '13px',
                  color: '#78350F',
                  outline: 'none'
                }}
              />
            </div>
          )}

          <div style={{ 
            backgroundColor: 'white', 
            borderRadius: '8px', 
            padding: '16px',
            border: '1px solid #FDE68A'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#92400E', margin: 0 }}>
                Attempted & Eliminated Paths ({filteredEdges.length}):
              </h4>
              <span style={{ fontSize: '12px', color: '#B45309' }}>
                Scrollable container
              </span>
            </div>
            
            {filteredEdges.length === 0 ? (
              <p style={{ color: '#B45309', fontSize: '12px', fontStyle: 'italic', margin: 0 }}>
                No matching attempted paths found.
              </p>
            ) : (
              <div style={{ 
                display: 'flex', 
                flexDirection: 'column', 
                gap: '8px',
                maxHeight: '280px',
                overflowY: 'auto',
                paddingRight: '4px'
              }}>
                {filteredEdges.map((edge, index) => {
                  const constraintStatus = getConstraintStatus(edge.constraint_failed);
                  
                  return (
                    <div key={edge.id || index} style={{
                      backgroundColor: '#FEF9C3',
                      borderRadius: '6px',
                      padding: '10px 12px',
                      border: '1px solid #FDE68A'
                    }}>
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'space-between',
                        marginBottom: '6px'
                      }}>
                        <span style={{ fontWeight: '600', color: '#92400E', fontSize: '13px' }}>
                          {formatEdgeLabel(edge.source || edge.from)} × {formatEdgeLabel(edge.target || edge.to)}
                        </span>
                        <XCircle style={{ width: '15px', height: '15px', color: '#DC2626' }} />
                      </div>
                      
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', fontSize: '11px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          {getConstraintIcon(constraintStatus.dataFlow)}
                          <span style={{ color: constraintStatus.dataFlow ? '#22c55e' : '#DC2626', fontWeight: '500' }}>
                            Data Flow
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          {getConstraintIcon(constraintStatus.executionOrder)}
                          <span style={{ color: constraintStatus.executionOrder ? '#22c55e' : '#DC2626', fontWeight: '500' }}>
                            Execution Order
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          {getConstraintIcon(constraintStatus.privilege)}
                          <span style={{ color: constraintStatus.privilege ? '#22c55e' : '#DC2626', fontWeight: '500' }}>
                            Privilege
                          </span>
                        </div>
                      </div>
                      
                      {edge.data?.reason && (
                        <div style={{
                          marginTop: '6px',
                          fontSize: '11px',
                          color: '#B45309',
                          fontStyle: 'italic',
                          borderTop: '1px solid #FDE68A',
                          paddingTop: '4px'
                        }}>
                          Reason: {edge.data.reason}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div style={{
            backgroundColor: 'white',
            borderRadius: '8px',
            padding: '12px 16px',
            border: '1px solid #FDE68A',
            marginTop: '12px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <XCircle style={{ width: '16px', height: '16px', color: '#DC2626' }} />
              <span style={{ color: '#DC2626', fontWeight: '600', fontSize: '13px' }}>
                Final State: 0 Valid Exploit Chains
              </span>
            </div>
            <p style={{ color: '#B45309', fontSize: '12px', marginTop: '4px', marginBottom: 0 }}>
              All exploit chain paths failed constraint validation, confirming the application is secure against multi-stage exploit execution.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default VisualProofPanel;
