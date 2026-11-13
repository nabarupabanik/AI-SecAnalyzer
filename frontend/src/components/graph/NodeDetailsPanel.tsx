import React from 'react';
import { X, FileText, CheckCircle, XCircle } from 'lucide-react';

interface NodeDetailsPanelProps {
  selectedNode: any;
  selectedEdge: any;
  onClose: () => void;
}

const NodeDetailsPanel: React.FC<NodeDetailsPanelProps> = ({ 
  selectedNode, 
  selectedEdge, 
  onClose 
}) => {
  const renderNodeDetails = () => {
    if (!selectedNode) return null;

    const data = selectedNode.data;
    
    return (
      <div className="space-y-4">
        <div>
          <h4 className="font-semibold text-gray-800 mb-2">Node Information</h4>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">ID:</span>
              <span className="font-medium">{selectedNode.id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Label:</span>
              <span className="font-medium">{data.label}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Type:</span>
              <span className="font-medium capitalize">{data.type}</span>
            </div>
            {data.severity && (
              <div className="flex justify-between">
                <span className="text-gray-600">Severity:</span>
                <span className={`font-medium capitalize ${
                  data.severity === 'critical' ? 'text-red-600' :
                  data.severity === 'high' ? 'text-orange-600' :
                  data.severity === 'medium' ? 'text-blue-600' :
                  'text-green-600'
                }`}>
                  {data.severity}
                </span>
              </div>
            )}
          </div>
        </div>

        {data.file && data.file !== 'dependency' && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Location</h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-600">File:</span>
                <span className="font-medium text-sm">{data.file}</span>
              </div>
              {data.line > 0 && (
                <div className="flex justify-between">
                  <span className="text-gray-600">Line:</span>
                  <span className="font-medium">{data.line}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {data.transaction_type && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Transaction Details</h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-600">Transaction Type:</span>
                <span className="font-medium capitalize">{data.transaction_type}</span>
              </div>
            </div>
          </div>
        )}

        {data.stg_mapping && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">STG Mapping</h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-600">STG Node:</span>
                <span className="font-medium text-sm">{data.stg_mapping}</span>
              </div>
            </div>
          </div>
        )}

        {data.data && Object.keys(data.data).length > 0 && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Additional Data</h4>
            <div className="bg-gray-50 rounded p-3">
              <pre className="text-xs text-gray-700 overflow-auto max-h-32">
                {JSON.stringify(data.data, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderEdgeDetails = () => {
    if (!selectedEdge) return null;

    const data = selectedEdge.data;
    const status = data?.status || 'unknown';
    
    return (
      <div className="space-y-4">
        <div>
          <h4 className="font-semibold text-gray-800 mb-2">Edge Information</h4>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">Source:</span>
              <span className="font-medium">{selectedEdge.source}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Target:</span>
              <span className="font-medium">{selectedEdge.target}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Status:</span>
              <span className={`font-medium capitalize ${
                status === 'valid' ? 'text-green-600' : 'text-red-600'
              }`}>
                {status}
              </span>
            </div>
          </div>
        </div>

        {data?.constraint_failed && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Constraint Analysis</h4>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Data Flow:</span>
                {data.constraint_failed.data_flow ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Execution Order:</span>
                {data.constraint_failed.execution_order ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Privilege:</span>
                {data.constraint_failed.privilege ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
            </div>
          </div>
        )}

        {data?.constraints_satisfied && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Satisfied Constraints</h4>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Data Flow Valid:</span>
                {data.constraints_satisfied.data_flow_valid ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Execution Order Valid:</span>
                {data.constraints_satisfied.execution_order_valid ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Privilege Valid:</span>
                {data.constraints_satisfied.privilege_valid ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-600">All Satisfied:</span>
                {data.constraints_satisfied.all_constraints_satisfied ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
              </div>
            </div>
          </div>
        )}

        {data && Object.keys(data).length > 0 && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2">Additional Data</h4>
            <div className="bg-gray-50 rounded p-3">
              <pre className="text-xs text-gray-700 overflow-auto max-h-32">
                {JSON.stringify(data, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ 
      width: '320px', 
      backgroundColor: 'var(--bg-card)', 
      borderLeft: '1px solid var(--border)', 
      height: '100%' 
    }}>
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h3 style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-primary)' }}>
            {selectedNode ? 'Node Details' : selectedEdge ? 'Edge Details' : 'Details'}
          </h3>
          <button
            onClick={onClose}
            style={{
              padding: '4px',
              backgroundColor: 'transparent',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              transition: 'background-color 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
          >
            <X style={{ width: '20px', height: '20px', color: 'var(--text-secondary)' }} />
          </button>
        </div>
      </div>
      
      <div style={{ padding: '16px', overflowY: 'auto', height: 'calc(100% - 73px)' }}>
        {!selectedNode && !selectedEdge ? (
          <div style={{ textAlign: 'center', padding: '32px 0' }}>
            <FileText style={{ width: '48px', height: '48px', color: 'var(--text-tertiary)', margin: '0 auto 12px' }} />
            <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
              Select a node or edge to view details
            </p>
          </div>
        ) : (
          <>
            {renderNodeDetails()}
            {renderEdgeDetails()}
          </>
        )}
      </div>
    </div>
  );
};

export default NodeDetailsPanel;
