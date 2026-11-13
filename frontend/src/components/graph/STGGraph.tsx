import React, { useMemo, useCallback } from 'react';
import ReactFlow, {
  addEdge,
  useNodesState,
  useEdgesState,
  Controls,
  Background,
  MiniMap,
  Handle,
  Position,
} from 'reactflow';
import type { Node, Edge, Connection, NodeTypes } from 'reactflow';
import 'reactflow/dist/style.css';

// Custom node component for STG
const STGNode = ({ data, selected }: { data: any; selected: boolean }) => {
  const getNodeColor = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'db_read':
        return '#3B82F6'; // blue
      case 'db_write':
        return '#F97316'; // orange
      case 'file_op':
        return '#F59E0B'; // amber
      case 'network_op':
        return '#8B5CF6'; // purple
      case 'system':
        return '#DC2626'; // red
      default:
        return '#6B7280'; // gray
    }
  };

  const getTransactionBadge = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'db_read':
        return 'DB_READ';
      case 'db_write':
        return 'DB_WRITE';
      case 'file_op':
        return 'FILE';
      case 'network_op':
        return 'NET';
      case 'system':
        return 'SYS';
      default:
        return 'UNKNOWN';
    }
  };

  const formatTransactionLabel = (label: string, nodeId: string) => {
    // Extract function name and convert to transaction description
    const functionName = label.replace('()', '');
    const transactionNum = nodeId?.split('_')[1] || '1';
    const description = functionName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    
    return `Transaction ${transactionNum}: ${description}`;
  };

  return (
    <div
      style={{
        padding: '10px 14px',
        borderRadius: '8px',
        border: `2px solid ${getNodeColor(data.transaction_type)}`,
        backgroundColor: selected ? '#F3F4F6' : 'white',
        color: '#1F2937',
        fontSize: '12px',
        fontWeight: '500',
        minWidth: '180px',
        textAlign: 'center',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
        position: 'relative'
      }}
    >
      <Handle type="target" position={Position.Top} />
      
      {/* Transaction Type Badge */}
      <div
        style={{
          position: 'absolute',
          top: '-8px',
          left: '50%',
          transform: 'translateX(-50%)',
          backgroundColor: getNodeColor(data.transaction_type),
          color: 'white',
          fontSize: '9px',
          fontWeight: '600',
          padding: '2px 6px',
          borderRadius: '4px',
          textTransform: 'uppercase',
          letterSpacing: '0.5px'
        }}
      >
        {getTransactionBadge(data.transaction_type)}
      </div>
      
      {/* Transaction Description */}
      <div style={{ marginTop: '8px', fontWeight: '600', lineHeight: '1.3' }}>
        {formatTransactionLabel(data.label, data.id)}
      </div>
      
      {/* Additional Details */}
      <div style={{ 
        marginTop: '4px', 
        fontSize: '10px', 
        color: '#6B7280',
        fontStyle: 'italic'
      }}>
        Type: {data.transaction_type?.toUpperCase()}
        {data.file}:{data.line}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
};

const nodeTypes: NodeTypes = {
  stgNode: STGNode,
};

interface STGGraphProps {
  nodes: any[];
  edges: any[];
  onNodeClick?: (node: any) => void;
  onEdgeClick?: (edge: any) => void;
}

const STGGraph: React.FC<STGGraphProps> = ({ nodes, edges, onNodeClick, onEdgeClick }) => {
  // Convert API data to ReactFlow format
  const initialNodes = useMemo(() => {
    return nodes.map((node, index) => ({
      id: node.id,
      type: 'stgNode',
      position: {
        x: (index % 5) * 320 + 40,
        y: Math.floor(index / 5) * 160 + 40,
      },
      data: {
        label: node.label,
        transaction_type: node.transaction_type,
        file: node.file,
        line: node.line,
        ...node.data,
      },
    }));
  }, [nodes]);

  const initialEdges = useMemo(() => {
    return edges.map((edge) => ({
      id: `${edge.source}-${edge.target}`,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      style: {
        stroke: '#9CA3AF',
        strokeWidth: 2,
      },
      markerEnd: 'arrow',
      data: edge.data,
    }));
  }, [edges]);

  const [reactFlowNodes, , onNodesChange] = useNodesState(initialNodes);
  const [reactFlowEdges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  const onNodeClickHandler = useCallback((_event: React.MouseEvent, node: Node) => {
    if (onNodeClick) {
      onNodeClick(node);
    }
  }, [onNodeClick]);

  const onEdgeClickHandler = useCallback((_event: React.MouseEvent, edge: Edge) => {
    if (onEdgeClick) {
      onEdgeClick(edge);
    }
  }, [onEdgeClick]);

  return (
    <div style={{ width: '100%', height: '100%', backgroundColor: '#F9FAFB' }}>
      <ReactFlow
        nodes={reactFlowNodes}
        edges={reactFlowEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={onNodeClickHandler}
        onEdgeClick={onEdgeClickHandler}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, minZoom: 0.4, maxZoom: 1.2 }}
        attributionPosition="bottom-left"
      >
        <Controls />
        <MiniMap
          nodeStrokeColor="#9CA3AF"
          nodeColor={(node) => {
            const nodeData = node.data as any;
            return nodeData.transaction_type === 'db' ? '#3B82F6' : '#6B7280';
          }}
          nodeBorderRadius={2}
        />
        <Background color="#9CA3AF" gap={16} />
      </ReactFlow>
    </div>
  );
};

export default STGGraph;
