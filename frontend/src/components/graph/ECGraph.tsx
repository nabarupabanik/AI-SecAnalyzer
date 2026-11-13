import React, { useMemo, useCallback, useState } from 'react';
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
import GraphLegend from './GraphLegend';
import ConstraintTooltip from './ConstraintTooltip';

// Custom node component for ECG
const ECGNode = ({ data, selected }: { data: any; selected: boolean }) => {
  const getNodeColor = (type: string, severity: string) => {
    if (type === 'dependency') {
      return '#8B5CF6'; // purple for dependencies
    }
    
    switch (severity?.toLowerCase()) {
      case 'critical':
        return '#DC2626'; // red
      case 'high':
        return '#F59E0B'; // amber
      case 'medium':
        return '#3B82F6'; // blue
      case 'low':
        return '#10B981'; // green
      default:
        return '#EF4444'; // red for vulnerabilities
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'CRITICAL';
      case 'high':
        return 'HIGH';
      case 'medium':
        return 'MED';
      case 'low':
        return 'LOW';
      default:
        return 'HIGH';
    }
  };

  return (
    <div
      style={{
        padding: '12px 16px',
        borderRadius: '8px',
        border: `2px solid ${selected ? '#2563EB' : getNodeColor(data.type, data.severity)}`,
        backgroundColor: 'white',
        minWidth: '180px',
        textAlign: 'center',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      }}
    >
      <Handle type="target" position={Position.Top} />
      <div style={{ marginBottom: '6px' }}>
        <span
          style={{
            fontSize: '10px',
            fontWeight: 'bold',
            padding: '2px 6px',
            borderRadius: '4px',
            backgroundColor: getNodeColor(data.type, data.severity),
            color: 'white',
          }}
        >
          {getSeverityIcon(data.severity)}
        </span>
      </div>
      <div style={{ fontWeight: 'bold', marginBottom: '4px', color: '#1F2937', fontSize: '14px' }}>
        {data.label}
      </div>
      <div style={{ fontSize: '12px', color: '#6B7280', marginBottom: '4px' }}>
        {data.type === 'dependency' ? 'Dependency' : 'Vulnerability'}
      </div>
      {data.file && data.file !== 'dependency' && (
        <div style={{ fontSize: '11px', color: '#9CA3AF' }}>
          {data.file}:{data.line}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
};

const nodeTypes: NodeTypes = {
  ecgNode: ECGNode,
};

interface ECGraphProps {
  nodes: any[];
  edges: any[];
  eliminatedEdges: any[];
  onNodeClick?: (node: any) => void;
  onEdgeClick?: (edge: any) => void;
}

const ECGraph: React.FC<ECGraphProps> = ({ 
  nodes, 
  edges, 
  eliminatedEdges, 
  onNodeClick, 
  onEdgeClick 
}) => {
  // Convert API data to ReactFlow format
  const initialNodes = useMemo(() => {
    return nodes.map((node, index) => ({
      id: node.id,
      type: 'ecgNode',
      position: {
        x: (index % 5) * 320 + 40,
        y: Math.floor(index / 5) * 180 + 40,
      },
      data: {
        label: node.label,
        type: node.type,
        severity: node.severity,
        file: node.file,
        line: node.line,
        stg_mapping: node.stg_mapping,
        ...node.data,
      },
    }));
  }, [nodes]);

  const initialEdges = useMemo(() => {
    const allEdges = [
      ...edges.map((edge) => ({
        id: `valid-${edge.source}-${edge.target}`,
        source: edge.source,
        target: edge.target,
        type: 'smoothstep',
        style: {
          stroke: '#22c55e', // Green for valid edges
          strokeWidth: 3,
        },
        markerEnd: 'arrow',
        data: { ...edge.data, status: 'valid' },
        className: 'valid-edge'
      })),
      ...eliminatedEdges.map((edge) => ({
        id: `eliminated-${edge.source}-${edge.target}`,
        source: edge.source,
        target: edge.target,
        type: 'smoothstep',
        style: {
          stroke: '#ef4444', // Red for eliminated edges
          strokeWidth: 3,
          strokeDasharray: '8,4', // More prominent dashed line
        },
        markerEnd: 'arrow',
        data: { 
          ...edge.data, 
          status: 'eliminated',
          constraint_failed: edge.constraint_failed || {
            data_flow: false,
            execution_order: false,
            privilege: false
          }
        },
        className: 'eliminated-edge'
      })),
    ];

    return allEdges;
  }, [edges, eliminatedEdges]);

  const [reactFlowNodes, , onNodesChange] = useNodesState(initialNodes);
  const [reactFlowEdges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [tooltip, setTooltip] = useState<{ edge: Edge; x: number; y: number } | null>(null);

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

  const onEdgeMouseEnter = useCallback((event: React.MouseEvent, edge: Edge) => {
    const rect = event.currentTarget.getBoundingClientRect();
    setTooltip({
      edge,
      x: rect.left + rect.width / 2,
      y: rect.top - 10
    });
  }, []);

  const onEdgeMouseLeave = useCallback(() => {
    setTooltip(null);
  }, []);

  return (
    <div style={{ width: '100%', height: '100%', backgroundColor: '#F9FAFB', position: 'relative' }}>
      <GraphLegend />
      <ReactFlow
        nodes={reactFlowNodes}
        edges={reactFlowEdges.map(edge => ({
          ...edge,
          onMouseEnter: (event: React.MouseEvent) => onEdgeMouseEnter(event, edge),
          onMouseLeave: onEdgeMouseLeave
        }))}
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
        <Background color="#9CA3AF" gap={16} />
        <Controls />
        <MiniMap
          nodeStrokeColor="#9CA3AF"
          nodeColor={(node) => {
            const nodeData = node.data as any;
            if (nodeData.type === 'dependency') return '#8B5CF6';
            return nodeData.severity === 'critical' ? '#DC2626' : '#F59E0B';
          }}
          nodeBorderRadius={2}
        />
        <Background color="#9CA3AF" gap={16} />
      </ReactFlow>
      {tooltip && (
        <ConstraintTooltip
          edge={tooltip.edge}
          x={tooltip.x}
          y={tooltip.y}
          visible={true}
        />
      )}
    </div>
  );
};

export default ECGraph;
