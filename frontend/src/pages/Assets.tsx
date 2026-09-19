import React, { useState, useEffect } from 'react';
import { ReactFlow, MiniMap, Controls, Background, useNodesState, useEdgesState } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Server, Globe, ShieldAlert, Cpu } from 'lucide-react';
import { API_URL } from '../api';

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const [nodes, setNodes, onNodesChange] = useNodesState<any>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  const fetchAssets = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8001/auth/assets');
      if (res.ok) {
        const data = await res.json();
        setAssets(data);
        buildGraphNodes(data);
      }
    } catch (err) {
      console.error('Error fetching assets:', err);
    } finally {
      setLoading(false);
    }
  };

  const buildGraphNodes = (items: any[]) => {
    // Generate React Flow nodes and edges dynamically based on assets in database
    const newNodes: any[] = [];
    const newEdges: any[] = [];

    // Root node
    const rootId = 'root-node';
    newNodes.push({
      id: rootId,
      position: { x: 250, y: 50 },
      data: {
        label: (
          <div className="flex items-center gap-2 bg-emerald-950/80 border border-emerald-500/50 p-2.5 rounded-lg text-emerald-400 font-mono text-[10px] shadow-lg shadow-emerald-500/10">
            <Globe className="w-4.5 h-4.5" />
            <div className="text-left">
              <span className="block font-bold">CyberAgent Root Scope</span>
              <span className="text-[8px] text-slate-400">Target Scans Network</span>
            </div>
          </div>
        )
      },
      style: { border: 'none', background: 'transparent' }
    });

    const domains = items.filter(a => a.type === 'domain');
    const ips = items.filter(a => a.type === 'ip');
    const ports = items.filter(a => a.type === 'port');
    const techs = items.filter(a => a.type === 'tech');

    // Build Domains
    domains.forEach((dom, index) => {
      const domId = `dom-${dom.id}`;
      newNodes.push({
        id: domId,
        position: { x: 50 + index * 200, y: 180 },
        data: {
          label: (
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 p-2 rounded text-xs text-white">
              <Globe className="w-3.5 h-3.5 text-blue-400" />
              <span>{dom.value}</span>
            </div>
          )
        },
        style: { border: 'none', background: 'transparent' }
      });
      newEdges.push({
        id: `e-root-${domId}`,
        source: rootId,
        target: domId,
        animated: true,
        style: { stroke: '#3b82f6', strokeWidth: 1 }
      });
    });

    // Build IPs
    ips.forEach((ip, index) => {
      const ipId = `ip-${ip.id}`;
      newNodes.push({
        id: ipId,
        position: { x: 80 + index * 180, y: 300 },
        data: {
          label: (
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 p-2 rounded text-xs text-white">
              <Server className="w-3.5 h-3.5 text-orange-400" />
              <span>{ip.value}</span>
            </div>
          )
        },
        style: { border: 'none', background: 'transparent' }
      });
      
      // Connect to domain if matched in metadata
      const domainVal = ip.metadata?.domain;
      const matchingDom = domains.find(d => d.value === domainVal);
      const sourceId = matchingDom ? `dom-${matchingDom.id}` : rootId;

      newEdges.push({
        id: `e-ip-${ipId}`,
        source: sourceId,
        target: ipId,
        style: { stroke: '#f97316', strokeWidth: 1 }
      });
    });

    // Build Technologies
    techs.forEach((t, index) => {
      const techId = `tech-${t.id}`;
      newNodes.push({
        id: techId,
        position: { x: 400 + index * 150, y: 300 },
        data: {
          label: (
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 p-2 rounded text-xs text-white">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>{t.value}</span>
            </div>
          )
        },
        style: { border: 'none', background: 'transparent' }
      });
      newEdges.push({
        id: `e-tech-${techId}`,
        source: rootId,
        target: techId,
        style: { stroke: '#06b6d4', strokeWidth: 1 }
      });
    });

    setNodes(newNodes);
    setEdges(newEdges as any);
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Attack Surface Graph</h2>
        <p className="text-slate-400 text-sm">Discovered target landscape mapping: domains, IPs, services, and running technologies.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Discovered Grid */}
        <div className="glass-card p-4 space-y-4 h-[550px] overflow-y-auto">
          <h3 className="text-sm font-semibold text-slate-300">Target Assets</h3>
          
          {loading ? (
            <div className="text-slate-500 text-xs text-center py-10">Resolving assets...</div>
          ) : assets.length === 0 ? (
            <div className="text-slate-500 text-xs text-center py-10">No assets detected. Run a scan to discover.</div>
          ) : (
            <div className="space-y-2">
              {assets.map((asset) => (
                <div key={asset.id} className="p-3 bg-slate-950/60 border border-slate-900 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    {asset.type === 'domain' && <Globe className="w-4 h-4 text-blue-400" />}
                    {asset.type === 'ip' && <Server className="w-4 h-4 text-orange-400" />}
                    {asset.type === 'port' && <ShieldAlert className="w-4 h-4 text-amber-400" />}
                    {asset.type === 'tech' && <Cpu className="w-4 h-4 text-cyan-400" />}
                    
                    <div className="text-xs">
                      <span className="font-semibold text-white block">{asset.value}</span>
                      <span className="text-[10px] text-slate-500 font-mono capitalize">{asset.type}</span>
                    </div>
                  </div>
                  {asset.type === 'port' && (
                    <span className="text-[9px] bg-slate-800 text-slate-300 font-bold px-2 py-0.5 rounded">
                      {asset.metadata?.service || 'open'}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attack Surface Network Map */}
        <div className="glass-card p-4 lg:col-span-3 h-[550px] relative overflow-hidden flex flex-col bg-slate-955">
          <h3 className="text-sm font-semibold text-slate-300 mb-2">Visual Topology Network</h3>
          <div className="flex-1 bg-slate-950 border border-slate-900 rounded-lg relative overflow-hidden">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              attributionPosition="bottom-right"
            >
              <Controls className="bg-slate-900 border border-slate-800 text-slate-300 rounded" />
              <Background color="#1e293b" gap={16} />
            </ReactFlow>
          </div>
        </div>
      </div>
    </div>
  );
};
