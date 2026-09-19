import React, { useState, useEffect, useCallback, memo } from 'react';
import { ReactFlow, MiniMap, Controls, Background, useNodesState, useEdgesState, Handle, Position } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Globe, Server, Cable, Cpu, Boxes } from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { DataTable } from '../components/DataTable';
import { EmptyState } from '../components/EmptyState';
import { formatDate } from '../components/format';

const TYPE_ICON: Record<string, React.ReactNode> = {
  domain: <Globe className="w-3.5 h-3.5" aria-hidden="true" />,
  ip: <Server className="w-3.5 h-3.5" aria-hidden="true" />,
  port: <Cable className="w-3.5 h-3.5" aria-hidden="true" />,
  tech: <Cpu className="w-3.5 h-3.5" aria-hidden="true" />,
};

const ScopeNode = memo(({ data }: any) => (
  <div className="px-3 py-2 border border-accent/50 bg-accent/10 rounded text-[11px] font-mono text-accent">
    <Handle type="source" position={Position.Bottom} className="!bg-accent !w-1.5 !h-1.5" />
    {data.label}
  </div>
));

const AssetNode = memo(({ data }: any) => (
  <div className="px-3 py-1.5 border border-line bg-surface-2 rounded text-[11px] font-mono text-text shadow-sm">
    <Handle type="target" position={Position.Top} className="!bg-line-strong !w-1.5 !h-1.5" />
    {data.label}
  </div>
));

const nodeTypes = { scope: ScopeNode, asset: AssetNode } as any;

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([]);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await apiFetch('/auth/assets');
      if (res.ok) {
        const data = await res.json();
        setAssets(data);
        buildGraph(data);
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load assets.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  const buildGraph = (items: any[]) => {
    const newNodes: any[] = [];
    const newEdges: any[] = [];

    newNodes.push({
      id: 'root',
      data: {
        label: 'Declared scope / root',
      },
      position: { x: 0, y: 0 },
      type: 'scope',
    });

    const domains = items.filter((a) => a.type === 'domain');
    const ips = items.filter((a) => a.type === 'ip');
    const ports = items.filter((a) => a.type === 'port');
    const techs = items.filter((a) => a.type === 'tech');

    domains.forEach((d, i) => {
      newNodes.push({
        id: `d-${d.id}`,
        data: { label: d.value },
        position: { x: (i - domains.length / 2) * 190, y: -80 },
        type: 'asset',
      });
      newEdges.push({ id: `e-root-${d.id}`, source: 'root', target: `d-${d.id}`, type: 'default' });
    });

    ips.forEach((ip, i) => {
      newNodes.push({
        id: `ip-${ip.id}`,
        data: { label: ip.value },
        position: { x: (i - ips.length / 2) * 190, y: 70 },
        type: 'asset',
      });
      const host = domains.find((d) => d.value === ip.metadata?.domain);
      newEdges.push({
        id: `e-ip-${ip.id}`,
        source: host ? `d-${host.id}` : 'root',
        target: `ip-${ip.id}`,
        type: 'default',
      });
    });

    ports.forEach((p, i) => {
      newNodes.push({
        id: `p-${p.id}`,
        data: { label: p.value },
        position: { x: (i - ports.length / 2) * 160, y: 210 },
        type: 'asset',
      });
      newEdges.push({ id: `e-p-${p.id}`, source: 'root', target: `p-${p.id}`, type: 'default' });
    });

    techs.forEach((t, i) => {
      newNodes.push({
        id: `t-${t.id}`,
        data: { label: t.value },
        position: { x: (i - techs.length / 2) * 170, y: 340 },
        type: 'asset',
      });
      newEdges.push({ id: `e-t-${t.id}`, source: 'root', target: `t-${t.id}`, type: 'default' });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  };

  const counts: Record<string, number> = { domain: 0, ip: 0, port: 0, tech: 0 };
  assets.forEach((a) => {
    counts[a.type] = (counts[a.type] ?? 0) + 1;
  });
  const total = assets.length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Assets"
        title="Attack surface graph"
        description="Discovered target landscape: domains, IPs, services, and running technologies. All nodes come from persisted observations."
      />

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Tile label="Total assets" value={total} />
        <Tile label="Domains" value={counts.domain} />
        <Tile label="IPs" value={counts.ip} />
        <Tile label="Ports" value={counts.port} />
        <Tile label="Technologies" value={counts.tech} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {/* Graph */}
        <div className="xl:col-span-7 panel rounded-md p-3 min-h-[420px]">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted px-1 pb-2">Topology</h2>
          <div className="h-[380px] bg-bg border border-line rounded overflow-hidden">
            {total === 0 && !loading ? (
              <EmptyState
                icon={<Boxes className="w-4 h-4" aria-hidden="true" />}
                title="No assets discovered"
                description="Run an assessment to start mapping the target surface."
              />
            ) : (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                fitView
                fitViewOptions={{ padding: 0.25 }}
                nodesConnectable={false}
                zoomOnScroll
                minZoom={0.2}
                proOptions={{ hideAttribution: true }}
                colorMode="dark"
              >
                <MiniMap pannable zoomable className="!bg-surface-2 !border !border-line" />
                <Controls showInteractive={false} />
                <Background color="#26282d" gap={20} />
              </ReactFlow>
            )}
          </div>
        </div>

        {/* Asset table */}
        <div className="xl:col-span-5">
          <div className="panel rounded-md overflow-hidden">
            <div className="px-4 pt-4 pb-2">
              <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">Discovered assets</h2>
            </div>
            <div className="max-h-[420px] overflow-y-auto">
              <DataTable
                loading={loading}
                error={error}
                onRetry={fetchAssets}
                rows={assets}
                keyField={(a: any) => String(a.id)}
                empty={{
                  title: 'No assets discovered',
                  description: 'Run an assessment to start mapping the target surface.',
                }}
                columns={[
                  {
                    key: 'value',
                    label: 'Asset',
                    render: (a: any) => (
                      <span className="flex items-center gap-2 min-w-0">
                        <span className="text-faint shrink-0">{TYPE_ICON[a.type] ?? <Server className="w-3.5 h-3.5" aria-hidden="true" />}</span>
                        <span className="font-mono text-[11px] text-text truncate">{a.value}</span>
                      </span>
                    ),
                  },
                  {
                    key: 'type',
                    label: 'Type',
                    render: (a: any) => <span className="mono-cell text-[10px] text-faint capitalize">{a.type}</span>,
                  },
                  {
                    key: 'service',
                    label: 'Detail',
                    render: (a: any) => {
                      const detail = a.metadata?.service || a.metadata?.name || a.metadata?.version || '';
                      return detail ? <span className="text-[11px] text-muted truncate max-w-[140px]">{detail}</span> : <span className="text-faint text-[11px]">—</span>;
                    },
                  },
                  {
                    key: 'first_seen',
                    label: 'First seen',
                    render: (a: any) => (
                      <span className="mono-cell text-[10px] text-faint">{formatDate(a.created_at)}</span>
                    ),
                  },
                ]}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const Tile: React.FC<{ label: string; value: number }> = ({ label, value }) => (
  <div className="panel rounded-md p-3">
    <p className="eyebrow mb-0.5">{label}</p>
    <p className="text-lg font-semibold text-text">{value}</p>
  </div>
);