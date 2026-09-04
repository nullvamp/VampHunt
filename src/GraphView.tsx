import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import {
  Focus,
  Maximize2,
  RefreshCw,
  Search,
  Tags,
  ZoomIn,
  ZoomOut,
} from "lucide-react";

type Relationship = {
  source_type: string;
  source_value: string;
  target_type: string;
  target_value: string;
  relation: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
};

type NodeDetail = {
  type: string;
  label: string;
  connections: number;
  events: number;
};

const colors: Record<string, string> = {
  user: "#f1bd63",
  host: "#7aa2f7",
  process: "#a99af8",
  path: "#78a9ff",
};

const prettyType = (type: string) =>
  type ? type.charAt(0).toUpperCase() + type.slice(1) : "Entity";

export function GraphView({
  relationships,
}: {
  relationships: Relationship[];
}) {
  const host = useRef<HTMLDivElement>(null);
  const graphRef = useRef<cytoscape.Core | null>(null);
  const [selected, setSelected] = useState<NodeDetail | null>(null);
  const [query, setQuery] = useState("");
  const [showRelations, setShowRelations] = useState(false);
  const [layoutMode, setLayoutMode] = useState<"organic" | "radial">("organic");

  const entityCounts = useMemo(() => {
    const values = new Map<string, Set<string>>();
    relationships.forEach((edge) => {
      if (!values.has(edge.source_type))
        values.set(edge.source_type, new Set());
      if (!values.has(edge.target_type))
        values.set(edge.target_type, new Set());
      values.get(edge.source_type)!.add(edge.source_value.toLowerCase());
      values.get(edge.target_type)!.add(edge.target_value.toLowerCase());
    });
    return Array.from(values.entries())
      .map(([type, set]) => ({ type, count: set.size }))
      .sort((a, b) => b.count - a.count);
  }, [relationships]);

  const clearFocus = () => {
    const graph = graphRef.current;
    if (!graph) return;
    graph.elements().removeClass("dimmed focused neighbor");
    setSelected(null);
  };

  const focusNode = (node: cytoscape.NodeSingular) => {
    const graph = graphRef.current;
    if (!graph) return;
    graph.elements().removeClass("dimmed focused neighbor");
    graph.elements().addClass("dimmed");

    const neighborhood = node.closedNeighborhood();
    neighborhood.removeClass("dimmed");
    node.addClass("focused");
    node.neighborhood("node").addClass("neighbor");

    const connected = node.connectedEdges();
    const events = connected.reduce(
      (sum, edge) => sum + Number(edge.data("count") || 0),
      0,
    );
    setSelected({
      type: node.data("type"),
      label: node.data("label"),
      connections: connected.length,
      events,
    });
  };

  const fitGraph = () => {
    const graph = graphRef.current;
    if (!graph) return;
    clearFocus();
    graph.animate(
      { fit: { eles: graph.elements(), padding: 54 } },
      { duration: 240 },
    );
  };

  const zoomBy = (factor: number) => {
    const graph = graphRef.current;
    if (!graph) return;
    const next = Math.max(
      graph.minZoom(),
      Math.min(graph.maxZoom(), graph.zoom() * factor),
    );
    const viewport = host.current?.getBoundingClientRect();
    graph.zoom({
      level: next,
      renderedPosition: {
        x: (viewport?.width ?? 0) / 2,
        y: (viewport?.height ?? 0) / 2,
      },
    });
  };

  const runLayout = (mode: "organic" | "radial" = layoutMode) => {
    const graph = graphRef.current;
    if (!graph) return;
    clearFocus();
    const layout =
      mode === "radial"
        ? ({
            name: "concentric",
            animate: false,
            fit: true,
            padding: 55,
            minNodeSpacing: 28,
            levelWidth: () => 1,
            concentric: (node: cytoscape.NodeSingular) =>
              node.connectedEdges().length,
          } as any)
        : ({
            name: "cose",
            animate: false,
            fit: true,
            padding: 55,
            randomize: false,
            quality: "draft",
            nodeRepulsion: () => 13500,
            idealEdgeLength: () => 105,
            edgeElasticity: () => 120,
            nestingFactor: 1.2,
            gravity: 0.22,
            numIter: 420,
          } as any);
    graph.layout(layout).run();
  };

  const searchGraph = () => {
    const graph = graphRef.current;
    const value = query.trim().toLowerCase();
    if (!graph || !value) return;
    const match = graph
      .nodes()
      .filter((node) => String(node.data("label")).toLowerCase().includes(value))
      .first();
    if (!match || match.empty()) return;
    focusNode(match as cytoscape.NodeSingular);
    graph.animate(
      { center: { eles: match }, zoom: Math.max(1.15, graph.zoom()) },
      { duration: 260 },
    );
  };

  useEffect(() => {
    if (!host.current) return;

    const ids = new Map<string, string>();
    const nodes: cytoscape.ElementDefinition[] = [];
    const nodeId = (type: string, value: string) => {
      const key = `${type}:${value.toLowerCase()}`;
      if (!ids.has(key)) {
        const id = `n${ids.size}`;
        ids.set(key, id);
        const shortLabel =
          value.length > 27 ? `${value.slice(0, 24)}…` : value;
        nodes.push({
          data: {
            id,
            label: value,
            shortLabel,
            type,
            color: colors[type] ?? "#8aa0ad",
          },
        });
      }
      return ids.get(key)!;
    };

    const edges = relationships.map((edge, index) => ({
      data: {
        id: `e${index}`,
        source: nodeId(edge.source_type, edge.source_value),
        target: nodeId(edge.target_type, edge.target_value),
        label: edge.relation.replaceAll("_", " "),
        count: edge.event_count,
      },
    }));

    const graph = cytoscape({
      container: host.current,
      elements: [...nodes, ...edges],
      minZoom: 0.24,
      maxZoom: 3.4,
      wheelSensitivity: 0.32,
      pixelRatio: 1,
      textureOnViewport: true,
      hideEdgesOnViewport: true,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            "background-opacity": 0.94,
            "border-width": 2,
            "border-color": "#d8e2e8",
            "border-opacity": 0.17,
            label: "data(shortLabel)",
            color: "#dce5eb",
            "font-size": "9px",
            "font-family": "Cascadia Mono, Consolas, monospace",
            "text-wrap": "ellipsis",
            "text-max-width": "122px",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 8,
            width: 30,
            height: 30,
            "overlay-opacity": 0,
            "underlay-color": "data(color)",
            "underlay-opacity": 0.08,
            "underlay-padding": 5,
          },
        },
        {
          selector: 'node[type = "host"]',
          style: {
            shape: "round-rectangle",
            width: 36,
            height: 27,
          },
        },
        {
          selector: 'node[type = "process"]',
          style: {
            shape: "diamond",
            width: 33,
            height: 33,
          },
        },
        {
          selector: 'node[type = "path"]',
          style: {
            shape: "round-rectangle",
            width: 34,
            height: 24,
          },
        },
        {
          selector: "node.neighbor",
          style: {
            "border-opacity": 0.4,
            "underlay-opacity": 0.12,
          },
        },
        {
          selector: "node.focused",
          style: {
            width: 38,
            height: 38,
            "border-width": 3,
            "border-color": "#f5f7fb",
            "border-opacity": 0.9,
            "underlay-opacity": 0.24,
            "underlay-padding": 9,
            "font-size": "10px",
            "font-weight": 700,
          },
        },
        {
          selector: "edge",
          style: {
            width: "mapData(count, 1, 100, 1, 4.5)",
            "line-color": "#536272",
            "line-opacity": 0.46,
            "target-arrow-color": "#677687",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.68,
            "curve-style": "bezier",
            label: "data(label)",
            color: "#9aa9b8",
            "font-size": "7px",
            "font-family": "Cascadia Mono, Consolas, monospace",
            "text-opacity": showRelations ? 0.82 : 0,
            "text-background-color": "#0b1017",
            "text-background-opacity": showRelations ? 0.92 : 0,
            "text-background-padding": "3px",
            "text-rotation": "autorotate",
          },
        },
        {
          selector: "edge:selected",
          style: {
            "line-color": "#8b84f7",
            "line-opacity": 0.95,
            "target-arrow-color": "#8b84f7",
            "text-opacity": 1,
            "text-background-opacity": 0.95,
          },
        },
        {
          selector: ".dimmed",
          style: {
            opacity: 0.13,
          },
        },
      ] as any,
      layout: {
        name: "cose",
        animate: false,
        fit: true,
        padding: 55,
        quality: "draft",
        nodeRepulsion: () => 13500,
        idealEdgeLength: () => 105,
        gravity: 0.22,
        numIter: 420,
      } as any,
    });

    graph.nodes().forEach((node) => {
      node.data("degree", node.degree());
    });
    graphRef.current = graph;

    graph.on("tap", "node", (event) => focusNode(event.target));
    graph.on("tap", (event) => {
      if (event.target === graph) clearFocus();
    });
    graph.on("dbltap", "node", (event) => {
      const node = event.target;
      graph.animate(
        { center: { eles: node }, zoom: Math.min(2, graph.maxZoom()) },
        { duration: 220 },
      );
    });

    return () => {
      graphRef.current = null;
      graph.destroy();
    };
  }, [relationships]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    graph.style()
      .selector("edge")
      .style({
        "text-opacity": showRelations ? 0.82 : 0,
        "text-background-opacity": showRelations ? 0.92 : 0,
      })
      .update();
  }, [showRelations]);

  return (
    <div className="graph-shell">
      <div className="graph-toolbar">
        <div className="graph-search">
          <Search size={14} />
          <input
            aria-label="Find entity"
            placeholder="Find user, host, process, path…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") searchGraph();
            }}
          />
          <button type="button" onClick={searchGraph}>
            Find
          </button>
        </div>
        <div className="graph-tools">
          <div className="graph-segmented" aria-label="Graph layout">
            <button
              type="button"
              className={layoutMode === "organic" ? "active" : ""}
              onClick={() => {
                setLayoutMode("organic");
                runLayout("organic");
              }}
            >
              Organic
            </button>
            <button
              type="button"
              className={layoutMode === "radial" ? "active" : ""}
              onClick={() => {
                setLayoutMode("radial");
                runLayout("radial");
              }}
            >
              Radial
            </button>
          </div>
          <button
            type="button"
            className={showRelations ? "active" : ""}
            title="Toggle relation labels"
            onClick={() => setShowRelations((value) => !value)}
          >
            <Tags size={14} />
            Labels
          </button>
          <button type="button" title="Zoom out" onClick={() => zoomBy(0.82)}>
            <ZoomOut size={15} />
          </button>
          <button type="button" title="Zoom in" onClick={() => zoomBy(1.22)}>
            <ZoomIn size={15} />
          </button>
          <button type="button" title="Fit graph" onClick={fitGraph}>
            <Maximize2 size={15} />
          </button>
          <button type="button" title="Re-layout graph" onClick={() => runLayout()}>
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      <div className="graph-stage">
        <div ref={host} className="graph-canvas" />

        <div className="graph-legend">
          {entityCounts.map(({ type, count }) => (
            <span key={type}>
              <i style={{ background: colors[type] ?? "#8aa0ad" }} />
              {prettyType(type)}
              <b>{count}</b>
            </span>
          ))}
        </div>

        {!selected && (
          <div className="graph-hint">
            <Focus size={13} />
            Click a node to isolate its neighborhood · double-click to inspect
          </div>
        )}

        {selected && (
          <aside className="graph-inspector">
            <div className="graph-inspector-head">
              <span style={{ background: colors[selected.type] ?? "#8aa0ad" }} />
              <div>
                <small>{prettyType(selected.type)}</small>
                <strong>{selected.label}</strong>
              </div>
              <button type="button" onClick={clearFocus}>
                ×
              </button>
            </div>
            <dl>
              <div>
                <dt>Relationships</dt>
                <dd>{selected.connections.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Linked events</dt>
                <dd>{selected.events.toLocaleString()}</dd>
              </div>
            </dl>
          </aside>
        )}
      </div>
    </div>
  );
}
