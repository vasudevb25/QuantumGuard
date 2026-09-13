import pickle
import matplotlib.pyplot as plt
import networkx as nx

with open("graphs/provenance_graph.gpickle", "rb") as f:
    G = pickle.load(f)

# Use Graphviz if available
try:
    pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
except Exception:
    pos = nx.spring_layout(
        G,
        seed=42,
        k=2,
        iterations=200
    )

processes = [
    n for n, d in G.nodes(data=True)
    if d["type"] == "process"
]

files = [
    n for n, d in G.nodes(data=True)
    if d["type"] == "file"
]

labels = {
    n: d["label"]
    for n, d in G.nodes(data=True)
}

exec_edges = [
    (u, v)
    for u, v, d in G.edges(data=True)
    if d["relation"] == "EXECUTES"
]

spawn_edges = [
    (u, v)
    for u, v, d in G.edges(data=True)
    if d["relation"] == "SPAWNS"
]

plt.figure(figsize=(18, 12))

nx.draw_networkx_nodes(
    G, pos,
    nodelist=processes,
    node_color="#4F9DDE",
    node_size=2600,
    edgecolors="black"
)

nx.draw_networkx_nodes(
    G, pos,
    nodelist=files,
    node_color="#6FCF97",
    node_size=2000,
    edgecolors="black",
    node_shape="s"
)

nx.draw_networkx_edges(
    G, pos,
    edgelist=exec_edges,
    edge_color="#555555",
    arrows=True,
    width=2
)

nx.draw_networkx_edges(
    G, pos,
    edgelist=spawn_edges,
    edge_color="#E63946",
    style="dashed",
    arrows=True,
    width=2.5
)

nx.draw_networkx_labels(
    G,
    pos,
    labels,
    font_size=8,
    font_weight="bold"
)

plt.title(
    "QuantumGuard Provenance Graph",
    fontsize=18,
    weight="bold"
)

plt.figtext(
    0.02,
    0.02,
    "Blue = Process | Green = Executable File | Red Dashed = Process Spawn",
    fontsize=10
)

plt.axis("off")
plt.tight_layout()

plt.savefig(
    "graphs/provenance_graph.png",
    dpi=300
)

plt.show()