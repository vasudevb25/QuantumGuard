import pickle
import networkx as nx
import matplotlib.pyplot as plt

# ---------------------------------------------------
# Load graph
# ---------------------------------------------------

with open("graphs/provenance_graph.gpickle", "rb") as f:
    G = pickle.load(f)

# ---------------------------------------------------
# Better layout
# ---------------------------------------------------

try:
    # Requires graphviz installed
    pos = nx.nx_agraph.graphviz_layout(G, prog="dot")
except Exception:
    pos = nx.spring_layout(
        G,
        k=1.8,
        iterations=150,
        seed=42
    )

# ---------------------------------------------------
# Split node types
# ---------------------------------------------------

process_nodes = [
    n for n, d in G.nodes(data=True)
    if d["type"] == "process"
]

file_nodes = [
    n for n, d in G.nodes(data=True)
    if d["type"] == "file"
]

# ---------------------------------------------------
# Labels
# ---------------------------------------------------

labels = {
    n: d.get("label", n)
    for n, d in G.nodes(data=True)
}

# ---------------------------------------------------
# Draw
# ---------------------------------------------------

plt.figure(figsize=(18, 12))

nx.draw_networkx_nodes(
    G,
    pos,
    nodelist=process_nodes,
    node_color="#4F9DDE",
    node_size=2200,
    edgecolors="black",
    linewidths=1.2,
    label="Process"
)

nx.draw_networkx_nodes(
    G,
    pos,
    nodelist=file_nodes,
    node_color="#7ED957",
    node_size=1700,
    edgecolors="black",
    linewidths=1.2,
    label="File"
)

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

nx.draw_networkx_edges(
    G,
    pos,
    edgelist=exec_edges,
    edge_color="#555555",
    arrows=True,
    arrowsize=18,
    width=1.8
)

nx.draw_networkx_edges(
    G,
    pos,
    edgelist=spawn_edges,
    edge_color="#D62728",
    style="dashed",
    arrows=True,
    arrowsize=18,
    width=2
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
    "Gray → EXECUTES    |    Red Dashed → SPAWNS",
    fontsize=10,
    bbox=dict(facecolor="white", alpha=0.8)
)

plt.legend(scatterpoints=1)
plt.axis("off")
plt.tight_layout()

plt.savefig(
    "graphs/provenance_graph.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()