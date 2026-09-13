from graph.service import ProvenanceGraphService

service = ProvenanceGraphService()

graph = service.run()

print("\n========== QUANTUMGUARD PROVENANCE GRAPH ==========")
print(f"Events Loaded     : {graph.graph['event_count']}")
print(f"Dropped Events    : {graph.graph['dropped_count']}")
print(f"Nodes             : {graph.number_of_nodes()}")
print(f"Edges             : {graph.number_of_edges()}")

processes = sum(
    1 for _, d in graph.nodes(data=True)
    if d["type"] == "process"
)

files = sum(
    1 for _, d in graph.nodes(data=True)
    if d["type"] == "file"
)

print(f"Process Nodes     : {processes}")
print(f"File Nodes        : {files}")
print("===============================================\n")