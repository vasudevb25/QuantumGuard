from graph.service import ProvenanceGraphService

service = ProvenanceGraphService()

raw = service.load_events()
print("Raw:", len(raw))

events = service.deduplicate(raw)
events = service.validate(events)
events = service.enrich(events)

G = service.build(events)
service.save(G)

print("Nodes:", G.number_of_nodes())
print("Edges:", G.number_of_edges())