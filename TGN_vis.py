import networkx as nx
import matplotlib.pyplot as plt

G = nx.DiGraph()

normal_nodes = ['Wallet_A', 'Wallet_B', 'Wallet_C', 'Exchange_1']
anomaly_nodes = ['Smurf_1', 'Smurf_2', 'Smurf_3', 'Mixer_Contract']

G.add_nodes_from(normal_nodes, color='lightgreen')
G.add_nodes_from(anomaly_nodes, color='salmon')

edges = [('Wallet_A', 'Exchange_1'), ('Wallet_B', 'Wallet_C'), 
         ('Smurf_1', 'Mixer_Contract'), ('Smurf_2', 'Mixer_Contract'), 
         ('Smurf_3', 'Mixer_Contract'), ('Mixer_Contract', 'Wallet_C')]
G.add_edges_from(edges)

color_map = [G.nodes[node]['color'] for node in G]

plt.figure(figsize=(9, 6))
nx.draw(G, with_labels=True, node_color=color_map, node_size=2500, 
        edge_color='gray', font_size=9, font_weight='bold', arrows=True)
plt.title("Visualisasi Deteksi Anomali TGN pada Aliran Dana Kripto", fontsize=14)
plt.show()