import re
import csv
from collections import defaultdict

def parse_graph(file_content):
    nodes = {}
    edges = set()
    node_pattern = re.compile(r'node: \{([^}]+)\}')

    for match in node_pattern.finditer(file_content):
        node_content = match.group(1).strip()
        node_attributes = {}
        attr_pattern = re.compile(r'(\w+):\s*"([^"]+)"|(\w+):\s*(\S+)')
        for attr_match in attr_pattern.finditer(node_content):
            if attr_match.group(1) and attr_match.group(2):
                key = attr_match.group(1).strip()
                value = attr_match.group(2).strip()
            else:
                key = attr_match.group(3).strip()
                value = attr_match.group(4).strip()
            node_attributes[key] = value

        title = node_attributes.get('title', None)
        label = node_attributes.get('label', node_attributes.get('node', ''))
        if title and label:
            nodes[title] = label

    for line in file_content.split('\n'):
        if line.startswith('edge: {'):
            source_match = re.search(r'sourcename: "([^"]+)"', line)
            target_match = re.search(r'targetname: "([^"]+)"', line)
            if source_match and target_match:
                source = source_match.group(1)
                target = target_match.group(1)
                source_label = nodes.get(source)
                target_label = nodes.get(target)
                if source_label and target_label:
                    edges.add((source_label, target_label))
    return nodes, edges

def find_references(label, edges):
    reverse_adjacency = {}
    for src, tgt in edges:
        if tgt not in reverse_adjacency:
            reverse_adjacency[tgt] = []
        reverse_adjacency[tgt].append(src)

    def recursive_find(current_label, visited_nodes, visited_edges):
        if current_label in visited_nodes:
            return
        visited_nodes.add(current_label)
        for predecessor in reverse_adjacency.get(current_label, []):
            visited_edges.add((predecessor, current_label))
            recursive_find(predecessor, visited_nodes, visited_edges)

    visited_nodes = set()
    visited_edges = set()
    recursive_find(label, visited_nodes, visited_edges)
    return visited_nodes, visited_edges


def normalize_label(label):
    if label.startswith('_'):
        return normalize_label(label[1:])
    if '@' in label:
        label = label.split('@', 1)[0]
    return label

def find_references_union(labels, edges):
    reverse_adjacency = defaultdict(set)
    for src, tgt in edges:
        normalized_src = normalize_label(src)
        normalized_tgt = normalize_label(tgt)
        reverse_adjacency[normalized_tgt].add(normalized_src)

    visited_nodes = set()
    visited_edges = set()
    stack = [normalize_label(label) for label in labels]

    while stack:
        current_label = stack.pop()
        if current_label in visited_nodes:
            continue
        visited_nodes.add(current_label)
        for predecessor in reverse_adjacency[current_label]:
            visited_edges.add((predecessor, current_label))
            if predecessor not in visited_nodes:
                stack.append(predecessor)

    return visited_nodes, visited_edges
def read_keywords_from_csv(csv_file):
    with open(csv_file, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        headers = next(reader)
        keywords = {header: [] for header in headers}
        for row in reader:
            for i, keyword in enumerate(row):
                if keyword:
                    keywords[headers[i]].append(keyword)
    return keywords


def write_graph(nodes, edges):
    node_dict = {node: str(index) for index, node in enumerate(nodes)}
    nodes_output = []
    for node, index in node_dict.items():
        nodes_output.append(f'node: {{ title: "{index}" label: "{node}" color: 76 textcolor: 73 bordercolor: black }}')
    edges_output = []
    for source, target in edges:
        source_index = node_dict[source]
        target_index = node_dict[target]
        edges_output.append(f'edge: {{ sourcename: "{source_index}" targetname: "{target_index}" }}')
    output = '\n'.join(nodes_output + edges_output)
    return output





