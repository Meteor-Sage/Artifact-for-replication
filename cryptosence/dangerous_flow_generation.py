import extract_graph
import subgraph
import json
import os
import extract_functions_with_keyword
from hyper_parameters import root_path, keyword_file


subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
for subfolder in subfolders:
    name = os.path.basename(subfolder)
    path = root_path + name + '/'
    file_path = path + name + '.c'
    output_file = path + name + '.csv'
    keywords = extract_functions_with_keyword.read_keywords_from_csv(keyword_file)

    read_graph_path = path + name + '.gdl'

    with open(read_graph_path, 'r') as rf:
        read_content = rf.read()

    nodes, edges = extract_graph.parse_graph(read_content)
    functions = extract_graph.read_keywords_from_csv(output_file)
    fun_list = ['crypt_function', 'delete_file_function', 'find_file_function', 'read_file_function',
                'danger_word_function']
    keword_list = ['crypt_keyword', 'delete_file_keyword', 'find_file_keyword', 'read_file_keyword','danger_word_keyword']
    category_list = ['crypt', 'delete_file', 'find_file', 'read_file', 'danger_word']
    for i in range(len(fun_list)):
        if len(functions[fun_list[i]]) > 15:
            priority_list = keywords[category_list[i]]
            priority_dict = {key: index for index, key in enumerate(priority_list)}
            combined_list = list(zip(functions[fun_list[i]], functions[keword_list[i]]))
            def get_priority(keywords):
                if all(keyword not in priority_dict for keyword in keywords):
                    return -1
                return min(priority_dict.get(keyword, float('inf')) for keyword in keywords)


            sorted_combined_list = sorted(combined_list, key=lambda x: get_priority(x[1]))
            sorted_combined_list = sorted_combined_list[:15]

            if sorted_combined_list:
                functions[fun_list[i]], functions[keword_list[i]] = zip(*sorted_combined_list)
            else:
                functions[fun_list[i]], functions[keword_list[i]] = [], []


    for category in fun_list:
        references_nodes, references_edges = extract_graph.find_references_union(functions[category], edges)
        res = extract_graph.write_graph(references_nodes, references_edges)
        if res:
            with open(path + category, 'w') as file:
                file.write(res)

    try:
        with open(path + 'find_file_function', 'r') as rf:
            find_content = rf.read()
        nodes4, edges4 = subgraph.parse_graph(find_content)
    except:
        pass

    try:
        with open(path + 'read_file_function', 'r') as rf:
            read_content = rf.read()
        nodes1, edges1 = subgraph.parse_graph(read_content)
    except:
        pass

    try:
        with open(path + 'crypt_function', 'r') as rf:
            crypt_content = rf.read()
        nodes2, edges2 = subgraph.parse_graph(crypt_content)
    except:
        pass

    try:
        with open(path + 'delete_file_function', 'r') as rf:
            delete_content = rf.read()
        nodes3, edges3 = subgraph.parse_graph(delete_content)
    except:
        pass

    try:
        sub_12_nodes, sub_12_edges, sub_12_leafs = subgraph.subgraph(nodes1, edges1, nodes2, edges2)
        sub_23_nodes, sub_23_edges, sub_23_leafs = subgraph.subgraph(nodes2, edges2, nodes3, edges3)
        sub_123_nodes, sub_123_edges, sub_123_leafs = subgraph.subgraph(sub_12_nodes, sub_12_edges, nodes3, edges3)

        result = {
            "sub_12": {
                "nodes": sub_12_nodes,
                "edges": list(sub_12_edges),
                "leafs": sub_12_leafs
            },
            "sub_23": {
                "nodes": sub_23_nodes,
                "edges": list(sub_23_edges),
                "leafs": sub_23_leafs
            },
            "sub_123": {
                "nodes": sub_123_nodes,
                "edges": list(sub_123_edges),
                "leafs": sub_123_leafs
            },
            "paths_12_1": [],
            "paths_12_2": [],
            "paths_23_2": [],
            "paths_23_3": [],
            "paths_123_12": [],
            "paths_123_23": []
        }

        for leaf in sub_12_leafs:
            for target in functions['read_file_function']:
                paths_12_1 = subgraph.path_track(leaf, target, nodes1, edges1)
                if paths_12_1:
                    result["paths_12_1"].append({"start": leaf, "end": target, "path": paths_12_1})

            for target in functions['crypt_function']:
                paths_12_2 = subgraph.path_track(leaf, target, nodes2, edges2)
                if paths_12_2:
                    result["paths_12_2"].append({"start": leaf, "end": target, "path": paths_12_2})

        for leaf in sub_23_leafs:
            for target in functions['crypt_function']:
                paths_23_2 = subgraph.path_track(leaf, target, nodes2, edges2)
                if paths_23_2:
                    result["paths_23_2"].append({"start": leaf, "end": target, "path": paths_23_2})

            for target in functions['delete_file_function']:
                paths_23_3 = subgraph.path_track(leaf, target, nodes3, edges3)
                if paths_23_3:
                    result["paths_23_3"].append({"start": leaf, "end": target, "path": paths_23_3})

        for leaf in sub_123_leafs:
            for leaf2 in sub_12_leafs:
                paths_123_12 = subgraph.path_track(leaf, leaf2, sub_12_nodes, sub_12_edges)
                if paths_123_12:
                    result["paths_123_12"].append({"start": leaf, "end": leaf2, "path": paths_123_12})

            for leaf3 in sub_23_leafs:
                paths_123_23 = subgraph.path_track(leaf, leaf3, sub_23_nodes, sub_23_edges)
                if paths_123_23:
                    result["paths_123_23"].append({"start": leaf, "end": leaf3, "path": paths_123_23})

        with open(path + 'res' + ".json", "w") as f:
            json.dump(result, f, indent=4)

        result2 = {
            "sub_12": {
                "nodes": sub_12_nodes,
                "edges": list(sub_12_edges),
                "leafs": sub_12_leafs
            },
            "sub_23": {
                "nodes": sub_23_nodes,
                "edges": list(sub_23_edges),
                "leafs": sub_23_leafs
            },
            "sub_123": {
                "nodes": sub_123_nodes,
                "edges": list(sub_123_edges),
                "leafs": sub_123_leafs
            },
            "paths_12_1": [],
            "paths_12_2": [],
            "paths_23_2": [],
            "paths_23_3": [],
            "paths_123_12": [],
            "paths_123_23": []
        }

        sub_12_leafs_update = set()
        sub_23_leafs_update = set()
        for leaf in sub_123_leafs:
            for leaf2 in sub_12_leafs:
                paths_123_12 = subgraph.path_track(leaf, leaf2, sub_12_nodes, sub_12_edges)
                if paths_123_12:
                    sub_12_leafs_update.add(leaf2)
                    result2["paths_123_12"].append({"start": leaf, "end": leaf2, "path": paths_123_12})

            for leaf3 in sub_23_leafs:
                paths_123_23 = subgraph.path_track(leaf, leaf3, sub_23_nodes, sub_23_edges)
                if paths_123_23:
                    sub_23_leafs_update.add(leaf3)
                    result2["paths_123_23"].append({"start": leaf, "end": leaf3, "path": paths_123_23})

        for leaf in sub_12_leafs_update:
            for target in functions['read_file_function']:
                paths_12_1 = subgraph.path_track(leaf, target, nodes1, edges1)
                if paths_12_1:
                    result2["paths_12_1"].append({"start": leaf, "end": target, "path": paths_12_1})

            for target in functions['crypt_function']:
                paths_12_2 = subgraph.path_track(leaf, target, nodes2, edges2)
                if paths_12_2:
                    result2["paths_12_2"].append({"start": leaf, "end": target, "path": paths_12_2})

        for leaf in sub_23_leafs_update:
            for target in functions['crypt_function']:
                paths_23_2 = subgraph.path_track(leaf, target, nodes2, edges2)
                if paths_23_2:
                    result2["paths_23_2"].append({"start": leaf, "end": target, "path": paths_23_2})

            for target in functions['delete_file_function']:
                paths_23_3 = subgraph.path_track(leaf, target, nodes3, edges3)
                if paths_23_3:
                    result2["paths_23_3"].append({"start": leaf, "end": target, "path": paths_23_3})

        with open(path + 'res2' + ".json", "w") as f:
            json.dump(result2, f, indent=4)

        result3 = {
            "sub_123": {
                "nodes": sub_123_nodes,
                "edges": list(sub_123_edges),
                "leafs": sub_123_leafs
            },
            "paths_123_1": [],
            "paths_123_2": [],
            "paths_123_3": [],
        }
        for leaf in sub_123_leafs:
            for leaf1 in functions['read_file_function']:
                paths_123_1 = subgraph.path_track(leaf, leaf1, nodes, edges)
                if paths_123_1:
                    result3["paths_123_1"].append({"start": leaf, "end": leaf1, "path": paths_123_1})
            for leaf2 in functions['crypt_function']:
                paths_123_2 = subgraph.path_track(leaf, leaf2, nodes, edges)
                if paths_123_2:
                    result3["paths_123_2"].append({"start": leaf, "end": leaf2, "path": paths_123_2})
            for leaf3 in functions['delete_file_function']:
                paths_123_3 = subgraph.path_track(leaf, leaf3, nodes, edges)
                if paths_123_3:
                    result3["paths_123_3"].append({"start": leaf, "end": leaf3, "path": paths_123_3})

        with open(path + 'res3' + ".json", "w") as f:
            json.dump(result3, f, indent=4)
        print("success:" + name)
    except:
        print("fail:"+name)


