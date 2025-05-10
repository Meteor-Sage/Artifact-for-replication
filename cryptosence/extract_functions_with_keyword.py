import re
import csv

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

def extract_functions_with_keywords(file_path, keywords):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        code = file.read()
    blocks = re.split(r'//----- (.*?) -{20,}', code)

    results = {category: [] for category in keywords.keys()}
    for i in range(1, len(blocks), 2):
        function_body = blocks[i + 1]

        pattern = re.compile(
            r'^\s*[_\w]+\s*\*?\s*(\w+)\s*\([^)]*\)',
            re.DOTALL
        )
        pattern2 = re.compile(
            r'(?:\w+::)?[_\w]+(?:\s*\*+)?\s+(\w+)\s*(?:@<\w+>)?\s*\([^)]*\)',
            re.DOTALL
        )
        function_name_match = re.search(pattern, function_body)
        function_name_match2 = re.search(pattern2, function_body)
        if function_name_match:
            function_name = function_name_match.group(1)
        elif function_name_match2:
            function_name = function_name_match2.group(1)
        else:
            continue

        for category, kw_list in keywords.items():
            matched_keywords = set()
            keyword_line_map = {}
            for keyword in kw_list:
                if keyword in function_body:
                    matched_keywords.add(keyword)
                    lines = [line.strip() for line in function_body.split('\n') if keyword in line]
                    keyword_line_map[keyword] = lines
            if matched_keywords:
                results[category].append((
                    function_name,
                    function_body,
                    keyword_line_map,
                    list(matched_keywords)
                ))

    return results

def write_results_to_csv(results, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        headers = []
        for category in results.keys():
            headers.append(f"{category}_function")
            headers.append(f"{category}_keyword")
        csvwriter.writerow(headers)
        max_length = max(len(functions) for functions in results.values())

        for i in range(max_length):
            row = []
            for category in results.keys():
                if i < len(results[category]):
                    function_name,_,_ ,keyword = results[category][i]
                    row.extend([function_name, keyword])
                else:
                    row.extend(['', ''])
            csvwriter.writerow(row)


