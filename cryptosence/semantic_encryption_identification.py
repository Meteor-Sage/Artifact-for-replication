from openai import OpenAI
import json
import os
import concurrent.futures
from retry import retry
from hyper_parameters import root_path
import hyper_parameters
import embeddings_gen
import numpy as np
from scipy.spatial.distance import cosine

clients = [OpenAI(base_url=params["base_url"], api_key=params["api_key"], timeout=params["timeout"]) for params in hyper_parameters.api_parameters]
executors = [concurrent.futures.ThreadPoolExecutor(max_workers=hyper_parameters.max_workers) for _ in clients]
current_client_index = 0
with open('Intra_function.json', 'r', encoding='utf-8') as file:
    data = json.load(file)

def compute_cosine_similarity(embedding1, embedding2):
    embedding1 = np.array(embedding1)
    embedding2 = np.array(embedding2)
    return 1 - cosine(embedding1, embedding2)

def find_closest_function(embedding):
    closest_function = None
    closest_similarity = -1

    for item in data:
        item_embedding = item['embedding']
        similarity = compute_cosine_similarity(embedding, item_embedding)
        if similarity > closest_similarity:
            closest_similarity = similarity
            closest_function = item['function_body']

    return closest_function

@retry(tries=5, delay=10)
def analyze_function(func):
    global current_client_index
    embedding = embeddings_gen.embeddings_generator_balanced(func)
    closest_function = find_closest_function(embedding)
    client = clients[current_client_index]
    name = func['Function']
    body = func['Function Body']
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system",
             "content": "You are now a code analyst and reverse engineering expert, with in-depth knowledge of various encryption algorithms and the underlying principles of ransomware."},
            {"role": "user",
             "content": f"Your task is to determine whether the code is the function of an encryption function(such as AES,RSA,TEA,DES,chacha,RC4...).\n\nRules and conditions:\n1)  If the code does not meet the criteria, set is_encryption_function to false.\n2) The output should be in JSON format. Below is an example output:\n\n  \"content_modification_operations\": \n    {{\n      \"fun_name\": \"sub_12345(v1, v2, v3);\",\n      \"is_crypto_fun\": true ,\n      \"description\": \"Potential encryption or modification of data content read into memory.\"\n}}\n3)Hash functions and other irreversible algorithms are not considered encryption algorithms.\n4) Below is an example of an encryption function from a cryptographic library:{closest_function} \n5) If you are ready, please reply 'Understood'."},
            {"role": "assistant", "content": "Understood"},
            {"role": "user", "content": f"fun_name:{name}\n{body}"},
        ]
    )
    message_content = response.choices[0].message.content
    json_content = message_content.strip('```json').strip('```').strip()
    parsed_json = json.loads(json_content)
    return parsed_json

def process_subfolder(subfolder):
    global current_client_index
    name = os.path.basename(subfolder)
    file_path = os.path.join(subfolder, f'{name}.txt')
    with open(file_path, 'r', encoding='utf-8') as file:
        functions_data = json.load(file)

    results = []
    executor = executors[current_client_index]
    current_client_index = (current_client_index + 1) % len(executors)
    with executor as e:
        future_to_func = {e.submit(analyze_function, func): func for func in functions_data}
        for future in concurrent.futures.as_completed(future_to_func):
            func = future_to_func[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                print(f'Function {func["Function"]} generated an exception: {exc}')

    output_file_path = os.path.join(subfolder, f'{name}_results.json')
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        json.dump(results, output_file, ensure_ascii=False, indent=4)


if __name__ == '__main__':
    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    for subfolder in subfolders:
        process_subfolder(subfolder)
        print(subfolder)
