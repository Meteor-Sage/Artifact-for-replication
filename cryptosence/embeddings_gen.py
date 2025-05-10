import http.client
import json
import numpy as np
from transformers import GPT2Tokenizer
import time
import itertools
import hyper_parameters

tokenizer = GPT2Tokenizer.from_pretrained("gpt2")

connections_headers = []

for params in hyper_parameters.api_parameters:
    conn = http.client.HTTPSConnection(params["base_url"].replace("https://", ""), timeout=params["timeout"])
    headers = {
        'Authorization': f'Bearer {params["api_key"]}',
        'Content-Type': 'application/json'
    }
    connections_headers.append((conn, headers))

round_robin = itertools.cycle(connections_headers)


def split_tokens(text, max_tokens):
    tokens = tokenizer.encode(text)
    return [tokens[i:i + max_tokens] for i in range(0, len(tokens), max_tokens)]


def get_embedding(payload, conn, headers):
    max_retries = 5
    for attempt in range(max_retries):
        try:
            conn.request("POST", "/v1/embeddings", payload, headers)
            res = conn.getresponse()
            data = res.read()
            response = json.loads(data.decode("utf-8"))
            return response.get("data")[0].get("embedding")
        except http.client.RemoteDisconnected as e:
            print(f"RemoteDisconnected error: {e}. Retrying {attempt + 1}/{max_retries}...")
            time.sleep(2)
        except Exception as e:
            print(f"Unexpected error: {e}. Retrying {attempt + 1}/{max_retries}...")
            time.sleep(2)
    raise Exception("Failed to get embedding after multiple retries")

def embeddings_generator(function_body, conn, headers):
    max_tokens = 8192
    tokenized_function = tokenizer.encode(function_body)
    if len(tokenized_function) > max_tokens:
        parts = split_tokens(function_body, max_tokens)
        embeddings = []
        for part in parts:
            part_text = tokenizer.decode(part)
            payload = json.dumps({
                "model": "text-embedding-3-large",
                "input": part_text
            })
            embedding = get_embedding(payload, conn, headers)
            embeddings.append(embedding)

        final_embedding = np.mean(embeddings, axis=0)
    else:
        payload = json.dumps({
            "model": "text-embedding-3-large",
            "input": function_body
        })
        final_embedding = get_embedding(payload, conn, headers)

    return final_embedding

def get_balanced_connection():
    return next(round_robin)

def embeddings_generator_balanced(function_body):
    conn, headers = get_balanced_connection()
    return embeddings_generator(function_body, conn, headers)




