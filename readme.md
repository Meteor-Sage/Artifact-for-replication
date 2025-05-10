### Targeting the Persistent and Inevitable: Static Ransomware Detection via Tracing Encryption Behaviors

#### Abstract

Ransomware persists as a critical cyber threat, with escalating attack volumes and sophistication despite decades of defensive efforts. Dynamic ransomware analysis incurs higher overhead than static analysis. In contrast, static approaches proactively identify ransomware prior to execution, inherently overcoming these limitations. However, representative detectors such as general-purpose raw-binary ones, struggle to cope with static obfuscation techniques (e.g. code polymorphism), highlighting the need for a more resilient approach.

Intuitively, we put our focus on the persistent and inevitable behavior of ransomware from a static perspective. i.e., encryption behaviors. It circumvents the pitfalls of dynamic approaches while addressing the limitations of general-purpose binary analysis and resisting common evasion techniques. We propose CryptoSense, a novel ransomware detection approach that leverages static analysis of intrinsic encryption behaviors overlooked by prior work. Our intuition is that attackers typically implement encryption behaviors by invoking OS APIs, reusing encryption libraries, or reimplementing encryption algorithms, while designing new encryption algorithms is rare. Our experiments demonstrate that ransomware exhibits distinctive OS API usage patterns and encryption algorithm constants. We evaluate CryptoSense's effectiveness, robustness, generalizability, and resistance to evasion attacks, compared to the state-of-the-art approaches. CryptoSense significantly outperforms the state-of-the-art, achieving F1-score improvements of 37.0%, 35.6%, and 27.8% across varying ransomware-to-benign ratios. Moreover, CryptoSense achieves a low false negative rate of 0.08, a prominent reduction of 82.2% compared to the state-of-the-art. Ablation studies, performance-cost analyses, and parameter sensitivity evaluations further validate CryptoSense's component effectiveness and practical usability.



This paper has been submitted to NDSS 2026.





### Recent News

- [2024-05-10]🚀🚀🚀We provided the source code for CRYPTOSENSE.
- [2024-05-8]🚀🚀🚀We provided the experimental data for [RQ2-6](evaluation) for validation.
- [2024-05-2]🚀🚀🚀We have updated the data [sources](dataset/source,database/source)  for data collection.
- [2024-05-1]🚀🚀🚀We provided the experimental data for [RQ1](evaluation/RQ1) for validation.
- [2024-04-29]🚀🚀🚀We have released our [dataset](dataset) (Benchmark A, Benchmark B, Benchmark C).
- [2025-04-28]🚀🚀🚀We have released our [data base](database).



### Dataset

**Ransomware Sample Collection:** We gathered ransomware samples from two primary sources. The first source is  [MarauderMap](https://github.com/THU-WingTecher/MarauderMap), which includes 7,796 active and unique ransomware samples spanning 95 widely recognized ransomware families, covering the period from 2022 to 2023. To evaluate the generalizability of our approach to more recent threats, we additionally collected 205 ransomware samples from [VirusShare](https://virusshare.com/). This was done using ransomware reports published by the Cybersecurity and Infrastructure Security Agency [(CISA)](https://www.cisa.gov/). Specifically, we searched recent reports on the CISA website using the keyword “ransomware,” which returned 100 results. We manually inspected each report and identified 23 distinct ransomware families. We excluded 15 of them if the ransomware incidents occurred before 2024, resulting in a final list of eight ransomware families. We then searched for these eight families on VirusShare, yielding 205 newly discovered ransomware samples, representing threats from 2024 to 2025.

**Benign Sample Collection:** Meanwhile, benign samples were sourced from the DikeDataset, which includes 1,083 benign software samples collected between 2021 and 2023.

**Sample Distribution and Cost Estimation:** We estimated that running the entire experiment would incur a considerable LLM usage fee. Specifically, executing all 9,084 packages (i.e., 7,796 from MarauderMap, 205 from VirusShare, and 1,083 benign samples) once would approximately cost USD $800. This cost scales up to approximately USD $40,000 to complete the Effectiveness Evaluation (RQ2), Evasion Evaluation (RQ3), Ablation Study (RQ4), and Parameter Sensitivity Analysis (RQ6). To balance cost and reliability, we instead sampled 366, 134, and 284 [packages](dataset) from MarauderMap, VirusShare, and DikeDataset, respectively, at a 95% confidence level and a 5% margin of error.



### Source code

Our code can be download [here](cryptosence)

#### **List of File:**

- backward_taint_analysis.py: Performs backward taint analysis to trace data flow .

- candidate_function_selection.py: Selects candidate functions for further analysis.

- constant_list.csv: Store yara rule name and API name for scanning

- dangerous_flow_generation.py: Generates potentially dangerous data flows.

- embeddings_gen.py: Generates embeddings for code snippets for further analysis.

- extract_functions_with_keyword.py: Extracts functions containing yara rule name and API name from the codebase for further analysis.
- extract_graph.py: Extracts control flow graphs from the code for static analysis.

- feature.py: Extracts features for training machine learning models.
- hyper_parameters.py: Defines and manages hyperparameters.
- Intra_function.json: Function database.
- lexical_encryption_identification.py: Identifies lexical encryption parts in the code through static analysis.
- logistic_regression_models.joblib: Saves trained logistic regression models for future predictions.

- logistic_regression_predict.py: Loads trained models and performs predictions on new data.
- logistic_regression_train.py: Trains logistic regression models from data and saves the models.

- process_identification.py: Saving identification results to csv.
- requirements.txt: Lists the Python libraries and versions required for the project.
- samples: Root path for samples.

- semantic_encryption_identification.py: Identifies semantic encryption mechanisms in the code.
- severity_level.py: Assesses and labels the severity of functions in the code.

- subgraph.py: Extracts specific subgraphs from the overall code structure for analysis.

#### **How to run:**

##### 00. environment:

see [requirements.txt](cryptosence/requirements.txt)

##### 01. Setup:

- **hyper_parameters.py:**

  - `root_path`: Specifies the root directory path where sample files are stored.

  - `max_workers`: Sets the maximum number of concurrent worker threads.

  * `max_tokens`: Sets the maximum number of tokens allowed per processing or request.

  - `Candidate_n`: Specifies the number of candidate options.

  - `sample_label`: Sets the label value for samples in training (0 for ransomware, 1 for benign).

  - `api_parameters`: Configures a list of parameters for API connections, including the base URL, API key, and request timeout.

    - `base_url`: The base URL of the API.

    - `api_key`: The key required to access the API.

    - `timeout`: The request timeout in seconds.

- **samples:**
  - If the sample is packed, use [mal_unpack](https://github.com/hasherezade/mal_unpack) to unpack it. Perform reverse analysis on the unpacked file using [IDA Pro](https: //hex-rays.com/ida-pro), and import the `Encryption_constants.rules` with the `findcrypt3.py` plugin for reverse analysis. Obtain the `hash.c` and `hash.gdl` file and place it in `samples/hash/`.

##### 02. Lexical encryption identification:

- **Input:**
  - Decompiled code `{hash}.c`
  - Call graph `{hash}.gdl`
  - Lexical list `constant_list.csv`
  - Hyperparameters `hyper_parameters.py`
- **Output**: 
  - Identified function list `{hash}.csv`

```
python lexical_encryption_identification.py
```

##### 03. Candidate function selection:

- **Input:**
  - Decompiled code `{hash}.c`
  - Identified function list `{hash}.csv`
  - Hyperparameters `hyper_parameters.py`
- **Output**: 
  - Candidate functions `{hash}.txt`
  - Identified function list `{hash}.csv`

```
python candidate_function_selection.py
```

##### 04. Semantic encryption identification:

- **Input:**
  - Candidate functions `{hash}.txt`
  - Hyperparameters `hyper_parameters.py`
- **Output**: 
  - Identified function list `{hash}.csv`
  - Semantic encryption function info `{hash}_results.json`

```
python semantic_encryption_identification.py
python process_identification.py
```

##### 05. Dangerous flow generation:

- **Input:**
  - Decompiled code `{hash}.c`
  - Identified function list `{hash}.csv`
  - Lexical list `constant_list.csv`
  - Hyperparameters `hyper_parameters.py`
- **Output**: 
  - Subgraphs of behaviors `{behaviors}`
  - Dangerous flow `res{1-3}.json`

```
python dangerous_flow_generation.py
```

**06. Backward taint analysis and Assign severity level:**

- **Input:**
  - Decompiled code `{hash}.c`
  - Subgraphs of behaviors `{behaviors}`
  - Dangerous flow `res{1-3}.json`
  - Hyperparameters `hyper_parameters.py`
- **Output**: 
  - Backward taint analysis and assign severity level results `{hash}.pkl`

```
python backward_taint_analysis.py
python severity_level.py
```

**07. Generate features and labels for training and testing**

- **Input:**
  - Backward taint analysis and assign severity level results `{hash}.pkl`
  - Hyperparameters `hyper_parameters.py`
  - Path to save feature and label lists
- **Output**: 
  - Feature and labels list `{name}.csv`

```
python feature.py {name}.csv
```

**08. Training logistic regression model: **

- **Input:**
  - Feature and labels list for all train data `{name}.csv`
  - Hyperparameters `hyper_parameters.py`
- **Output**: 
  - Logistic regression model `logistic_regression_models.joblib`

```
python logistic_regression_train.py {name}.csv
```

**09. Logistic Regression Model Prediction: **

- **Input:**
  - Feature and labels list for all train data `{name}.csv`
  - Logistic regression model `logistic_regression_models.joblib`
- **Output**: 
  - Performance Metrics

```
python logistic_regression_predict.py {name}.csv
```



### Evaluation

The evaluation contains RQ1, RQ2, RQ3, RQ4 and RQ5, the data and code can download [here](evaluation), after downloading, you can easily replicate the result on our paper.

- **Usage Analysis (RQ1):**

  The results from the Algorithm Constants analysis are stored in [Encryption_Algorithm_Constants_Benign.csv](evaluation/RQ1/Encryption_Algorithm_Constants_Benign.csv) and [Encryption_Algorithm_Constants_Ransomware.csv](evaluation/RQ1/Encryption_Algorithm_Constants_Ransomware.csv). The results from the OS API analysis are stored in [OS_API_Benign.csv](evaluation/RQ1/OS_API_Benign.csv) and [OS_API_Ransomware.csv](evaluation/RQ1/OS_API_Ransomware.csv).

  Run the following commands to calculate the metrics corresponding to different evidence:

  ```
  python Process_APIs.py
  python Process_Constants.py
  ```

  This will generate metric files ending with .pkl. Then, run the following command:

  ```
  python Validation.py
  ```

  This will generate [Fig7](evaluation/RQ1/Fig7.pdf) and [Fig8](evaluation/RQ1/Fig8.pdf) from the paper.

- **Effectiveness Evaluation (RQ2):** 

  For **GREEDYBLOCK**, we cloned the open-source code by [Keane Lucas](https://kilthub.cmu.edu/authors/Keane_Lucas/18736429). However, this code could not run due to the absence of a dataset and some utility functions. We replicated the method according to its code logic and tested it on all [data](dataset), obtaining the detection [results](evaluation/RQ2/results_GREEDYBLOCK.json).

  For **Random Forest**, we cloned the open-source code by [Hojjat](https://github.com/ucsb-seclab/packware), followed its [guidelines](https://github.com/ucsb-seclab/packware?tab=readme-ov-file#1-introduction), and tested it on all [data](dataset), obtaining the detection [results](evaluation/RQ2/results_Random_Forest.json).

  For **ZRS**, since it was not open-sourced, we replicated the method based on its paper. We used this tool to test all [data](dataset), obtaining the detection [results](evaluation/RQ2/results_ZRS.json).

  For **GREEDY**, since the original open-source code link had expired, we replicated the method based on its paper. As the method involved an adversarial training process, we used [enhanced-binary-diversification](https://github.com/pwwl/enhanced-binary-diversification/tree/main) to randomly apply Kreuk, IPR, and DISP transformations to each sample in the training set. We then used this tool to test all [data](dataset), obtaining the detection [results](evaluation/RQ2/results_GREEDY_A.json).

  For our scheme **CRYPTOSENSE**, due to the presence of adversarial samples in **GREEDY**, the training set was altered. We trained two [logistic regression models](evaluation/RQ2/logistic_regression_models.joblib, evaluation/RQ2/logistic_regression_models_A.joblib) based on two datasets. To generate the accuracy of the tool on each sample, please run the following command:

  ```
  python Process_Res.py
  ```

  To calculate the accuracy of all tools on each test set, please run the following command:

  ```
  python Validation.py
  ```

  This will reproduce the results in our TABLE V.

- **Evasion Evaluation (RQ3):** 

  we used [enhanced-binary-diversification](https://github.com/pwwl/enhanced-binary-diversification/tree/main) to apply Kreuk, IPR, and DISP transformations to each sample in the testing set.

  To generate the accuracy of the tool on each sample, please run the following command:

  ```
  python Process_Res.py
  ```

  To calculate the accuracy of all tools on each test set, please run the following command:

  ```
  python Validation.py
  ```

  This will reproduce the results in our TABLE VI.

- **Ablation Study (RQ4):** 

  We evaluated the impact of different modules on CRYPTOSENSE's performance by adjusting various modules in the [source code](cryptosence). The test results for each sample are saved in the corresponding [CSV files](evaluation/RQ4/).

  By executing the following command, you can obtain the results in our TABLE VII:

  ```
  python Validation.py
  ```

- **Performance and Cost Evaluation (RQ5):** 

  When executing CRYPTOSENSE, we recorded the execution time, token usage, and cost consumption for each sample. Our evaluation data has been extracted to [cost_CRYPTOSENSE.csv](evaluation/RQ5/cost_CRYPTOSENSE.csv) and [time_CRYPTOSENSE.csv](evaluation/RQ5/time_CRYPTOSENSE.csv).

  The time consumption of other tools can be extracted from their logs. Detailed detection time data for each tool can be found [here](evaluation/RQ5/).

  To calculate the average values and total tokens for each metric, you can execute the following command:

  ```
  python Validation.py
  ```

- **Parameter Sensitivity Analysis (RQ6):**

  We evaluated the impact of different thresholds on CRYPTOSENSE's performance by adjusting the threshold parameter (Candidate_n) in [hyper_parameters.py](cryptosence/hyper_parameters.py). After modifying the configuration, detect all data based on the benchmark dataset to generate experimental results. Run the following command to generate [Fig9](evaluation/RQ6/Fig9.pdf) from the paper:

  ```
  python Validation.py
  ```

  

