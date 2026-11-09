# Threat Fusion AI Project

## Overview
The Threat Fusion AI project is designed to analyze web traffic data and identify potential security threats. It utilizes a dataset containing web traffic logs and implements a rules engine to flag suspicious activities based on predefined criteria.

## Project Structure
```
ThreatFusionAI
├── data
│   └── CloudWatch_Traffic_Web_Attack.csv  # Dataset for analyzing web traffic and potential attacks
├── src
│   └── rules_engine.py                      # Implements the rules engine for processing web traffic data
├── Rules.ipynb                              # Jupyter notebook for analyzing web traffic data using pandas
└── README.md                                 # Documentation for the project
```

## Setup Instructions
1. Clone the repository to your local machine.
2. Ensure you have Python installed along with the necessary libraries:
   - pandas
3. Place the `CloudWatch_Traffic_Web_Attack.csv` file in the `data` directory.

## Usage Guidelines
- Open the `Rules.ipynb` notebook to load the dataset and analyze web traffic.
- The `rules_engine.py` file contains the core logic for applying security rules to the data.
- Review the output in the notebook for any flagged suspicious activities.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any suggestions or improvements.