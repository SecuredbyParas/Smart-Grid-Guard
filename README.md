

# Smart Power Grid and Energy Infrastructure Threat Monitoring (PS-25)

## About the Project

Smart power grids use smart meters, gateways, and connected systems to monitor electricity consumption and manage energy distribution. Since these systems depend on digital communication, unusual activities or unauthorized access can affect their normal functioning.

For this project, I developed a Smart Power Grid and Energy Infrastructure Threat Monitoring Platform that works with simulated smart-meter, gateway, and administrator logs.

The main idea is to understand what normal activity looks like and identify anything that seems unusual. The system analyses the generated data, detects suspicious behaviour, and connects related events across different devices and substations.

It also provides a dashboard where users can view detected incidents, check affected assets, and understand why an activity was flagged. An incident report is also generated to make the investigation easier.

**Important:** This project is developed entirely for simulation and educational purposes. All data is generated locally using `src/generate_data.py`. It does not connect to real smart meters, power grids, SCADA systems, or other infrastructure. It only processes CSV files and cannot control any physical device.

## Project Objectives

The project focuses on the following areas:

| Objective | Implementation |
|---|---|
| Generate smart-grid telemetry | `src/generate_data.py` |
| Analyse normal electricity consumption | `detection.add_scores()` |
| Identify unusual meter readings | `detection.detect_telemetry()` |
| Detect suspicious communication activity | `detection.detect_telemetry()` |
| Identify unusual administrator activities | `detection.detect_admin()` |
| Connect related security events | `src/correlation.py` |
| Display affected devices and incidents | Streamlit dashboard |
| Generate incident reports | `src/report.py` |
| Store simulated scenarios and datasets | `data/` and `docs/scenarios.md` |

## Project Structure

The project is organised into different folders so that data generation, detection, correlation, and reporting can be managed separately.

```text
smart_grid_monitor/
│
├── app.py
├── run_pipeline.py
├── requirements.txt
│
├── src/
│   ├── config.py
│   ├── generate_data.py
│   ├── detection.py
│   ├── correlation.py
│   └── report.py
│
├── data/
│   └── Generated CSV files
│
├── reports/
│   └── incident_report.md
│
├── docs/
│   ├── scenarios.md
│   └── limitations.md
│
└── tests/
    └── test_pipeline.py
```

### File Description

- **app.py:** Contains the Streamlit dashboard where detected incidents, affected assets, and other results are displayed.
- **run_pipeline.py:** Runs the complete detection process from the terminal.
- **config.py:** Stores project settings, detection thresholds, and other configurations.
- **generate_data.py:** Generates synthetic smart-meter readings, gateway logs, administrator activities, and simulated attack scenarios.
- **detection.py:** Analyses the generated data and identifies unusual patterns using statistical methods, Isolation Forest, and predefined security rules.
- **correlation.py:** Connects related events and groups them into incidents based on their location and occurrence time.
- **report.py:** Creates a Markdown report containing information about detected incidents.
- **data/:** Stores the generated CSV datasets.
- **docs/:** Contains information about simulated scenarios and known limitations.
- **tests/:** Contains tests used to check the main project functionality.

## Installation and Setup

To run this project on your local machine, you need Python 3.9 or above.

### 1. Clone the Repository

```bash
git clone <your-github-repository-link>
cd smart_grid_monitor
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Environment

For Windows:

```powershell
venv\Scripts\activate
```

For Linux or macOS:

```bash
source venv/bin/activate
```

### 4. Install Required Libraries

```bash
pip install -r requirements.txt
```

### 5. Run the Detection Pipeline

```bash
python run_pipeline.py
```

This runs the analysis process, displays the detected incidents in the terminal, and generates an incident report.

### 6. Start the Dashboard

```bash
streamlit run app.py
```

The dashboard will open in your browser.

### 7. Run Tests (Optional)

```bash
pytest
```

To generate a new set of synthetic data, run:

```bash
python -m src.generate_data
```

## How Does the Detection System Work?

The project uses a combination of statistical analysis, machine learning, and predefined security rules to identify suspicious activities.

### 1. Establishing a Normal Behaviour Baseline

Before detecting unusual activities, the system needs to understand what normal behaviour looks like.

For this, the first 10 days of generated data are used to calculate the average behaviour of each meter for different hours of the day.

For example, electricity consumption at 10 AM may normally be different from consumption at 2 AM. Therefore, the system maintains separate baseline values for each meter and hour.

New readings are compared against these baseline values to identify unusual changes.

### 2. Z-Score Based Detection

The system uses the Z-score method to understand how far a reading is from its normal value.

It considers the normal variation in the readings and identifies values that are significantly different.

In this project, a reading is flagged when its absolute Z-score is greater than 5. The threshold can also be adjusted through the dashboard sidebar.

### 3. Isolation Forest

Along with statistical detection, the project uses the Isolation Forest algorithm to identify unusual patterns.

The model is trained using baseline data and checks whether new readings behave differently from the patterns it has learned.

This provides an additional way to identify anomalies and compare the results with the Z-score method.

### 4. Administrator Activity Monitoring

The project also checks administrator and gateway logs to identify activities that may require further investigation.

Some of the conditions considered include:

- Login attempts from external IP addresses.
- Administrator activity during unusual hours.
- Use of privileged accounts and actions.
- Multiple failed login attempts within a short period.

The system assigns risk points to these activities based on the configured rules.

### 5. Event Correlation

Detecting individual anomalies is useful, but understanding how different events are connected is equally important.

The correlation module groups suspicious events based on their substation and occurrence time.

For example, if unusual administrator activity is detected on a gateway and several meters in the same substation start showing abnormal communication behaviour within the following three hours, the system can associate these events with the same incident.

The incident severity is calculated using factors such as:

- Number of affected meters.
- Types of detected anomalies.
- Duration of the suspicious activity.
- Involvement of administrator or gateway events.

This helps organise individual alerts into incidents that are easier to investigate.

## Sample Detection Results

During testing with the generated datasets, the system produced the following sample incidents:

| Incident ID | Severity | Description |
|---|---|---|
| INC-001 | Critical | Suspicious administrator activity on GW-03 followed by unusual traffic patterns across three meters in SS-03. |
| INC-002 | High | An unusual voltage drop was detected across all 15 meters in SS-02. |
| INC-003 | High | Meter M-007 in SS-01 reported significantly lower readings than its normal consumption pattern. |
| INC-004 | Low | Multiple failed login attempts were detected on GW-04 in SS-04. |

These incidents are generated through predefined simulation scenarios. They are examples of how the platform groups and presents suspicious activities, not evidence of real-world attacks.

## Dashboard Features

The project includes a Streamlit dashboard to make the analysis easier to understand.

The dashboard contains the following sections:

- **Asset Map:** Displays the simulated infrastructure and helps identify affected devices and substations.
- **Incidents:** Shows detected incidents along with their severity and related events.
- **Investigation Recommendations:** Provides suggestions for checking suspicious activities.
- **About:** Explains the purpose of the project, its simulation-based nature, and its limitations.

The dashboard also provides access to the generated incident report.

## Incident Report

After analysing the generated data, the system creates an incident report in Markdown format.

The report contains information about detected incidents, their severity, affected assets, and related suspicious activities.

**Report location:**

```text
reports/incident_report.md
```

The report can also be downloaded directly from the dashboard.

## Limitations and Future Improvements

While developing this project, I also identified some limitations that should be considered.

- The project uses synthetic datasets, which are generally cleaner and more predictable than real-world smart-grid data.
- Detection thresholds were configured and tested using the generated datasets. They may not work equally well with real infrastructure data.
- The current event correlation mainly depends on substation and time information.
- Incident severity is calculated using a rule-based score and should not be treated as a confirmed measure of actual risk.
- Isolation Forest and statistical detection can produce false positives or miss certain unusual activities.

### Possible Future Improvements

Some areas that could be improved in future versions include:

- Testing with more diverse and realistic datasets.
- Improving event correlation by including additional device and network information.
- Adding more detection rules for suspicious administrator and gateway activities.
- Improving incident severity calculation.
- Exploring additional machine learning techniques for anomaly detection.

## Project Disclaimer

This project was created for learning, experimentation, and cybersecurity research purposes.

All smart-meter readings, gateway activities, administrator logs, and attack scenarios are simulated.

The platform only reads and analyses locally generated CSV files. It does not connect to, scan, access, or modify real power grids, smart meters, SCADA systems, or industrial control systems.

The detection results are intended for demonstration and educational purposes only.
```

**Note:** Before publishing, replace `<your-github-repository-link>` with your actual repository URL and verify that the described dashboard tabs and detection functions exist in your code.