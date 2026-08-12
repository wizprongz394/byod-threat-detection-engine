# V3.1 Benchmark Policy

## Objective

Establish a controlled evaluation framework for comparing Stable V2 and future V3 implementations.

## Training Data

Training data must contain benign traffic only.

The training dataset is used to establish the normal behavioural baseline.

## Validation Data

Validation data is used during V3 development for feature, model, and threshold decisions.

Validation captures must remain separate from the final test set.

## Test Data

The test dataset is reserved for final evaluation.

The existing attack corpus consists of one PCAP per attack scenario. Therefore the complete attack PCAPs will remain intact and will be evaluated as independent test scenarios.

## Attack Data

The existing ten attack PCAPs will not be split at the flow level.

Each attack PCAP remains an indivisible evaluation unit.

## Data Leakage Prevention

Packets or flows from the same PCAP must not be distributed across different benchmark splits.

Scaler and model parameters must be fitted using training data only.

Validation and test data must never be used to fit the scaler or model.

## Ground Truth

Ground truth is explicitly represented in the benchmark manifest.

Benign traffic is labelled `benign`.

Attack traffic is labelled `attack`.

Attack scenario information is stored separately in the `attack_type` field.

## Stable V2 Preservation

The Stable V2 implementation and frozen baseline artifacts must not be modified as part of benchmark construction.

V3.1 evaluation infrastructure must remain separate from the Stable V2 baseline.