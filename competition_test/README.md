# Advanced Network Intrusion Detection System
## NetSec Lab Competition - SomSem 2025

This is a comprehensive solution for the NetSec Lab Competition featuring advanced machine learning techniques, hyperparameter optimization, and ensemble methods for detecting network threats in PCAP files.

## 🚀 Quick Start

### 1. Setup Environment
```bash
# Make setup script executable and run it
chmod +x setup.sh
./setup.sh
```

### 2. Prepare Training Data
Place these files in the project directory:
- `training_clean_mod.pcap`
- `flowkeys_training_labeled_enc.csv`
- `4tuple_bidi.json` (provided)

### 3. Train the Model
```bash
python3 train_model.py
```

### 4. Test Your Solution
```bash
# Test with validation script
python3 test_solution.py --pcap training_clean_mod.pcap

# Or test directly
./run.sh training_clean_mod.pcap
```

### 5. Competition Usage
```bash
./run.sh <test.pcap>
```

## 📁 File Structure

```
├── advanced_ids.py          # Main IDS implementation
├── run.sh                   # Competition execution script
├── train_model.py           # Pre-training script
├── test_solution.py         # Validation and testing
├── setup.sh                 # Environment setup
├── requirements.txt         # Python dependencies
├── 4tuple_bidi.json        # Go-Flows configuration
└── README.md               # This file
```

## 🧠 Advanced Features

### Machine Learning Models
- **Random Forest** with hyperparameter optimization
- **XGBoost** with advanced boosting parameters
- **Gradient Boosting** with custom learning rates
- **Neural Networks** with multiple architectures
- **Ensemble Methods** (Stacking and Voting)

### Feature Engineering
- **80+ Advanced Features** extracted from network flows
- **Temporal Features**: Flow duration, inter-arrival times, packet rates
- **Statistical Features**: Mean, std, skewness, kurtosis, entropy
- **Behavioral Features**: TCP flag analysis, connection patterns
- **Protocol Features**: Port analysis, service detection
- **IP Features**: Address type analysis, subnet detection

### Optimization Techniques
- **Randomized Search** for hyperparameter optimization
- **Stratified Cross-Validation** for robust evaluation
- **Custom Scoring Function** matching competition requirements
- **Class Balancing** to handle imbalanced datasets
- **Ensemble Stacking** for improved performance

## 🎯 Competition-Specific Features

### Threat Detection Categories
The system detects 8 types of network threats:
- **C1**: Distributed resource exhaustion attack (DDoS)
- **C2**: Horizontal network probing
- **C3**: Vertical service enumeration  
- **C4**: Remote code execution via service vulnerability
- **C5**: Amplified overload using exposed service
- **C6**: Connection slot saturation via slow requests
- **C7**: Malicious input to extract/manipulate data
- **C8**: Remote code execution via file-transfer service vulnerability

### Scoring Optimization
The model is optimized for the competition scoring system:
- **Correct prediction**: 0 points
- **False Positive**: 3 points penalty
- **Wrong attack class**: 1 point penalty
- **False Negative**: 40 points penalty (heavily penalized)

The system prioritizes **high recall** to minimize false negatives.

### Performance Requirements
- **Execution time**: < 600 seconds (with time penalties)
- **Memory efficient**: Optimized for large PCAP files
- **Format compliance**: Exact output format matching

## 🔧 Technical Implementation

### Flow Extraction
Uses Go-Flows with bidirectional 4-tuple keys:
- Source/Destination IP addresses
- Source/Destination ports
- 1000-second active and idle timeouts

### Feature Extraction Pipeline
```python
# Advanced feature extraction
features = NetworkFlowFeatureExtractor()
X = features.fit_transform(flow_data)

# Robust scaling
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
```

### Model Training Pipeline
```python
# Hyperparameter optimization
search = RandomizedSearchCV(
    model, param_distributions, 
    scoring=custom_competition_scorer,
    cv=StratifiedKFold(n_splits=5)
)

# Ensemble creation
ensemble = StackingClassifier(
    estimators=base_models,
    final_estimator=LogisticRegression()
)
```

## 📊 Performance Metrics

### Cross-Validation Results
The system reports multiple metrics:
- Competition scoring function (custom)
- Precision, Recall, F1-score per class
- Confusion matrix analysis
- Execution time benchmarks

### Expected Performance
Based on advanced ML techniques and feature engineering:
- **High Recall**: > 95% for attack detection
- **Balanced Precision**: Optimized for competition scoring
- **Fast Execution**: < 300 seconds typical runtime
- **Robust Predictions**: Handles various network patterns

## 🛠️ Troubleshooting

### Common Issues

**Go-Flows not found:**
```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go install github.com/CN-TU/go-flows/cmd/go-flows@latest
```

**Python dependencies:**
```bash
pip3 install --user -r requirements.txt
```

**Permission errors:**
```bash
chmod +x run.sh setup.sh
```

**Memory issues:**
- Reduce feature complexity in `NetworkFlowFeatureExtractor`
- Use smaller ensemble sizes
- Process PCAP files in chunks

### Validation Errors

**Output format issues:**
- Check column names match exactly
- Verify Binary_Label values are 0/1
- Ensure Attack_Type_enc uses correct labels

**Timing issues:**
- Pre-train model (don't train during execution)
- Optimize feature extraction
- Use efficient data structures

## 🏆 Competition Strategy

### Key Success Factors
1. **Minimize False Negatives**: 40-point penalty is severe
2. **Advanced Feature Engineering**: Better features > complex models
3. **Ensemble Methods**: Combine multiple model strengths
4. **Speed Optimization**: Pre-compute everything possible
5. **Format Compliance**: Exact specification matching

### Recommended Workflow
1. Analyze training data thoroughly
2. Engineer threat-specific features
3. Train multiple models with hyperparameter optimization
4. Create ensemble combining best performers
5. Validate extensively before submission
6. Test execution time limits

## 📝 Submission Checklist

- [ ] All required files present
- [ ] Model pre-trained (not training during execution)
- [ ] `run.sh` executable and working
- [ ] Output format matches competition requirements
- [ ] Execution time < 600 seconds
- [ ] Go-Flows configuration preserved
- [ ] Dependencies installable in evaluation environment
- [ ] Validation tests passing

## 📧 Support

For questions about this implementation:
1. Check the validation output with `test_solution.py`
2. Review the troubleshooting section
3. Examine the feature engineering in `advanced_ids.py`
4. Test with different PCAP files

## 🔬 Advanced Usage

### Custom Feature Engineering
Modify `NetworkFlowFeatureExtractor` to add domain-specific features:
```python
def _custom_threat_features(self, flow):
    # Add your custom threat detection logic
    return custom_features
```

### Model Experimentation
Add new models to the optimization pipeline:
```python
models_config['custom_model'] = {
    'model': YourCustomModel(),
    'params': your_param_grid
}
```

### Performance Tuning
For different hardware configurations:
- Adjust `n_jobs` parameters for parallelization
- Modify `n_iter` in RandomizedSearchCV for speed/accuracy trade-off
- Tune ensemble size for memory constraints

---

**Good luck with the competition! 🚀**
