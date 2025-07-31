# AI Integration Guide

Comprehensive guide for integrating and developing AI/ML components within the Metasploit-AI framework.

## Table of Contents

1. [AI System Overview](#ai-system-overview)
2. [Model Architecture](#model-architecture)
3. [Training Data Management](#training-data-management)
4. [Model Development](#model-development)
5. [Model Integration](#model-integration)
6. [Feature Engineering](#feature-engineering)
7. [Model Evaluation](#model-evaluation)
8. [Production Deployment](#production-deployment)
9. [Model Monitoring](#model-monitoring)
10. [Performance Optimization](#performance-optimization)
11. [Custom AI Components](#custom-ai-components)
12. [Best Practices](#best-practices)

## AI System Overview

The Metasploit-AI framework incorporates multiple AI/ML components to enhance penetration testing capabilities through intelligent automation, pattern recognition, and predictive analysis.

### Core AI Components

```
┌─────────────────────────────────────────────────────┐
│                  AI Engine Core                     │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │Vulnerability│  │   Exploit   │  │   Payload   │ │
│  │  Analyzer   │  │Recommender  │  │ Generator   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │    Risk     │  │   Pattern   │  │   Anomaly   │ │
│  │  Assessor   │  │  Detector   │  │  Detector   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Model     │  │   Feature   │  │    Data     │ │
│  │  Manager    │  │ Extractor   │  │ Processor   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────┘
```

### AI Integration Points

**1. Vulnerability Analysis**
- CVE severity prediction
- Exploitability assessment
- Impact analysis
- Risk scoring

**2. Exploit Recommendation**
- Success probability calculation
- Payload compatibility matching
- Target environment analysis
- Attack path optimization

**3. Payload Generation**
- Evasion technique selection
- Polymorphic code generation
- Anti-analysis features
- Stealth optimization

**4. Behavioral Analysis**
- Network traffic patterns
- System behavior anomalies
- Defense mechanism detection
- Lateral movement planning

## Model Architecture

### AI Engine Core Implementation

```python
from typing import Dict, Any, List, Optional, Union
import logging
import numpy as np
import pandas as pd
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

class ModelType(Enum):
    """Types of AI models supported."""
    CLASSIFICATION = "classification"
    REGRESSION = "regression"
    CLUSTERING = "clustering"
    REINFORCEMENT = "reinforcement"
    GENERATIVE = "generative"

@dataclass
class ModelMetadata:
    """Metadata for AI models."""
    name: str
    version: str
    model_type: ModelType
    input_features: List[str]
    output_classes: List[str]
    accuracy: float
    training_date: str
    model_path: str

class AIModel(ABC):
    """Base class for AI models."""
    
    def __init__(self, metadata: ModelMetadata):
        self.metadata = metadata
        self.model = None
        self.scaler = None
        self.encoder = None
        self.is_loaded = False
        self.logger = logging.getLogger(f"ai.{metadata.name}")
    
    @abstractmethod
    def load(self) -> bool:
        """Load the model from storage."""
        pass
    
    @abstractmethod
    def predict(self, input_data: Union[np.ndarray, pd.DataFrame]) -> Any:
        """Make predictions using the model."""
        pass
    
    @abstractmethod
    def train(self, training_data: pd.DataFrame, labels: np.ndarray) -> Dict[str, float]:
        """Train the model."""
        pass
    
    def preprocess(self, data: Union[Dict, pd.DataFrame]) -> np.ndarray:
        """Preprocess input data."""
        if isinstance(data, dict):
            data = pd.DataFrame([data])
        
        # Apply scaling if available
        if self.scaler:
            data = self.scaler.transform(data)
        
        return data
    
    def postprocess(self, predictions: np.ndarray) -> Dict[str, Any]:
        """Postprocess model predictions."""
        return {"predictions": predictions.tolist()}

class AIEngine:
    """Central AI engine managing all ML components."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models: Dict[str, AIModel] = {}
        self.feature_extractors: Dict[str, 'FeatureExtractor'] = {}
        self.data_processors: Dict[str, 'DataProcessor'] = {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize model registry
        self.model_registry = ModelRegistry(config.get('model_path', './models'))
        
        # Initialize feature store
        self.feature_store = FeatureStore(config.get('feature_store', {}))
    
    def load_models(self) -> bool:
        """Load all configured AI models."""
        model_configs = self.config.get('models', {})
        
        for model_name, model_config in model_configs.items():
            try:
                model = self._create_model(model_name, model_config)
                if model.load():
                    self.models[model_name] = model
                    self.logger.info(f"Loaded model: {model_name}")
                else:
                    self.logger.error(f"Failed to load model: {model_name}")
                    
            except Exception as e:
                self.logger.error(f"Error loading model {model_name}: {e}")
        
        return len(self.models) > 0
    
    def get_model(self, model_name: str) -> Optional[AIModel]:
        """Get a loaded model by name."""
        return self.models.get(model_name)
    
    def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability using AI models."""
        vuln_analyzer = self.get_model('vulnerability_analyzer')
        if not vuln_analyzer:
            raise RuntimeError("Vulnerability analyzer model not loaded")
        
        # Extract features
        features = self._extract_vulnerability_features(vuln_data)
        
        # Make prediction
        prediction = vuln_analyzer.predict(features)
        
        # Enhance with risk assessment
        risk_assessment = self._assess_risk(vuln_data, prediction)
        
        return {
            'vulnerability_id': vuln_data.get('cve_id'),
            'ai_analysis': prediction,
            'risk_assessment': risk_assessment,
            'confidence': prediction.get('confidence', 0.0),
            'recommendations': self._generate_recommendations(vuln_data, prediction)
        }
    
    def recommend_exploits(self, target: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recommend exploits using AI."""
        exploit_recommender = self.get_model('exploit_recommender')
        if not exploit_recommender:
            raise RuntimeError("Exploit recommender model not loaded")
        
        recommendations = []
        
        for vuln in vulnerabilities:
            # Extract features for recommendation
            features = self._extract_exploit_features(target, vuln)
            
            # Get recommendations
            prediction = exploit_recommender.predict(features)
            
            recommendations.append({
                'vulnerability': vuln,
                'exploits': prediction.get('recommended_exploits', []),
                'success_probability': prediction.get('success_probability', 0.0),
                'difficulty': prediction.get('difficulty', 'unknown'),
                'impact': prediction.get('impact', 'unknown')
            })
        
        # Sort by success probability
        recommendations.sort(key=lambda x: x['success_probability'], reverse=True)
        
        return recommendations
    
    def generate_payload(self, exploit_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate optimized payload using AI."""
        payload_generator = self.get_model('payload_generator')
        if not payload_generator:
            raise RuntimeError("Payload generator model not loaded")
        
        # Extract features for payload generation
        features = self._extract_payload_features(exploit_config)
        
        # Generate payload
        generation_result = payload_generator.predict(features)
        
        return {
            'payload_type': generation_result.get('payload_type'),
            'payload_data': generation_result.get('payload_data'),
            'evasion_techniques': generation_result.get('evasion_techniques', []),
            'estimated_success_rate': generation_result.get('success_rate', 0.0),
            'stealth_score': generation_result.get('stealth_score', 0.0)
        }
```

### Vulnerability Analyzer Model

```python
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pandas as pd
import numpy as np

class VulnerabilityAnalyzer(AIModel):
    """AI model for vulnerability analysis and severity prediction."""
    
    def __init__(self, metadata: ModelMetadata):
        super().__init__(metadata)
        self.feature_columns = [
            'cvss_base_score', 'cvss_impact_score', 'cvss_exploitability_score',
            'age_days', 'public_exploits_count', 'affected_products_count',
            'cwe_category', 'attack_vector', 'attack_complexity',
            'privileges_required', 'user_interaction', 'scope',
            'confidentiality_impact', 'integrity_impact', 'availability_impact'
        ]
    
    def load(self) -> bool:
        """Load the vulnerability analyzer model."""
        try:
            model_path = self.metadata.model_path
            
            # Load TensorFlow model
            self.model = tf.keras.models.load_model(f"{model_path}/vuln_analyzer.h5")
            
            # Load preprocessing components
            import joblib
            self.scaler = joblib.load(f"{model_path}/scaler.pkl")
            self.label_encoder = joblib.load(f"{model_path}/label_encoder.pkl")
            
            self.is_loaded = True
            self.logger.info("Vulnerability analyzer model loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load vulnerability analyzer: {e}")
            return False
    
    def predict(self, input_data: Union[np.ndarray, pd.DataFrame]) -> Dict[str, Any]:
        """Predict vulnerability characteristics."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded")
        
        # Preprocess input
        processed_data = self.preprocess(input_data)
        
        # Make prediction
        predictions = self.model.predict(processed_data)
        
        # Extract predictions
        severity_probs = predictions[0]
        exploitability_score = predictions[1][0]
        impact_score = predictions[2][0]
        
        # Determine severity class
        severity_classes = ['Low', 'Medium', 'High', 'Critical']
        predicted_severity = severity_classes[np.argmax(severity_probs)]
        confidence = float(np.max(severity_probs))
        
        return {
            'predicted_severity': predicted_severity,
            'confidence': confidence,
            'severity_probabilities': {
                class_name: float(prob)
                for class_name, prob in zip(severity_classes, severity_probs)
            },
            'exploitability_score': float(exploitability_score),
            'impact_score': float(impact_score),
            'risk_score': self._calculate_risk_score(exploitability_score, impact_score),
            'recommendations': self._generate_vuln_recommendations(predicted_severity, confidence)
        }
    
    def train(self, training_data: pd.DataFrame, labels: np.ndarray) -> Dict[str, float]:
        """Train the vulnerability analyzer model."""
        # Prepare features
        X = training_data[self.feature_columns]
        
        # Preprocess features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Prepare labels
        self.label_encoder = LabelEncoder()
        y_severity = self.label_encoder.fit_transform(labels['severity'])
        y_exploitability = labels['exploitability_score'].values
        y_impact = labels['impact_score'].values
        
        # Build model architecture
        self.model = self._build_model(X_scaled.shape[1])
        
        # Train model
        history = self.model.fit(
            X_scaled,
            [
                tf.keras.utils.to_categorical(y_severity, num_classes=4),
                y_exploitability,
                y_impact
            ],
            epochs=100,
            batch_size=32,
            validation_split=0.2,
            verbose=1
        )
        
        # Calculate metrics
        final_loss = history.history['loss'][-1]
        final_accuracy = history.history['severity_output_accuracy'][-1]
        
        return {
            'final_loss': final_loss,
            'final_accuracy': final_accuracy,
            'training_epochs': len(history.history['loss'])
        }
    
    def _build_model(self, input_dim: int) -> tf.keras.Model:
        """Build neural network architecture."""
        inputs = tf.keras.layers.Input(shape=(input_dim,))
        
        # Shared layers
        x = tf.keras.layers.Dense(128, activation='relu')(inputs)
        x = tf.keras.layers.Dropout(0.3)(x)
        x = tf.keras.layers.Dense(64, activation='relu')(x)
        x = tf.keras.layers.Dropout(0.3)(x)
        x = tf.keras.layers.Dense(32, activation='relu')(x)
        
        # Severity classification output
        severity_output = tf.keras.layers.Dense(4, activation='softmax', name='severity_output')(x)
        
        # Exploitability regression output
        exploitability_output = tf.keras.layers.Dense(1, activation='sigmoid', name='exploitability_output')(x)
        
        # Impact regression output
        impact_output = tf.keras.layers.Dense(1, activation='sigmoid', name='impact_output')(x)
        
        model = tf.keras.Model(
            inputs=inputs,
            outputs=[severity_output, exploitability_output, impact_output]
        )
        
        model.compile(
            optimizer='adam',
            loss={
                'severity_output': 'categorical_crossentropy',
                'exploitability_output': 'mse',
                'impact_output': 'mse'
            },
            metrics={
                'severity_output': ['accuracy'],
                'exploitability_output': ['mae'],
                'impact_output': ['mae']
            }
        )
        
        return model
    
    def _calculate_risk_score(self, exploitability: float, impact: float) -> float:
        """Calculate overall risk score."""
        return float((exploitability * 0.6 + impact * 0.4) * 10)
    
    def _generate_vuln_recommendations(self, severity: str, confidence: float) -> List[str]:
        """Generate vulnerability-specific recommendations."""
        recommendations = []
        
        if severity in ['Critical', 'High'] and confidence > 0.8:
            recommendations.append("Immediate patching required")
            recommendations.append("Implement temporary mitigations")
            recommendations.append("Monitor for active exploitation")
        elif severity in ['Medium', 'High']:
            recommendations.append("Schedule patching within maintenance window")
            recommendations.append("Assess exploit availability")
            recommendations.append("Review access controls")
        else:
            recommendations.append("Monitor for updates")
            recommendations.append("Consider patching during next cycle")
        
        return recommendations
```

### Exploit Recommender System

```python
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd
import numpy as np

class ExploitRecommender(AIModel):
    """AI-powered exploit recommendation system."""
    
    def __init__(self, metadata: ModelMetadata):
        super().__init__(metadata)
        self.exploit_database = None
        self.similarity_matrix = None
        self.tfidf_vectorizer = None
        self.success_predictor = None
    
    def load(self) -> bool:
        """Load exploit recommender components."""
        try:
            import joblib
            model_path = self.metadata.model_path
            
            # Load exploit database
            self.exploit_database = pd.read_csv(f"{model_path}/exploit_database.csv")
            
            # Load similarity matrix
            self.similarity_matrix = np.load(f"{model_path}/similarity_matrix.npy")
            
            # Load TF-IDF vectorizer
            self.tfidf_vectorizer = joblib.load(f"{model_path}/tfidf_vectorizer.pkl")
            
            # Load success prediction model
            self.success_predictor = joblib.load(f"{model_path}/success_predictor.pkl")
            
            self.is_loaded = True
            self.logger.info("Exploit recommender loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load exploit recommender: {e}")
            return False
    
    def predict(self, input_data: Union[np.ndarray, pd.DataFrame]) -> Dict[str, Any]:
        """Recommend exploits for given vulnerability and target."""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded")
        
        # Extract target and vulnerability information
        if isinstance(input_data, pd.DataFrame):
            features = input_data.iloc[0].to_dict()
        else:
            features = input_data
        
        vulnerability_cve = features.get('cve_id')
        target_os = features.get('target_os')
        target_arch = features.get('target_arch')
        target_services = features.get('target_services', [])
        
        # Find applicable exploits
        applicable_exploits = self._find_applicable_exploits(
            vulnerability_cve, target_os, target_arch, target_services
        )
        
        # Calculate success probabilities
        recommendations = []
        for exploit in applicable_exploits:
            success_prob = self._predict_success_probability(exploit, features)
            difficulty = self._assess_difficulty(exploit, features)
            
            recommendations.append({
                'exploit_name': exploit['name'],
                'exploit_id': exploit['id'],
                'success_probability': success_prob,
                'difficulty': difficulty,
                'description': exploit['description'],
                'requirements': exploit.get('requirements', []),
                'payloads': exploit.get('compatible_payloads', []),
                'risk_level': self._assess_risk_level(exploit, success_prob)
            })
        
        # Sort by success probability
        recommendations.sort(key=lambda x: x['success_probability'], reverse=True)
        
        return {
            'recommended_exploits': recommendations[:10],  # Top 10
            'total_found': len(applicable_exploits),
            'analysis_confidence': self._calculate_confidence(recommendations),
            'target_compatibility': self._assess_target_compatibility(features)
        }
    
    def train(self, training_data: pd.DataFrame, labels: np.ndarray) -> Dict[str, float]:
        """Train the exploit recommender system."""
        # Build exploit database from training data
        self.exploit_database = training_data.copy()
        
        # Create TF-IDF vectors for exploit descriptions
        descriptions = training_data['description'].fillna('')
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            lowercase=True
        )
        tfidf_matrix = self.tfidf_vectorizer.fit_transform(descriptions)
        
        # Calculate similarity matrix
        self.similarity_matrix = cosine_similarity(tfidf_matrix)
        
        # Train success predictor
        feature_columns = [
            'target_os_match', 'target_arch_match', 'service_overlap',
            'exploit_complexity', 'exploit_reliability', 'target_patched'
        ]
        
        X = training_data[feature_columns]
        y = labels  # Success/failure labels
        
        from sklearn.ensemble import GradientBoostingClassifier
        self.success_predictor = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5
        )
        self.success_predictor.fit(X, y)
        
        # Calculate training metrics
        training_accuracy = self.success_predictor.score(X, y)
        
        return {
            'training_accuracy': training_accuracy,
            'exploit_count': len(self.exploit_database),
            'feature_count': len(feature_columns)
        }
    
    def _find_applicable_exploits(self, cve_id: str, target_os: str, 
                                target_arch: str, target_services: List[str]) -> List[Dict]:
        """Find exploits applicable to the target."""
        applicable = []
        
        for _, exploit in self.exploit_database.iterrows():
            # Check CVE compatibility
            if cve_id and cve_id in exploit.get('cve_list', []):
                score = 1.0
            else:
                score = 0.5
            
            # Check OS compatibility
            if target_os and target_os.lower() in exploit.get('target_os', '').lower():
                score += 0.3
            
            # Check architecture compatibility
            if target_arch and target_arch in exploit.get('target_arch', []):
                score += 0.2
            
            # Check service compatibility
            exploit_services = exploit.get('target_services', [])
            service_overlap = len(set(target_services) & set(exploit_services))
            if service_overlap > 0:
                score += 0.2 * service_overlap
            
            if score >= 0.7:  # Threshold for applicability
                applicable.append(exploit.to_dict())
        
        return applicable
    
    def _predict_success_probability(self, exploit: Dict, target_features: Dict) -> float:
        """Predict exploitation success probability."""
        # Prepare features for prediction
        features = {
            'target_os_match': 1 if target_features.get('target_os', '').lower() in exploit.get('target_os', '').lower() else 0,
            'target_arch_match': 1 if target_features.get('target_arch') in exploit.get('target_arch', []) else 0,
            'service_overlap': len(set(target_features.get('target_services', [])) & set(exploit.get('target_services', []))),
            'exploit_complexity': exploit.get('complexity_score', 0.5),
            'exploit_reliability': exploit.get('reliability_score', 0.5),
            'target_patched': target_features.get('patched', 0)
        }
        
        feature_array = np.array([[
            features['target_os_match'],
            features['target_arch_match'],
            features['service_overlap'],
            features['exploit_complexity'],
            features['exploit_reliability'],
            features['target_patched']
        ]])
        
        # Predict success probability
        prob = self.success_predictor.predict_proba(feature_array)[0][1]  # Probability of success
        
        return float(prob)
    
    def _assess_difficulty(self, exploit: Dict, target_features: Dict) -> str:
        """Assess exploitation difficulty."""
        complexity = exploit.get('complexity_score', 0.5)
        reliability = exploit.get('reliability_score', 0.5)
        
        difficulty_score = (complexity + (1 - reliability)) / 2
        
        if difficulty_score < 0.3:
            return 'Easy'
        elif difficulty_score < 0.6:
            return 'Medium'
        else:
            return 'Hard'
    
    def _assess_risk_level(self, exploit: Dict, success_prob: float) -> str:
        """Assess risk level of using the exploit."""
        stealth_score = exploit.get('stealth_score', 0.5)
        impact_score = exploit.get('impact_score', 0.5)
        
        risk_score = (1 - stealth_score) * 0.4 + impact_score * 0.6
        
        if success_prob > 0.8 and risk_score < 0.4:
            return 'Low'
        elif success_prob > 0.6 and risk_score < 0.6:
            return 'Medium'
        else:
            return 'High'
```

## Training Data Management

### Data Collection and Preparation

```python
class TrainingDataManager:
    """Manages training data collection and preparation."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_sources = {}
        self.data_validators = {}
        self.logger = logging.getLogger(__name__)
    
    def collect_vulnerability_data(self) -> pd.DataFrame:
        """Collect vulnerability data from multiple sources."""
        sources = [
            CVEDataSource(),
            NVDDataSource(),
            ExploitDBDataSource(),
            CustomDataSource(self.config.get('custom_sources', []))
        ]
        
        all_data = []
        for source in sources:
            try:
                data = source.fetch_data()
                validated_data = self._validate_data(data, 'vulnerability')
                all_data.append(validated_data)
                self.logger.info(f"Collected {len(validated_data)} records from {source.name}")
            except Exception as e:
                self.logger.error(f"Failed to collect data from {source.name}: {e}")
        
        if all_data:
            combined_data = pd.concat(all_data, ignore_index=True)
            return self._deduplicate_data(combined_data)
        else:
            return pd.DataFrame()
    
    def prepare_training_data(self, raw_data: pd.DataFrame, 
                            target_column: str) -> tuple[pd.DataFrame, np.ndarray]:
        """Prepare data for model training."""
        # Clean data
        cleaned_data = self._clean_data(raw_data)
        
        # Feature engineering
        engineered_data = self._engineer_features(cleaned_data)
        
        # Handle missing values
        complete_data = self._handle_missing_values(engineered_data)
        
        # Split features and targets
        features = complete_data.drop(columns=[target_column])
        targets = complete_data[target_column].values
        
        return features, targets
    
    def _validate_data(self, data: pd.DataFrame, data_type: str) -> pd.DataFrame:
        """Validate data quality and consistency."""
        validator = self.data_validators.get(data_type)
        if validator:
            return validator.validate(data)
        return data
    
    def _clean_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Clean and standardize data."""
        # Remove duplicates
        data = data.drop_duplicates()
        
        # Standardize text fields
        text_columns = data.select_dtypes(include=['object']).columns
        for col in text_columns:
            if col in data.columns:
                data[col] = data[col].str.lower().str.strip()
        
        # Remove outliers (using IQR method)
        numeric_columns = data.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            Q1 = data[col].quantile(0.25)
            Q3 = data[col].quantile(0.75)
            IQR = Q3 - Q1
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR
            data = data[(data[col] >= lower_bound) & (data[col] <= upper_bound)]
        
        return data
    
    def _engineer_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Create engineered features."""
        # Example: Create age feature from publication date
        if 'published_date' in data.columns:
            data['published_date'] = pd.to_datetime(data['published_date'])
            data['age_days'] = (pd.Timestamp.now() - data['published_date']).dt.days
        
        # Example: Create complexity score from description
        if 'description' in data.columns:
            data['description_length'] = data['description'].str.len()
            data['has_poc'] = data['description'].str.contains('proof.of.concept|poc', case=False, na=False)
        
        # Example: Create categorical features
        if 'cvss_vector' in data.columns:
            data['attack_vector'] = data['cvss_vector'].str.extract(r'AV:([NLAPR])')
            data['attack_complexity'] = data['cvss_vector'].str.extract(r'AC:([LH])')
        
        return data

class CVEDataSource:
    """Data source for CVE information."""
    
    def __init__(self):
        self.name = "CVE Database"
        self.base_url = "https://cve.mitre.org/data/downloads/"
    
    def fetch_data(self) -> pd.DataFrame:
        """Fetch CVE data."""
        # Implementation to fetch CVE data
        # This is a simplified example
        import requests
        
        # Fetch recent CVEs
        response = requests.get(f"{self.base_url}/allitems.csv")
        data = pd.read_csv(response.content)
        
        # Standardize column names
        data.columns = [col.lower().replace(' ', '_') for col in data.columns]
        
        return data

class FeatureStore:
    """Feature store for ML features."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.features = {}
        self.feature_groups = {}
        
    def register_feature_group(self, name: str, features: List[str], 
                             extractor: 'FeatureExtractor') -> None:
        """Register a group of related features."""
        self.feature_groups[name] = {
            'features': features,
            'extractor': extractor
        }
    
    def extract_features(self, data: Dict[str, Any], 
                        feature_groups: List[str] = None) -> pd.DataFrame:
        """Extract features for given data."""
        if feature_groups is None:
            feature_groups = list(self.feature_groups.keys())
        
        all_features = {}
        
        for group_name in feature_groups:
            if group_name in self.feature_groups:
                group = self.feature_groups[group_name]
                extractor = group['extractor']
                features = extractor.extract(data)
                all_features.update(features)
        
        return pd.DataFrame([all_features])
```

## Model Evaluation

### Evaluation Framework

```python
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from sklearn.model_selection import cross_val_score, StratifiedKFold
import matplotlib.pyplot as plt
import seaborn as sns

class ModelEvaluator:
    """Comprehensive model evaluation framework."""
    
    def __init__(self):
        self.metrics = {}
        self.plots = {}
        
    def evaluate_classification_model(self, model: AIModel, X_test: np.ndarray, 
                                    y_test: np.ndarray) -> Dict[str, float]:
        """Evaluate classification model performance."""
        predictions = model.predict(X_test)
        
        if isinstance(predictions, dict):
            y_pred = predictions.get('predictions', predictions.get('predicted_class'))
        else:
            y_pred = predictions
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }
        
        # Cross-validation scores
        if hasattr(model, 'model') and hasattr(model.model, 'predict'):
            cv_scores = cross_val_score(model.model, X_test, y_test, cv=5, scoring='accuracy')
            metrics['cv_mean'] = cv_scores.mean()
            metrics['cv_std'] = cv_scores.std()
        
        return metrics
    
    def evaluate_regression_model(self, model: AIModel, X_test: np.ndarray, 
                                y_test: np.ndarray) -> Dict[str, float]:
        """Evaluate regression model performance."""
        predictions = model.predict(X_test)
        
        if isinstance(predictions, dict):
            y_pred = predictions.get('predictions')
        else:
            y_pred = predictions
        
        metrics = {
            'mse': mean_squared_error(y_test, y_pred),
            'rmse': np.sqrt(mean_squared_error(y_test, y_pred)),
            'mae': mean_absolute_error(y_test, y_pred),
            'r2': r2_score(y_test, y_pred)
        }
        
        return metrics
    
    def create_evaluation_report(self, model: AIModel, test_data: Dict[str, np.ndarray]) -> Dict[str, Any]:
        """Create comprehensive evaluation report."""
        X_test = test_data['X']
        y_test = test_data['y']
        
        report = {
            'model_info': {
                'name': model.metadata.name,
                'type': model.metadata.model_type.value,
                'version': model.metadata.version
            }
        }
        
        # Performance metrics
        if model.metadata.model_type == ModelType.CLASSIFICATION:
            report['metrics'] = self.evaluate_classification_model(model, X_test, y_test)
            report['confusion_matrix'] = self._create_confusion_matrix(model, X_test, y_test)
        elif model.metadata.model_type == ModelType.REGRESSION:
            report['metrics'] = self.evaluate_regression_model(model, X_test, y_test)
            report['residual_analysis'] = self._analyze_residuals(model, X_test, y_test)
        
        # Feature importance (if available)
        if hasattr(model.model, 'feature_importances_'):
            report['feature_importance'] = self._analyze_feature_importance(model)
        
        # Model stability
        report['stability'] = self._assess_model_stability(model, X_test, y_test)
        
        return report
    
    def _create_confusion_matrix(self, model: AIModel, X_test: np.ndarray, 
                               y_test: np.ndarray) -> Dict[str, Any]:
        """Create confusion matrix for classification model."""
        from sklearn.metrics import confusion_matrix, classification_report
        
        predictions = model.predict(X_test)
        if isinstance(predictions, dict):
            y_pred = predictions.get('predictions', predictions.get('predicted_class'))
        else:
            y_pred = predictions
        
        cm = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred, output_dict=True)
        
        return {
            'matrix': cm.tolist(),
            'classification_report': class_report,
            'classes': list(set(y_test))
        }
    
    def _analyze_residuals(self, model: AIModel, X_test: np.ndarray, 
                         y_test: np.ndarray) -> Dict[str, Any]:
        """Analyze residuals for regression model."""
        predictions = model.predict(X_test)
        if isinstance(predictions, dict):
            y_pred = predictions.get('predictions')
        else:
            y_pred = predictions
        
        residuals = y_test - y_pred
        
        return {
            'mean_residual': float(np.mean(residuals)),
            'std_residual': float(np.std(residuals)),
            'residual_distribution': {
                'min': float(np.min(residuals)),
                'max': float(np.max(residuals)),
                'q25': float(np.percentile(residuals, 25)),
                'q50': float(np.percentile(residuals, 50)),
                'q75': float(np.percentile(residuals, 75))
            }
        }
    
    def _analyze_feature_importance(self, model: AIModel) -> List[Dict[str, Any]]:
        """Analyze feature importance."""
        importances = model.model.feature_importances_
        feature_names = model.metadata.input_features
        
        importance_data = [
            {'feature': name, 'importance': float(importance)}
            for name, importance in zip(feature_names, importances)
        ]
        
        # Sort by importance
        importance_data.sort(key=lambda x: x['importance'], reverse=True)
        
        return importance_data
    
    def _assess_model_stability(self, model: AIModel, X_test: np.ndarray, 
                              y_test: np.ndarray) -> Dict[str, float]:
        """Assess model stability through multiple evaluations."""
        # Add noise to test data and evaluate multiple times
        stability_scores = []
        
        for i in range(10):
            # Add small amount of noise
            noise = np.random.normal(0, 0.01, X_test.shape)
            X_noisy = X_test + noise
            
            try:
                predictions = model.predict(X_noisy)
                if isinstance(predictions, dict):
                    score = predictions.get('confidence', 0.5)
                else:
                    # Calculate a simple stability score
                    score = 1.0 - np.mean(np.abs(predictions - model.predict(X_test)))
                
                stability_scores.append(score)
            except:
                stability_scores.append(0.0)
        
        return {
            'mean_stability': float(np.mean(stability_scores)),
            'std_stability': float(np.std(stability_scores)),
            'min_stability': float(np.min(stability_scores)),
            'max_stability': float(np.max(stability_scores))
        }
```

## Production Deployment

### Model Deployment Pipeline

```python
class ModelDeploymentPipeline:
    """Pipeline for deploying AI models to production."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_registry = ModelRegistry(config)
        self.deployment_manager = DeploymentManager(config)
        
    def deploy_model(self, model: AIModel, deployment_config: Dict[str, Any]) -> bool:
        """Deploy model to production environment."""
        try:
            # Validate model
            if not self._validate_model_for_deployment(model):
                return False
            
            # Create deployment package
            package_path = self._create_deployment_package(model)
            
            # Deploy to target environment
            deployment_id = self.deployment_manager.deploy(package_path, deployment_config)
            
            # Run health checks
            if self._run_health_checks(deployment_id):
                self.model_registry.mark_as_deployed(model.metadata.name, deployment_id)
                return True
            else:
                self.deployment_manager.rollback(deployment_id)
                return False
                
        except Exception as e:
            logging.error(f"Deployment failed: {e}")
            return False
    
    def _validate_model_for_deployment(self, model: AIModel) -> bool:
        """Validate model is ready for deployment."""
        validations = [
            self._check_model_performance(model),
            self._check_model_security(model),
            self._check_model_compatibility(model),
            self._check_resource_requirements(model)
        ]
        
        return all(validations)
    
    def _create_deployment_package(self, model: AIModel) -> str:
        """Create deployment package for model."""
        import tempfile
        import shutil
        import os
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        package_dir = os.path.join(temp_dir, f"{model.metadata.name}_deployment")
        os.makedirs(package_dir)
        
        try:
            # Copy model files
            model_dir = os.path.join(package_dir, "model")
            shutil.copytree(model.metadata.model_path, model_dir)
            
            # Create metadata file
            metadata_file = os.path.join(package_dir, "metadata.json")
            with open(metadata_file, 'w') as f:
                import json
                json.dump(model.metadata.__dict__, f, indent=2, default=str)
            
            # Create deployment script
            deployment_script = os.path.join(package_dir, "deploy.py")
            self._create_deployment_script(deployment_script, model)
            
            # Create requirements file
            requirements_file = os.path.join(package_dir, "requirements.txt")
            self._create_requirements_file(requirements_file, model)
            
            # Create package archive
            package_path = f"{package_dir}.tar.gz"
            shutil.make_archive(package_dir, 'gztar', temp_dir, 
                              os.path.basename(package_dir))
            
            return package_path
            
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)

class ModelMonitor:
    """Monitor deployed models for performance and drift."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics_collector = MetricsCollector()
        self.drift_detector = DriftDetector()
        self.alert_manager = AlertManager(config)
        
    def monitor_model(self, model_name: str, prediction_data: Dict[str, Any]) -> None:
        """Monitor model predictions and performance."""
        # Collect metrics
        metrics = self._collect_prediction_metrics(prediction_data)
        self.metrics_collector.record(model_name, metrics)
        
        # Detect drift
        drift_score = self.drift_detector.detect_drift(model_name, prediction_data)
        
        # Check for anomalies
        anomalies = self._detect_anomalies(metrics)
        
        # Generate alerts if needed
        if drift_score > self.config.get('drift_threshold', 0.3):
            self.alert_manager.send_alert(f"Data drift detected for {model_name}", 
                                        {'drift_score': drift_score})
        
        if anomalies:
            self.alert_manager.send_alert(f"Performance anomalies for {model_name}", 
                                        {'anomalies': anomalies})
    
    def _collect_prediction_metrics(self, prediction_data: Dict[str, Any]) -> Dict[str, float]:
        """Collect metrics from prediction data."""
        return {
            'prediction_count': len(prediction_data.get('predictions', [])),
            'average_confidence': np.mean(prediction_data.get('confidences', [0])),
            'prediction_latency': prediction_data.get('latency', 0),
            'error_rate': prediction_data.get('error_rate', 0)
        }
    
    def _detect_anomalies(self, metrics: Dict[str, float]) -> List[str]:
        """Detect anomalies in metrics."""
        anomalies = []
        
        # Check confidence scores
        if metrics.get('average_confidence', 1.0) < 0.5:
            anomalies.append("Low confidence predictions")
        
        # Check latency
        if metrics.get('prediction_latency', 0) > 1000:  # 1 second
            anomalies.append("High prediction latency")
        
        # Check error rate
        if metrics.get('error_rate', 0) > 0.1:  # 10%
            anomalies.append("High error rate")
        
        return anomalies
```

## Best Practices

### AI Development Best Practices

```python
class AIBestPractices:
    """Collection of AI development best practices."""
    
    @staticmethod
    def validate_training_data(data: pd.DataFrame) -> Dict[str, Any]:
        """Validate training data quality."""
        issues = []
        
        # Check for sufficient data
        if len(data) < 1000:
            issues.append("Insufficient training data (< 1000 samples)")
        
        # Check for missing values
        missing_percentage = data.isnull().sum() / len(data) * 100
        high_missing = missing_percentage[missing_percentage > 20]
        if not high_missing.empty:
            issues.append(f"High missing values in columns: {list(high_missing.index)}")
        
        # Check for class imbalance
        if 'target' in data.columns:
            class_counts = data['target'].value_counts()
            imbalance_ratio = class_counts.max() / class_counts.min()
            if imbalance_ratio > 10:
                issues.append(f"Severe class imbalance (ratio: {imbalance_ratio:.2f})")
        
        # Check for data leakage
        if 'future_data' in data.columns:
            issues.append("Potential data leakage detected")
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'data_shape': data.shape,
            'missing_stats': missing_percentage.to_dict()
        }
    
    @staticmethod
    def implement_security_measures(model: AIModel) -> None:
        """Implement security measures for AI models."""
        # Input validation
        model.input_validator = InputValidator()
        
        # Output sanitization
        model.output_sanitizer = OutputSanitizer()
        
        # Rate limiting
        model.rate_limiter = RateLimiter(max_requests_per_minute=100)
        
        # Audit logging
        model.audit_logger = AuditLogger()
    
    @staticmethod
    def ensure_model_interpretability(model: AIModel) -> Dict[str, Any]:
        """Ensure model interpretability and explainability."""
        interpretability_features = {
            'feature_importance': hasattr(model.model, 'feature_importances_'),
            'local_explanations': False,  # LIME/SHAP integration
            'global_explanations': False,  # Global feature importance
            'decision_paths': False,       # Decision tree paths
            'attention_weights': False     # For neural networks
        }
        
        # Add SHAP explanations if available
        try:
            import shap
            model.explainer = shap.Explainer(model.model)
            interpretability_features['local_explanations'] = True
        except ImportError:
            pass
        
        return interpretability_features
    
    @staticmethod
    def implement_bias_detection(model: AIModel, test_data: pd.DataFrame) -> Dict[str, Any]:
        """Implement bias detection and fairness assessment."""
        bias_metrics = {}
        
        # Demographic parity
        if 'protected_attribute' in test_data.columns:
            predictions = model.predict(test_data.drop(columns=['target', 'protected_attribute']))
            
            for group in test_data['protected_attribute'].unique():
                group_data = test_data[test_data['protected_attribute'] == group]
                group_predictions = predictions[test_data['protected_attribute'] == group]
                
                bias_metrics[f'positive_rate_{group}'] = np.mean(group_predictions > 0.5)
        
        # Equalized odds
        # Implementation for equalized odds bias detection
        
        return bias_metrics
```

---

*This AI integration guide is part of the Metasploit-AI documentation suite. For more information, see the [Development Guide](development.md) or visit the [project repository](https://github.com/yashab-cyber/metasploit-ai).*

---

*Created by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team*
