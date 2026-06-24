#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    AI-SENTINEL PREMIUM v3.0 — Hybrid AI Threat Classification Engine
═══════════════════════════════════════════════════════════════════════════════

    This module implements a HYBRID AI APPROACH combining:
    
    1. SUPERVISED LEARNING (Random Forest Classifier)
       - Classifies services into 5 risk categories
       - Trained on cybersecurity domain knowledge
       
    2. UNSUPERVISED LEARNING (Isolation Forest)
       - Detects anomalous/unusual service patterns
       - Identifies unknown threats not in training data
       
    3. EXPLAINABLE AI (XAI)
       - Provides human-readable explanations for each classification
       - Shows feature importance and confidence scores
       
    4. HYBRID RISK SCORING
       - Combines supervised + unsupervised scores
       - Produces final intelligent risk assessment

    Author: AI-Sentinel Security Team
    Version: 3.0 Premium Edition
═══════════════════════════════════════════════════════════════════════════════
"""

import numpy as np
import pickle
import os
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


class AIThreatAnalyzer:
    """
    Hybrid AI Engine for Intelligent Threat Classification
    
    This class implements a state-of-the-art hybrid AI approach combining
    supervised classification with unsupervised anomaly detection for
    comprehensive cybersecurity threat assessment.
    """

    # ═══════════════════════════════════════════════════════════════════════
    # CYBERSECURITY KNOWLEDGE BASE
    # ═══════════════════════════════════════════════════════════════════════
    
    # Port Risk Database (Domain Expert Knowledge)
    PORT_RISK_DB = {
        # Safe ports (0)
        443: 0, 993: 0, 995: 0, 8443: 0, 465: 0,
        
        # Low risk (1)
        22: 1, 53: 1, 123: 1, 587: 1, 631: 1, 853: 1,
        
        # Medium risk (2)
        25: 2, 80: 2, 110: 2, 143: 2, 111: 2, 1723: 2,
        5432: 2, 6379: 2, 8080: 2, 27017: 2, 9090: 2,
        2049: 2, 3632: 2, 5000: 2, 8000: 2, 9200: 2,
        
        # High risk (3)
        21: 3, 135: 3, 139: 3, 445: 3, 1433: 3, 3306: 3,
        3389: 3, 5900: 3, 5985: 3, 1099: 3, 8180: 3,
        512: 3, 513: 3, 514: 3, 1521: 3, 5984: 3,
        
        # Critical risk (4)
        23: 4, 79: 4, 1080: 4, 1524: 4, 4444: 4, 5555: 4,
        6667: 4, 1337: 4, 27374: 4, 31337: 4, 6666: 4,
        9001: 4, 12345: 4, 65535: 4,
    }

    # Service Risk Database
    SERVICE_RISK_DB = {
        # Safe services
        'https': 0, 'imaps': 0, 'pop3s': 0, 'smtps': 0,
        
        # Low risk services
        'ssh': 1, 'domain': 1, 'ntp': 1, 'submission': 1,
        
        # Medium risk services
        'http': 2, 'smtp': 2, 'pop3': 2, 'imap': 2, 'dns': 2,
        'postgresql': 2, 'redis': 2, 'mongodb': 2, 'elasticsearch': 2,
        'http-proxy': 2, 'squid': 2, 'rpcbind': 2,
        
        # High risk services
        'ftp': 3, 'mysql': 3, 'ms-sql-s': 3, 'microsoft-ds': 3,
        'netbios-ssn': 3, 'rdp': 3, 'ms-wbt-server': 3, 'vnc': 3,
        'java-rmi': 3, 'ajp13': 3, 'oracle': 3, 'exec': 3,
        'login': 3, 'shell': 3, 'nfs': 3, 'distccd': 3,
        
        # Critical risk services
        'telnet': 4, 'finger': 4, 'irc': 4, 'ircd': 4,
        'ingreslock': 4, 'metasploit': 4, 'backdoor': 4,
        'trojan': 4, 'unknown': 2,
    }

    # Risk Labels
    RISK_LABELS = ['Safe', 'Low', 'Medium', 'High', 'Critical']
    
    # Risk Colors (for UI)
    RISK_COLORS = {
        'Safe': '#3b82f6',
        'Low': '#22c55e', 
        'Medium': '#eab308',
        'High': '#f59e0b',
        'Critical': '#ef4444'
    }

    # Feature Names (for explainability)
    FEATURE_NAMES = [
        'port_number',
        'is_well_known_port',
        'is_registered_port', 
        'is_dynamic_port',
        'port_risk_score',
        'service_risk_score',
        'is_tcp_protocol',
        'has_version_info',
        'is_backdoor_port',
        'is_database_port',
        'is_remote_access_port'
    ]

    # ═══════════════════════════════════════════════════════════════════════
    # INITIALIZATION
    # ═══════════════════════════════════════════════════════════════════════

    def __init__(self):
        """Initialize the Hybrid AI Engine"""
        
        # Supervised Learning Model
        self.rf_classifier = None
        
        # Unsupervised Learning Model  
        self.anomaly_detector = None
        
        # Feature Scaler
        self.scaler = StandardScaler()
        
        # Model State
        self.model_path = 'model/ai_sentinel_v3.pkl'
        self.is_trained = False
        self.accuracy = 0.0
        self.feature_importance = {}
        
        # Training Statistics
        self.training_stats = {
            'samples': 0,
            'accuracy': 0.0,
            'anomaly_contamination': 0.1,
            'trained_at': None
        }

    # ═══════════════════════════════════════════════════════════════════════
    # TRAINING DATA GENERATION
    # ═══════════════════════════════════════════════════════════════════════

    def _generate_training_data(self, n_samples=3000):
        """
        Generate balanced training data using cybersecurity domain knowledge.
        
        This creates synthetic training samples that represent real-world
        port/service risk patterns observed in penetration testing.
        """
        np.random.seed(42)
        features = []
        labels = []
        
        samples_per_class = n_samples // 5

        # ─── CLASS 0: SAFE SERVICES ───────────────────────────────────────
        safe_services = [
            (443, 'https', 1), (993, 'imaps', 1), (995, 'pop3s', 1),
            (8443, 'https', 1), (465, 'smtps', 1), (853, 'domain', 1),
        ]
        for _ in range(samples_per_class):
            port, service, proto = safe_services[np.random.randint(0, len(safe_services))]
            port = max(1, min(65535, port + np.random.randint(-10, 11)))
            features.append(self._extract_features_raw(port, service, proto))
            labels.append(0)

        # ─── CLASS 1: LOW RISK SERVICES ───────────────────────────────────
        low_services = [
            (22, 'ssh', 1), (53, 'domain', 1), (123, 'ntp', 0),
            (587, 'submission', 1), (631, 'ipp', 1), (5353, 'mdns', 0),
        ]
        for _ in range(samples_per_class):
            port, service, proto = low_services[np.random.randint(0, len(low_services))]
            port = max(1, min(65535, port + np.random.randint(-5, 6)))
            features.append(self._extract_features_raw(port, service, proto))
            labels.append(1)

        # ─── CLASS 2: MEDIUM RISK SERVICES ────────────────────────────────
        medium_services = [
            (80, 'http', 1), (8080, 'http-proxy', 1), (25, 'smtp', 1),
            (110, 'pop3', 1), (143, 'imap', 1), (5432, 'postgresql', 1),
            (6379, 'redis', 1), (27017, 'mongodb', 1), (9200, 'elasticsearch', 1),
        ]
        for _ in range(samples_per_class):
            port, service, proto = medium_services[np.random.randint(0, len(medium_services))]
            port = max(1, min(65535, port + np.random.randint(-8, 9)))
            features.append(self._extract_features_raw(port, service, proto))
            labels.append(2)

        # ─── CLASS 3: HIGH RISK SERVICES ──────────────────────────────────
        high_services = [
            (21, 'ftp', 1), (445, 'microsoft-ds', 1), (139, 'netbios-ssn', 1),
            (3306, 'mysql', 1), (3389, 'ms-wbt-server', 1), (5900, 'vnc', 1),
            (1099, 'java-rmi', 1), (8180, 'http', 1), (512, 'exec', 1),
            (513, 'login', 1), (514, 'shell', 1), (1433, 'ms-sql-s', 1),
        ]
        for _ in range(samples_per_class):
            port, service, proto = high_services[np.random.randint(0, len(high_services))]
            port = max(1, min(65535, port + np.random.randint(-5, 6)))
            features.append(self._extract_features_raw(port, service, proto))
            labels.append(3)

        # ─── CLASS 4: CRITICAL RISK SERVICES ──────────────────────────────
        critical_services = [
            (23, 'telnet', 1), (1524, 'ingreslock', 1), (4444, 'metasploit', 1),
            (6667, 'irc', 1), (31337, 'backdoor', 1), (1337, 'backdoor', 1),
            (5555, 'backdoor', 1), (79, 'finger', 1), (512, 'exec', 1),
            (27374, 'subseven', 1), (6666, 'irc', 1),
        ]
        for _ in range(samples_per_class):
            port, service, proto = critical_services[np.random.randint(0, len(critical_services))]
            port = max(1, min(65535, port + np.random.randint(-3, 4)))
            features.append(self._extract_features_raw(port, service, proto))
            labels.append(4)

        return np.array(features), np.array(labels)

    def _extract_features_raw(self, port, service, proto_num):
        """Extract raw feature vector for a port/service"""
        
        is_well_known = 1 if port < 1024 else 0
        is_registered = 1 if 1024 <= port <= 49151 else 0
        is_dynamic = 1 if port > 49151 else 0
        
        port_risk = self.PORT_RISK_DB.get(port, 2)
        service_risk = self.SERVICE_RISK_DB.get(service.lower() if service else 'unknown', 2)
        
        backdoor_ports = {1524, 4444, 5555, 6666, 6667, 1337, 31337, 27374, 12345}
        database_ports = {3306, 5432, 1433, 27017, 6379, 1521, 5984, 9200}
        remote_ports = {22, 23, 3389, 5900, 512, 513, 514, 5985}
        
        is_backdoor = 1 if port in backdoor_ports else 0
        is_database = 1 if port in database_ports else 0
        is_remote = 1 if port in remote_ports else 0
        
        return [
            port,
            is_well_known,
            is_registered,
            is_dynamic,
            port_risk,
            service_risk,
            proto_num,
            1,  # has_version (assume yes during training)
            is_backdoor,
            is_database,
            is_remote
        ]

    # ═══════════════════════════════════════════════════════════════════════
    # MODEL TRAINING
    # ═══════════════════════════════════════════════════════════════════════

    def train(self):
        """
        Train the Hybrid AI Engine
        
        This trains both:
        1. Random Forest Classifier (supervised)
        2. Isolation Forest (unsupervised anomaly detection)
        """
        
        print("\n" + "═" * 65)
        print("🧠 AI-SENTINEL PREMIUM v3.0 — HYBRID AI TRAINING")
        print("═" * 65)
        
        # ─── STEP 1: GENERATE TRAINING DATA ───────────────────────────────
        print("\n📊 Step 1: Generating training dataset...")
        X, y = self._generate_training_data(3000)
        print(f"   ✓ Generated {len(X)} samples across 5 risk classes")
        
        # ─── STEP 2: SPLIT DATA ───────────────────────────────────────────
        print("\n📊 Step 2: Splitting data (80% train / 20% test)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"   ✓ Training samples: {len(X_train)}")
        print(f"   ✓ Testing samples: {len(X_test)}")
        
        # ─── STEP 3: SCALE FEATURES ───────────────────────────────────────
        print("\n📊 Step 3: Scaling features (StandardScaler)...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        print(f"   ✓ Features scaled to zero mean and unit variance")
        
        # ─── STEP 4: TRAIN RANDOM FOREST (SUPERVISED) ─────────────────────
        print("\n🌲 Step 4: Training Random Forest Classifier...")
        print("   [Supervised Learning Model]")
        
        self.rf_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        self.rf_classifier.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.rf_classifier.predict(X_test_scaled)
        self.accuracy = accuracy_score(y_test, y_pred)
        
        print(f"   ✓ Model trained successfully!")
        print(f"   ✓ Accuracy: {self.accuracy:.2%}")
        
        # Classification Report
        print("\n   📋 Classification Report:")
        print("   " + "-" * 55)
        
        # Handle potential missing classes
        present_labels = sorted(list(set(y_test) | set(y_pred)))
        present_names = [self.RISK_LABELS[i] for i in present_labels]
        
        report = classification_report(
            y_test, y_pred,
            labels=present_labels,
            target_names=present_names,
            zero_division=0
        )
        for line in report.split('\n'):
            print(f"   {line}")
        
        # ─── STEP 5: CALCULATE FEATURE IMPORTANCE ─────────────────────────
        print("\n📊 Step 5: Calculating feature importance...")
        importances = self.rf_classifier.feature_importances_
        self.feature_importance = dict(zip(self.FEATURE_NAMES, importances))
        
        print("   Feature Importance Ranking:")
        sorted_features = sorted(self.feature_importance.items(), key=lambda x: -x[1])
        for i, (name, imp) in enumerate(sorted_features[:6], 1):
            bar = "█" * int(imp * 40)
            print(f"   {i}. {name:25s} {imp:.3f} {bar}")
        
        # ─── STEP 6: TRAIN ISOLATION FOREST (UNSUPERVISED) ────────────────
        print("\n🔍 Step 6: Training Isolation Forest...")
        print("   [Unsupervised Anomaly Detection Model]")
        
        self.anomaly_detector = IsolationForest(
            n_estimators=150,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.anomaly_detector.fit(X_train_scaled)
        
        print(f"   ✓ Anomaly detector trained!")
        print(f"   ✓ Contamination rate: 10%")
        
        # ─── STEP 7: SAVE MODEL ───────────────────────────────────────────
        print("\n💾 Step 7: Saving trained models...")
        
        self.training_stats = {
            'samples': len(X),
            'accuracy': self.accuracy,
            'anomaly_contamination': 0.1,
            'trained_at': datetime.now().isoformat()
        }
        
        os.makedirs('model', exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'rf_classifier': self.rf_classifier,
                'anomaly_detector': self.anomaly_detector,
                'scaler': self.scaler,
                'feature_importance': self.feature_importance,
                'training_stats': self.training_stats,
                'accuracy': self.accuracy
            }, f)
        
        self.is_trained = True
        
        print(f"   ✓ Models saved to: {self.model_path}")
        
        # ─── SUMMARY ──────────────────────────────────────────────────────
        print("\n" + "═" * 65)
        print("✅ HYBRID AI TRAINING COMPLETE")
        print("═" * 65)
        print(f"   • Supervised Model:   Random Forest Classifier")
        print(f"   • Unsupervised Model: Isolation Forest")
        print(f"   • Overall Accuracy:   {self.accuracy:.2%}")
        print(f"   • Total Samples:      {len(X)}")
        print(f"   • Risk Categories:    {len(self.RISK_LABELS)}")
        print("═" * 65 + "\n")
        
        return self.accuracy

    # ═══════════════════════════════════════════════════════════════════════
    # MODEL LOADING
    # ═══════════════════════════════════════════════════════════════════════

    def load_model(self):
        """Load pre-trained models from disk"""
        
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.rf_classifier = data['rf_classifier']
                    self.anomaly_detector = data['anomaly_detector']
                    self.scaler = data['scaler']
                    self.feature_importance = data.get('feature_importance', {})
                    self.training_stats = data.get('training_stats', {})
                    self.accuracy = data.get('accuracy', 0.0)
                    self.is_trained = True
                    
                print(f"   📂 AI Models loaded successfully!")
                print(f"      • Accuracy: {self.accuracy:.2%}")
                print(f"      • Trained: {self.training_stats.get('trained_at', 'Unknown')[:19]}")
                return True
            except Exception as e:
                print(f"   ⚠️ Error loading model: {e}")
                return False
        return False

    # ═══════════════════════════════════════════════════════════════════════
    # HYBRID AI CLASSIFICATION
    # ═══════════════════════════════════════════════════════════════════════

    def classify_port(self, port, service, protocol):
        """
        Perform Hybrid AI Classification on a single port/service.
        
        This combines:
        1. Random Forest risk classification
        2. Isolation Forest anomaly detection
        3. Rule-based expert knowledge
        4. Explainable AI reasoning
        
        Returns a comprehensive threat assessment.
        """
        
        # Ensure models are loaded
        if not self.is_trained:
            if not self.load_model():
                self.train()
        
        # Extract features
        proto_num = 1 if protocol.lower() == 'tcp' else 0
        service_lower = service.lower() if service else 'unknown'
        
        features = np.array([self._extract_features_raw(port, service_lower, proto_num)])
        features_scaled = self.scaler.transform(features)
        
        # ─── SUPERVISED CLASSIFICATION ────────────────────────────────────
        rf_prediction = int(self.rf_classifier.predict(features_scaled)[0])
        rf_probabilities = self.rf_classifier.predict_proba(features_scaled)[0]
        rf_confidence = float(max(rf_probabilities)) * 100
        
        # ─── ANOMALY DETECTION ────────────────────────────────────────────
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        # Normalize anomaly score (0-100)
        anomaly_score_normalized = max(0, min(100, (1 - anomaly_score) * 50))
        
        # ─── HYBRID RISK CALCULATION ──────────────────────────────────────
        # Combine supervised + unsupervised + rules
        
        # Base risk from Random Forest
        hybrid_risk = rf_prediction
        
        # Boost risk if anomaly detected
        if is_anomaly and hybrid_risk < 4:
            hybrid_risk = min(4, hybrid_risk + 1)
        
        # Apply domain expert rules
        if port in {1524, 4444, 5555, 6667, 31337, 1337}:
            hybrid_risk = 4  # Force critical for known backdoors
        
        if service_lower == 'telnet':
            hybrid_risk = max(hybrid_risk, 4)
        
        hybrid_risk = max(0, min(4, hybrid_risk))
        
        # ─── HYBRID CONFIDENCE ────────────────────────────────────────────
        # Weight: 70% supervised + 30% anomaly influence
        hybrid_confidence = rf_confidence * 0.7 + (100 - anomaly_score_normalized) * 0.3
        hybrid_confidence = round(min(99.9, max(50, hybrid_confidence)), 1)
        
        # ─── EXPLAINABLE AI REASONING ─────────────────────────────────────
        explanations = self._generate_explanations(
            port, service_lower, rf_prediction, is_anomaly, features[0]
        )
        
        # ─── BUILD RESULT ─────────────────────────────────────────────────
        return {
            'risk_level': hybrid_risk,
            'risk_label': self.RISK_LABELS[hybrid_risk],
            'risk_color': self.RISK_COLORS[self.RISK_LABELS[hybrid_risk]],
            'confidence': hybrid_confidence,
            
            # Detailed scores
            'supervised_score': {
                'prediction': rf_prediction,
                'label': self.RISK_LABELS[rf_prediction],
                'confidence': round(rf_confidence, 1),
                'probabilities': {
                    self.RISK_LABELS[i]: round(float(p) * 100, 1)
                    for i, p in enumerate(rf_probabilities)
                }
            },
            
            'anomaly_score': {
                'is_anomaly': is_anomaly,
                'score': round(anomaly_score_normalized, 1),
                'status': 'ANOMALY DETECTED' if is_anomaly else 'Normal Pattern'
            },
            
            'hybrid_analysis': {
                'final_risk': hybrid_risk,
                'final_label': self.RISK_LABELS[hybrid_risk],
                'methodology': 'Supervised + Unsupervised + Expert Rules'
            },
            
            'explanation': explanations,
            'ai_model': 'AI-Sentinel Hybrid Engine v3.0'
        }

    def _generate_explanations(self, port, service, rf_risk, is_anomaly, features):
        """Generate human-readable AI explanations"""
        
        explanations = []
        
        # ─── PORT-BASED EXPLANATIONS ──────────────────────────────────────
        if port in {1524, 4444, 5555, 31337, 1337, 27374}:
            explanations.append(f"⚠️ CRITICAL: Port {port} is a known backdoor/malware port")
        
        if port in {6667, 6666}:
            explanations.append(f"⚠️ Port {port} is commonly used by IRC botnets")
        
        if port == 23:
            explanations.append("⚠️ Telnet transmits credentials in cleartext")
        
        if port in {512, 513, 514}:
            explanations.append("⚠️ R-services (rexec/rlogin/rsh) have weak authentication")
        
        if port in {3306, 5432, 1433, 27017}:
            explanations.append(f"Database port {port} exposed — potential data breach risk")
        
        if port in {3389, 5900}:
            explanations.append(f"Remote desktop port {port} exposed — brute force target")
        
        if port == 445 or port == 139:
            explanations.append("SMB/CIFS ports are frequently exploited by ransomware")
        
        if port == 21:
            explanations.append("FTP often has weak authentication or anonymous access")
        
        # ─── SERVICE-BASED EXPLANATIONS ───────────────────────────────────
        if service in {'telnet', 'finger'}:
            explanations.append(f"Service '{service}' is considered inherently insecure")
        
        if service in {'http', 'http-proxy'} and port not in {80, 8080}:
            explanations.append(f"HTTP on non-standard port {port} — potentially hidden service")
        
        # ─── ANOMALY-BASED EXPLANATIONS ───────────────────────────────────
        if is_anomaly:
            explanations.append("🔍 ANOMALY: Unusual pattern detected by AI (not in training data)")
        
        # ─── RISK-LEVEL EXPLANATIONS ──────────────────────────────────────
        if rf_risk >= 4:
            explanations.append("AI classifies this as CRITICAL based on learned patterns")
        elif rf_risk >= 3:
            explanations.append("AI classifies this as HIGH RISK based on learned patterns")
        elif rf_risk >= 2:
            explanations.append("AI classifies this as MEDIUM RISK — requires attention")
        elif rf_risk == 1:
            explanations.append("AI classifies this as LOW RISK — generally safe")
        else:
            explanations.append("AI classifies this as SAFE — encrypted/secure service")
        
        # Ensure at least one explanation
        if not explanations:
            explanations.append("Standard service with typical risk profile")
        
        return explanations

    # ═══════════════════════════════════════════════════════════════════════
    # FULL SCAN ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════

    def analyze_full_scan(self, scan_results):
        """
        Perform Hybrid AI Analysis on complete scan results.
        
        Returns:
        - Enriched scan results with AI classifications
        - Comprehensive threat summary
        - AI-generated executive summary
        """
        
        print("\n" + "═" * 65)
        print("🧠 AI-SENTINEL HYBRID THREAT ANALYSIS")
        print("═" * 65)
        
        # Ensure models loaded
        if not self.is_trained:
            if not self.load_model():
                self.train()
        
        analyzed_results = []
        all_confidences = []
        anomaly_count = 0
        
        threat_summary = {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'safe': 0,
            'anomalies_detected': 0,
            'ai_confidence_avg': 0,
            'ai_model_accuracy': f"{self.accuracy:.2%}",
            'ai_methodology': 'Hybrid (Supervised + Unsupervised + Expert Rules)',
            'top_threats': [],
            'executive_summary': ''
        }
        
        # ─── ANALYZE EACH HOST ────────────────────────────────────────────
        for host in scan_results:
            host_analysis = {
                'ip': host['ip'],
                'hostname': host.get('hostname', 'N/A'),
                'os': host.get('os', 'Unknown'),
                'ports': [],
                'overall_risk': 0,
                'anomaly_count': 0
            }
            
            for port_info in host.get('ports', []):
                # Perform Hybrid AI classification
                ai_result = self.classify_port(
                    port_info['port'],
                    port_info.get('service', 'unknown'),
                    port_info.get('protocol', 'tcp')
                )
                
                # Enrich port data with AI results
                enriched_port = {
                    **port_info,
                    'ai_risk_level': ai_result['risk_level'],
                    'ai_risk_label': ai_result['risk_label'],
                    'ai_risk_color': ai_result['risk_color'],
                    'ai_confidence': ai_result['confidence'],
                    'ai_is_anomaly': ai_result['anomaly_score']['is_anomaly'],
                    'ai_anomaly_score': ai_result['anomaly_score']['score'],
                    'ai_explanation': ai_result['explanation'],
                    'ai_supervised_score': ai_result['supervised_score'],
                    'ai_hybrid_analysis': ai_result['hybrid_analysis'],
                }
                
                host_analysis['ports'].append(enriched_port)
                
                # Update statistics
                threat_summary['total_findings'] += 1
                all_confidences.append(ai_result['confidence'])
                
                if ai_result['anomaly_score']['is_anomaly']:
                    anomaly_count += 1
                    host_analysis['anomaly_count'] += 1
                
                # Count by risk level
                risk_key = ai_result['risk_label'].lower()
                if risk_key in threat_summary:
                    threat_summary[risk_key] += 1
                
                # Track host overall risk
                if ai_result['risk_level'] > host_analysis['overall_risk']:
                    host_analysis['overall_risk'] = ai_result['risk_level']
                
                # Track top threats
                if ai_result['risk_level'] >= 3:
                    threat_summary['top_threats'].append({
                        'host': host['ip'],
                        'port': port_info['port'],
                        'service': port_info.get('service', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'risk_level': ai_result['risk_level'],
                        'risk_label': ai_result['risk_label'],
                        'confidence': ai_result['confidence'],
                        'is_anomaly': ai_result['anomaly_score']['is_anomaly'],
                        'explanation': ai_result['explanation']
                    })
            
            analyzed_results.append(host_analysis)
        
        # ─── CALCULATE FINAL STATISTICS ───────────────────────────────────
        threat_summary['anomalies_detected'] = anomaly_count
        
        if all_confidences:
            threat_summary['ai_confidence_avg'] = round(np.mean(all_confidences), 1)
        
        # Sort top threats by risk level (descending)
        threat_summary['top_threats'].sort(
            key=lambda x: (x['risk_level'], x['confidence']),
            reverse=True
        )
        threat_summary['top_threats'] = threat_summary['top_threats'][:10]
        
        # ─── GENERATE EXECUTIVE SUMMARY ───────────────────────────────────
        threat_summary['executive_summary'] = self._generate_executive_summary(
            threat_summary, analyzed_results
        )
        
        # ─── PRINT SUMMARY ────────────────────────────────────────────────
        print(f"\n✅ Hybrid AI Analysis Complete!")
        print(f"   • Total Findings:      {threat_summary['total_findings']}")
        print(f"   • Critical Risks:      {threat_summary['critical']}")
        print(f"   • High Risks:          {threat_summary['high']}")
        print(f"   • Medium Risks:        {threat_summary['medium']}")
        print(f"   • Low Risks:           {threat_summary['low']}")
        print(f"   • Safe Services:       {threat_summary['safe']}")
        print(f"   • Anomalies Detected:  {threat_summary['anomalies_detected']}")
        print(f"   • AI Confidence:       {threat_summary['ai_confidence_avg']}%")
        print("═" * 65 + "\n")
        
        return analyzed_results, threat_summary

    # ═══════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY GENERATOR
    # ═══════════════════════════════════════════════════════════════════════

    def _generate_executive_summary(self, summary, results):
        """
        Generate an AI-powered Executive Summary for the security assessment.
        
        This creates a professional narrative summary suitable for
        executive reports and presentations.
        """
        
        total = summary['total_findings']
        critical = summary['critical']
        high = summary['high']
        medium = summary['medium']
        anomalies = summary['anomalies_detected']
        confidence = summary['ai_confidence_avg']
        
        # Determine overall security posture
        if critical > 0:
            posture = "CRITICAL"
            posture_desc = "severely compromised"
        elif high > 2:
            posture = "HIGH RISK"
            posture_desc = "significantly at risk"
        elif high > 0 or medium > 3:
            posture = "ELEVATED RISK"
            posture_desc = "requires immediate attention"
        elif medium > 0:
            posture = "MODERATE RISK"
            posture_desc = "has some security concerns"
        else:
            posture = "LOW RISK"
            posture_desc = "generally secure"
        
        # Build executive summary
        lines = []
        
        lines.append(f"SECURITY POSTURE: {posture}")
        lines.append("")
        
        lines.append(f"The AI-Sentinel Hybrid Analysis Engine has completed a comprehensive "
                     f"security assessment of the target infrastructure. The analysis utilized "
                     f"a combination of supervised machine learning (Random Forest Classifier), "
                     f"unsupervised anomaly detection (Isolation Forest), and expert domain knowledge "
                     f"to evaluate {total} discovered services.")
        lines.append("")
        
        lines.append(f"FINDINGS SUMMARY:")
        lines.append(f"The target environment is {posture_desc}. The AI engine identified "
                     f"{critical} critical-risk services, {high} high-risk services, "
                     f"and {medium} medium-risk services requiring attention.")
        lines.append("")
        
        if anomalies > 0:
            lines.append(f"ANOMALY DETECTION:")
            lines.append(f"The unsupervised AI component detected {anomalies} anomalous service patterns "
                         f"that deviate from normal network behavior. These require further investigation "
                         f"as they may indicate unknown threats or misconfigurations.")
            lines.append("")
        
        # Top threats
        if summary['top_threats']:
            lines.append(f"TOP THREATS IDENTIFIED:")
            for i, threat in enumerate(summary['top_threats'][:5], 1):
                lines.append(f"  {i}. {threat['host']}:{threat['port']} ({threat['service']}) — "
                             f"{threat['risk_label']} Risk ({threat['confidence']}% confidence)")
            lines.append("")
        
        # Recommendations
        lines.append(f"RECOMMENDATIONS:")
        
        if critical > 0:
            lines.append(f"  • IMMEDIATE: Address {critical} critical vulnerabilities within 24 hours")
        if high > 0:
            lines.append(f"  • HIGH PRIORITY: Remediate {high} high-risk findings within 7 days")
        if anomalies > 0:
            lines.append(f"  • INVESTIGATE: Review {anomalies} anomalous services for potential threats")
        
        lines.append(f"  • ONGOING: Implement continuous security monitoring")
        lines.append(f"  • HARDENING: Disable unnecessary services and apply patches")
        lines.append("")
        
        lines.append(f"AI MODEL CONFIDENCE: {confidence}%")
        lines.append(f"METHODOLOGY: Hybrid AI (Supervised + Unsupervised + Expert Rules)")
        
        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════════════════

    def get_feature_importance(self):
        """Get feature importance rankings for explainability"""
        
        if not self.feature_importance:
            return {}
        
        sorted_features = sorted(
            self.feature_importance.items(),
            key=lambda x: -x[1]
        )
        
        return {
            'features': [f[0] for f in sorted_features],
            'importances': [round(f[1], 4) for f in sorted_features],
            'top_feature': sorted_features[0][0] if sorted_features else None
        }

    def get_model_info(self):
        """Get information about the trained models"""
        
        return {
            'name': 'AI-Sentinel Hybrid Engine v3.0',
            'supervised_model': 'Random Forest Classifier (200 trees, depth 15)',
            'unsupervised_model': 'Isolation Forest (150 estimators, 10% contamination)',
            'accuracy': f"{self.accuracy:.2%}",
            'is_trained': self.is_trained,
            'training_samples': self.training_stats.get('samples', 0),
            'trained_at': self.training_stats.get('trained_at', 'Not trained'),
            'risk_categories': self.RISK_LABELS,
            'feature_count': len(self.FEATURE_NAMES),
            'features': self.FEATURE_NAMES
        }

    def explain_decision(self, port, service, protocol):
        """
        Get a detailed explanation of AI decision for a specific port.
        Useful for transparency and debugging.
        """
        
        result = self.classify_port(port, service, protocol)
        
        explanation = {
            'input': {
                'port': port,
                'service': service,
                'protocol': protocol
            },
            'decision': {
                'risk_level': result['risk_level'],
                'risk_label': result['risk_label'],
                'confidence': result['confidence']
            },
            'reasoning': {
                'supervised_classification': result['supervised_score'],
                'anomaly_detection': result['anomaly_score'],
                'final_hybrid_result': result['hybrid_analysis']
            },
            'human_explanation': result['explanation'],
            'feature_importance': self.get_feature_importance()
        }
        
        return explanation


# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE TESTING
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("   AI-SENTINEL PREMIUM v3.0 — HYBRID AI ENGINE TEST")
    print("=" * 70)
    
    # Initialize and train
    ai = AIThreatAnalyzer()
    ai.train()
    
    # Test classifications
    print("\n" + "=" * 70)
    print("   TESTING HYBRID AI CLASSIFICATION")
    print("=" * 70)
    
    test_cases = [
        (443, 'https', 'tcp'),      # Safe
        (22, 'ssh', 'tcp'),         # Low
        (80, 'http', 'tcp'),        # Medium
        (3306, 'mysql', 'tcp'),     # High
        (23, 'telnet', 'tcp'),      # Critical
        (4444, 'unknown', 'tcp'),   # Critical (backdoor)
        (31337, 'unknown', 'tcp'),  # Critical (elite backdoor)
        (6667, 'irc', 'tcp'),       # Critical (botnet)
    ]
    
    print(f"\n{'Port':<8} {'Service':<12} {'Risk':<10} {'Confidence':<12} {'Anomaly':<10}")
    print("-" * 60)
    
    for port, service, proto in test_cases:
        result = ai.classify_port(port, service, proto)
        anomaly = "🔍 YES" if result['anomaly_score']['is_anomaly'] else "No"
        print(f"{port:<8} {service:<12} {result['risk_label']:<10} {result['confidence']:<12} {anomaly:<10}")
    
    # Show model info
    print("\n" + "=" * 70)
    print("   MODEL INFORMATION")
    print("=" * 70)
    model_info = ai.get_model_info()
    for key, value in model_info.items():
        if key != 'features':
            print(f"   {key}: {value}")
    
    print("\n✅ Hybrid AI Engine test complete!\n")
