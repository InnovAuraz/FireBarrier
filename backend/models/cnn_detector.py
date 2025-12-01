import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import joblib
from pathlib import Path
from utils.logger import logger
from config import config

class CNNDetector:
    """
    Lightweight 1D CNN for traffic anomaly detection.
    Uses convolution to detect local patterns in feature sequences.
    """
    
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.scaler_mean = None
        self.scaler_std = None
        
        # Training data collection
        self.feature_buffer = []
        self.label_buffer = []
        self.min_training_samples = config.CNN_MIN_SAMPLES
        
        # Model paths
        self.model_path = Path("models/cnn_model.keras")
        self.scaler_path = Path("models/cnn_scaler.npz")
        
        # Feature configuration (align with your packet features)
        self.feature_dim = 12  # Extended feature set for CNN
        
        # Try to load existing model
        self._load_model()
        
        # Build model if not loaded
        if self.model is None:
            self._build_model()
    
    def _build_model(self):
        """
        Build tiny 1D CNN architecture optimized for presentation.
        Designed to be visually impressive yet computationally light.
        """
        model = keras.Sequential([
            # Input layer - expects (batch_size, feature_dim, 1) for Conv1D
            layers.Input(shape=(self.feature_dim, 1)),
            
            # Conv Block 1: Local pattern detection
            layers.Conv1D(
                filters=16,           # Few filters for speed
                kernel_size=3,        # Small window for local patterns
                activation='relu',
                padding='same',
                name='conv1d_local'
            ),
            layers.BatchNormalization(),
            layers.Dropout(0.2),
            
            # Conv Block 2: Higher-level feature extraction
            layers.Conv1D(
                filters=8,
                kernel_size=3,
                activation='relu',
                padding='same',
                name='conv1d_global'
            ),
            layers.BatchNormalization(),
            
            # Global pooling to compress spatial dimensions
            layers.GlobalMaxPooling1D(),
            
            # Dense classification head
            layers.Dense(8, activation='relu', name='dense_features'),
            layers.Dropout(0.3),
            layers.Dense(1, activation='sigmoid', name='anomaly_probability')
        ])
        
        # Compile with binary classification loss
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'AUC']
        )
        
        self.model = model
        logger.info(f"CNN model built: {model.count_params()} trainable parameters")
    
    def _extract_features(self, packet_info: dict) -> np.ndarray:
        """
        Extract 12D feature vector from packet.
        Richer feature set than Isolation Forest for CNN's learning capacity.
        """
        features = [
            packet_info.get('size', 0),
            packet_info.get('src_port', 0),
            packet_info.get('dst_port', 0),
            packet_info.get('protocol', 0),
            
            # Binary flags
            1.0 if packet_info.get('type') == 'TCP' else 0.0,
            1.0 if packet_info.get('type') == 'UDP' else 0.0,
            
            # Payload characteristics
            len(packet_info.get('payload', b'')),
            
            # Port range indicators (useful for pattern detection)
            1.0 if packet_info.get('dst_port', 0) < 1024 else 0.0,  # Well-known ports
            1.0 if 1024 <= packet_info.get('dst_port', 0) < 49152 else 0.0,  # Registered
            1.0 if packet_info.get('dst_port', 0) >= 49152 else 0.0,  # Ephemeral
            
            # Size categories
            1.0 if packet_info.get('size', 0) < 100 else 0.0,  # Small
            1.0 if packet_info.get('size', 0) > 1200 else 0.0,  # Large
        ]
        
        return np.array(features, dtype=np.float32)
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """Z-score normalization for stable training"""
        if self.scaler_mean is None or self.scaler_std is None:
            # Compute on first batch
            self.scaler_mean = np.mean(features, axis=0)
            self.scaler_std = np.std(features, axis=0) + 1e-8  # Avoid div by zero
        
        return (features - self.scaler_mean) / self.scaler_std
    
    def collect_sample(self, packet_info: dict, is_threat: bool):
        """
        Collect labeled samples for training.
        Uses combined detection from other layers as labels.
        """
        if self.is_trained:
            return  # Stop collecting after initial training
        
        features = self._extract_features(packet_info)
        self.feature_buffer.append(features)
        self.label_buffer.append(1.0 if is_threat else 0.0)
        
        # Log progress
        if len(self.feature_buffer) % 50 == 0:
            logger.info(f"CNN collected {len(self.feature_buffer)}/{self.min_training_samples} samples")
    
    def should_train(self) -> bool:
        """Check if we have enough samples to train"""
        return (not self.is_trained and 
                len(self.feature_buffer) >= self.min_training_samples)
    
    def train(self):
        """Train the CNN on collected samples"""
        if len(self.feature_buffer) < self.min_training_samples:
            logger.warning(f"Not enough samples for CNN training: {len(self.feature_buffer)}/{self.min_training_samples}")
            return
        
        logger.info("Starting CNN training...")
        
        try:
            # Prepare training data
            X = np.array(self.feature_buffer, dtype=np.float32)
            y = np.array(self.label_buffer, dtype=np.float32)
            
            # Normalize features
            X = self._normalize_features(X)
            
            # Reshape for Conv1D: (samples, features, channels)
            X = X.reshape(-1, self.feature_dim, 1)
            
            # Train with validation split
            history = self.model.fit(
                X, y,
                epochs=20,  # Few epochs for quick training
                batch_size=32,
                validation_split=0.2,
                verbose=0,  # Silent for production
                callbacks=[
                    keras.callbacks.EarlyStopping(
                        monitor='val_loss',
                        patience=5,
                        restore_best_weights=True
                    )
                ]
            )
            
            self.is_trained = True
            
            # Log training metrics
            final_acc = history.history['accuracy'][-1]
            final_val_acc = history.history.get('val_accuracy', [0])[-1]
            logger.info(f"CNN trained | Accuracy: {final_acc:.3f} | Val Accuracy: {final_val_acc:.3f}")
            
            # Save model and scaler
            self._save_model()
            
            # Clear buffers to free memory
            self.feature_buffer.clear()
            self.label_buffer.clear()
            
        except Exception as e:
            logger.error(f"CNN training failed: {e}")
    
    def predict(self, packet_info: dict) -> tuple:
        """
        Predict anomaly probability for a packet.
        Returns: (is_threat: bool, probability: float)
        """
        if not self.is_trained or self.model is None:
            return False, 0.0
        
        try:
            # Extract and normalize features
            features = self._extract_features(packet_info)
            features = self._normalize_features(features)
            features = features.reshape(1, self.feature_dim, 1)
            
            # Predict
            prob = self.model.predict(features, verbose=0)[0][0]
            
            # Threshold from config
            threshold = getattr(config, 'CNN_PREDICTION_THRESHOLD', 0.6)
            is_threat = prob >= threshold
            
            return is_threat, float(prob)
            
        except Exception as e:
            logger.error(f"CNN prediction error: {e}")
            return False, 0.0
    
    def _save_model(self):
        """Save model and normalization parameters"""
        try:
            # Save Keras model
            self.model.save(self.model_path)
            
            # Save scaler params
            np.savez(
                self.scaler_path,
                mean=self.scaler_mean,
                std=self.scaler_std
            )
            
            logger.info(f"CNN model saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Failed to save CNN model: {e}")
    
    def _load_model(self):
        """Load existing model if available"""
        if not self.model_path.exists():
            logger.info("No existing CNN model found")
            return
        
        try:
            # Load Keras model
            self.model = keras.models.load_model(self.model_path)
            
            # Load scaler
            if self.scaler_path.exists():
                scaler_data = np.load(self.scaler_path)
                self.scaler_mean = scaler_data['mean']
                self.scaler_std = scaler_data['std']
            
            self.is_trained = True
            logger.info(f"CNN model loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Failed to load CNN model: {e}")
            self.model = None
            self.is_trained = False
    
    def get_stats(self) -> dict:
        """Get CNN training/detection statistics for API"""
        return {
            'is_trained': self.is_trained,
            'samples_collected': len(self.feature_buffer),
            'samples_needed': self.min_training_samples,
            'training_progress': min(100, int(len(self.feature_buffer) / self.min_training_samples * 100)),
            'model_params': self.model.count_params() if self.model else 0
        }
