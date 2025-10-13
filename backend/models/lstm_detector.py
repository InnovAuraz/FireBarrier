import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TensorFlow info messages
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from collections import deque
import time
import os

class LSTMThreatDetector:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.sequence_length = 10
        self.feature_dim = 8
        self.packet_sequences = deque(maxlen=self.sequence_length)
        self.training_sequences = []
        self.training_labels = []
        self.min_training_samples = 100
        self.model_path = 'models/lstm_model.keras'
        
        self.feature_means = None
        self.feature_stds = None
        
        print("🧠 LSTM Detector initialized (needs training)")
    
    def extract_features(self, packet_info):
        """Extract numerical features from packet"""
        features = [
            float(packet_info.get('size', 0)),
            float(packet_info.get('src_port', 0)),
            float(packet_info.get('dst_port', 0)),
            float(packet_info.get('protocol', 0)),
            1.0 if packet_info.get('type') == 'TCP' else 0.0,
            1.0 if packet_info.get('type') == 'UDP' else 0.0,
            float(len(packet_info.get('payload', b''))),
            float(packet_info.get('timestamp', time.time()) % 86400)
        ]
        return np.array(features)
    
    def add_packet_sequence(self, packet_info, is_threat=False):
        """Add packet to sequence buffer"""
        features = self.extract_features(packet_info)
        self.packet_sequences.append(features)
        
        if len(self.packet_sequences) == self.sequence_length:
            sequence = np.array(list(self.packet_sequences))
            self.training_sequences.append(sequence)
            self.training_labels.append(1 if is_threat else 0)
    
    def build_model(self):
        """Build LSTM neural network architecture"""
        model = Sequential([
            LSTM(64, input_shape=(self.sequence_length, self.feature_dim), 
                 return_sequences=True, activation='tanh'),
            Dropout(0.2),
            LSTM(32, activation='tanh'),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def normalize_features(self, sequences):
        """Normalize features for better training"""
        sequences = np.array(sequences)
        
        if self.feature_means is None:
            reshaped = sequences.reshape(-1, self.feature_dim)
            self.feature_means = np.mean(reshaped, axis=0)
            self.feature_stds = np.std(reshaped, axis=0) + 1e-8
        
        normalized = (sequences - self.feature_means) / self.feature_stds
        return normalized
    
    def train(self):
        """Train LSTM model on collected sequences"""
        if len(self.training_sequences) < self.min_training_samples:
            print(f"⏳ LSTM: Need {self.min_training_samples - len(self.training_sequences)} more sequences to train")
            return False
        
        print(f"🧠 Training LSTM on {len(self.training_sequences)} sequences...")
        
        X = np.array(self.training_sequences)
        y = np.array(self.training_labels)
        
        X = self.normalize_features(X)
        
        self.model = self.build_model()
        
        try:
            history = self.model.fit(
                X, y,
                epochs=20,
                batch_size=32,
                validation_split=0.2,
                verbose=0,
                callbacks=[
                    keras.callbacks.EarlyStopping(
                        monitor='val_loss',
                        patience=5,
                        restore_best_weights=True
                    )
                ]
            )
            
            final_accuracy = history.history['accuracy'][-1]
            final_val_accuracy = history.history.get('val_accuracy', [0])[-1]
            
            print(f"✅ LSTM trained! Accuracy: {final_accuracy:.2%} | Val Accuracy: {final_val_accuracy:.2%}")
            
            self.is_trained = True
            self.save_model()
            
            return True
            
        except Exception as e:
            print(f"❌ LSTM training failed: {e}")
            return False
    
    def predict_threat(self, packet_info):
        """Predict if current packet sequence is a threat"""
        if not self.is_trained or self.model is None:
            return False
        
        features = self.extract_features(packet_info)
        self.packet_sequences.append(features)
        
        if len(self.packet_sequences) < self.sequence_length:
            return False
        
        try:
            sequence = np.array(list(self.packet_sequences))
            sequence = sequence.reshape(1, self.sequence_length, self.feature_dim)
            
            # FIX: Check normalization parameters
            if self.feature_means is None or self.feature_stds is None:
                reshaped = sequence.reshape(-1, self.feature_dim)
                self.feature_means = np.mean(reshaped, axis=0)
                self.feature_stds = np.std(reshaped, axis=0) + 1e-8
            
            sequence = (sequence - self.feature_means) / self.feature_stds
            
            prediction = self.model.predict(sequence, verbose=0)[0][0]
            
            is_threat = prediction > 0.5  # Threshold can be adjusted
            
            if is_threat:
                print(f"🔴 LSTM detected threat! Confidence: {prediction:.2%}")
            
            return is_threat
            
        except Exception as e:
            print(f"❌ LSTM prediction error: {e}")
            return False
    
    def save_model(self):
        """Save trained model and normalization parameters"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            self.model.save(self.model_path)
            
            # Save normalization parameters
            norm_path = self.model_path.replace('.keras', '_norm.npz')
            if self.feature_means is not None and self.feature_stds is not None:
                np.savez(norm_path, means=self.feature_means, stds=self.feature_stds)
                print(f"💾 LSTM model and normalization saved")
            else:
                print(f"💾 LSTM model saved")
                
        except Exception as e:
            print(f"❌ Failed to save model: {e}")
    
    def load_model(self):
        """Load trained model and normalization parameters"""
        if os.path.exists(self.model_path):
            try:
                self.model = keras.models.load_model(self.model_path)
                
                # Load normalization parameters
                norm_path = self.model_path.replace('.keras', '_norm.npz')
                if os.path.exists(norm_path):
                    norm_data = np.load(norm_path)
                    self.feature_means = norm_data['means']
                    self.feature_stds = norm_data['stds']
                    print(f"✅ LSTM model and normalization loaded")
                else:
                    print(f"⚠️ LSTM model loaded but normalization params missing")
                
                self.is_trained = True
                return True
                
            except Exception as e:
                print(f"❌ Failed to load model: {e}")
                return False
        return False
    
    def get_stats(self):
        """Get LSTM statistics"""
        return {
            'is_trained': self.is_trained,
            'sequences_collected': len(self.training_sequences),
            'sequences_needed': max(0, self.min_training_samples - len(self.training_sequences)),
            'sequence_length': self.sequence_length
        }

# Global instance
lstm_detector = LSTMThreatDetector()
lstm_detector.load_model()
