import tensorflow as tf
from tensorflow import keras
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

epochs = 16
latent_dim = 12

def load_data(data_path):
  """Loads preprocessed network traffic data from a CSV file."""
  df = pd.read_csv(data_path)
  features = df.drop(columns=['Timestamp', 'Source IP', 'Destination IP', 'Website Name', 'Domain Name'])
  scaler = MinMaxScaler()
  scaled_features = scaler.fit_transform(features)
  return scaled_features

def build_autoencoder(input_dim):
  """Defines and builds the autoencoder model."""
  encoded = keras.Sequential([
      keras.layers.Dense(32, activation='relu', input_shape=(input_dim,)),
      keras.layers.Dense(latent_dim, activation='relu'),
  ])
  decoded = keras.Sequential([
      keras.layers.Dense(32, activation='relu'),
      keras.layers.Dense(input_dim, activation='sigmoid'),
  ])
  autoencoder = keras.Model(inputs=encoded.input, outputs=decoded(encoded.output))
  autoencoder.compile(loss='binary_crossentropy', optimizer='adam')
  return autoencoder, scaler

def detect_anomalies(model, scaler, data):
  """Predicts anomalies based on reconstruction error."""
  predictions = model.predict(data)
  reconstruction_error = tf.keras.losses.binary_crossentropy(data, predictions)
  threshold = 0.5  
  anomalies = data[reconstruction_error > threshold]
  return anomalies

if __name__ == "__main__":

  data_path = "cleaned_traffic.csv"
  
  data = load_data(data_path)
  
  model, scaler = build_autoencoder(data.shape[1])
  model.fit(data, data, epochs=epochs)
  
  anomalies = detect_anomalies(model, scaler, data)
  
  print(f"Number of anomalies detected: {len(anomalies)}")
