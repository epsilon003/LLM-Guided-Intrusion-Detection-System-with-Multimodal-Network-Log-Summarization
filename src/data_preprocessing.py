"""
LLM-Guided Explainable Intrusion Detection System
Module 1: Data Collection & Preprocessing

This module handles loading and preprocessing of network traffic data
from multiple IDS datasets including NSL-KDD, CICIDS2017, and UNSW-NB15.

Author: Your Name
Date: 2024
License: MIT
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Dict, List
import warnings
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from collections import Counter
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

warnings.filterwarnings('ignore')


class NetworkDataPreprocessor:
    """
    Comprehensive preprocessor for network traffic data from various IDS datasets.
    
    Supported Datasets:
        - NSL-KDD (KDD Cup 99 improved version)
        - CICIDS2017 (Canadian Institute for Cybersecurity)
        - UNSW-NB15 (University of New South Wales)
    
    Features:
        - Automatic feature encoding
        - Missing value handling
        - Feature scaling and normalization
        - Attack type mapping
        - Train/test splitting
        - Feature importance analysis
    
    Example:
        >>> preprocessor = NetworkDataPreprocessor(dataset_type='NSL-KDD')
        >>> df = preprocessor.load_nsl_kdd('data/raw/nsl-kdd/KDDTrain+.txt')
        >>> X, y, y_binary = preprocessor.preprocess_data(df)
        >>> print(f"Shape: {X.shape}, Labels: {len(np.unique(y))}")
    """
    
    def __init__(self, dataset_type: str = 'NSL-KDD', config: Optional[Dict] = None):
        """
        Initialize the network data preprocessor.
        
        Args:
            dataset_type: Type of dataset ('NSL-KDD', 'CICIDS2017', 'UNSW-NB15')
            config: Optional configuration dictionary for preprocessing parameters
        """
        self.dataset_type = dataset_type.upper()
        self.config = config or {}
        
        # Scalers and encoders
        self.scaler = StandardScaler()
        self.minmax_scaler = MinMaxScaler()
        self.label_encoders = {}
        
        # Feature information
        self.feature_names = []
        self.categorical_features = []
        self.numerical_features = []
        
        # Attack mappings
        self.attack_mapping = {}
        self.attack_category_mapping = {}
        
        # Statistics
        self.preprocessing_stats = {}
        
        logger.info(f"Initialized preprocessor for {self.dataset_type} dataset")
    
    # ========================================================================
    # DATASET LOADING METHODS
    # ========================================================================
    
    def load_nsl_kdd(self, filepath: str, has_difficulty: bool = True) -> pd.DataFrame:
        """
        Load NSL-KDD dataset.
        
        NSL-KDD is an improved version of the KDD Cup 99 dataset, addressing
        issues like redundant records and unbalanced class distribution.
        
        Args:
            filepath: Path to NSL-KDD data file
            has_difficulty: Whether the file includes difficulty level column
        
        Returns:
            DataFrame containing the loaded data
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            pd.errors.ParserError: If file format is invalid
        """
        logger.info(f"Loading NSL-KDD dataset from {filepath}")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"NSL-KDD file not found: {filepath}")
        
        # Define column names
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'attack_type'
        ]
        
        if has_difficulty:
            columns.append('difficulty_level')
        
        try:
            df = pd.read_csv(filepath, names=columns, skipinitialspace=True)
            
            # Clean attack type (remove trailing dots if present)
            df['attack_type'] = df['attack_type'].str.strip()
            
            # Map attacks to categories
            self._setup_nsl_kdd_attack_mapping()
            df['attack_category'] = df['attack_type'].map(self.attack_category_mapping)
            
            logger.info(f"Loaded {len(df)} records with {len(df.columns)} features")
            logger.info(f"Attack distribution: {df['attack_type'].value_counts().to_dict()}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error loading NSL-KDD dataset: {e}")
            raise
    
    def load_cicids2017(self, filepath: str) -> pd.DataFrame:
        """
        Load CICIDS2017 dataset.
        
        CICIDS2017 contains modern attacks and is widely used for ML-based IDS research.
        
        Args:
            filepath: Path to CICIDS2017 CSV file
        
        Returns:
            DataFrame containing the loaded data
        """
        logger.info(f"Loading CICIDS2017 dataset from {filepath}")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"CICIDS2017 file not found: {filepath}")
        
        try:
            df = pd.read_csv(filepath, skipinitialspace=True)
            
            # Clean column names (remove spaces)
            df.columns = df.columns.str.strip()
            
            # The label column might be named differently
            label_cols = ['Label', 'label', ' Label']
            for col in label_cols:
                if col in df.columns:
                    df.rename(columns={col: 'attack_type'}, inplace=True)
                    break
            
            # Handle infinite values
            df = df.replace([np.inf, -np.inf], np.nan)
            
            logger.info(f"Loaded {len(df)} records with {len(df.columns)} features")
            
            if 'attack_type' in df.columns:
                logger.info(f"Attack distribution: {df['attack_type'].value_counts().to_dict()}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error loading CICIDS2017 dataset: {e}")
            raise
    
    def load_unsw_nb15(self, filepath: str) -> pd.DataFrame:
        """
        Load UNSW-NB15 dataset.
        
        UNSW-NB15 contains modern normal and attack activities with 49 features.
        
        Args:
            filepath: Path to UNSW-NB15 CSV file
        
        Returns:
            DataFrame containing the loaded data
        """
        logger.info(f"Loading UNSW-NB15 dataset from {filepath}")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"UNSW-NB15 file not found: {filepath}")
        
        try:
            df = pd.read_csv(filepath, skipinitialspace=True)
            
            # Rename label column if needed
            if 'label' in df.columns:
                df['attack_binary'] = df['label']
            
            if 'attack_cat' in df.columns:
                df.rename(columns={'attack_cat': 'attack_type'}, inplace=True)
            
            logger.info(f"Loaded {len(df)} records with {len(df.columns)} features")
            
            if 'attack_type' in df.columns:
                logger.info(f"Attack distribution: {df['attack_type'].value_counts().to_dict()}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error loading UNSW-NB15 dataset: {e}")
            raise
    
    def load_data(self, filepath: str, **kwargs) -> pd.DataFrame:
        """
        Load data based on dataset type.
        
        Args:
            filepath: Path to data file
            **kwargs: Additional arguments for specific loaders
        
        Returns:
            DataFrame containing the loaded data
        """
        if self.dataset_type == 'NSL-KDD':
            return self.load_nsl_kdd(filepath, **kwargs)
        elif self.dataset_type == 'CICIDS2017':
            return self.load_cicids2017(filepath)
        elif self.dataset_type == 'UNSW-NB15':
            return self.load_unsw_nb15(filepath)
        else:
            raise ValueError(f"Unsupported dataset type: {self.dataset_type}")
    
    # ========================================================================
    # PREPROCESSING METHODS
    # ========================================================================
    
    def preprocess_data(
        self,
        df: pd.DataFrame,
        target_column: str = 'attack_type',
        test_size: float = 0.0,
        random_state: int = 42,
        normalize: bool = True,
        handle_missing: str = 'zero'
    ) -> Tuple[pd.DataFrame, Optional[pd.Series], Optional[pd.Series]]:
        """
        Comprehensive preprocessing pipeline.
        
        Steps:
            1. Handle missing values
            2. Remove duplicates
            3. Encode categorical variables
            4. Normalize/scale numerical features
            5. Create binary labels (normal vs attack)
        
        Args:
            df: Input DataFrame
            target_column: Name of the target/label column
            test_size: Proportion for test split (0 for no split)
            random_state: Random seed for reproducibility
            normalize: Whether to normalize numerical features
            handle_missing: Strategy for missing values ('zero', 'mean', 'median', 'drop')
        
        Returns:
            Tuple of (X, y, y_binary) where:
                - X: Preprocessed features
                - y: Original labels
                - y_binary: Binary labels (0=normal, 1=attack)
        """
        logger.info("Starting data preprocessing pipeline...")
        
        # Make a copy to avoid modifying original
        data = df.copy()
        
        # Record initial statistics
        self.preprocessing_stats['initial_records'] = len(data)
        self.preprocessing_stats['initial_features'] = len(data.columns)
        
        # Step 1: Handle missing values
        data = self._handle_missing_values(data, strategy=handle_missing)
        
        # Step 2: Remove duplicates
        initial_len = len(data)
        data = data.drop_duplicates()
        duplicates_removed = initial_len - len(data)
        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate records")
            self.preprocessing_stats['duplicates_removed'] = duplicates_removed
        
        # Step 3: Separate features and target
        if target_column in data.columns:
            y = data[target_column].copy()
            X = data.drop(columns=[target_column])
            
            # Drop difficulty level if exists
            if 'difficulty_level' in X.columns:
                X = X.drop(columns=['difficulty_level'])
            
            # Drop attack_category if it's not the target
            if 'attack_category' in X.columns and target_column != 'attack_category':
                X = X.drop(columns=['attack_category'])
        else:
            logger.warning(f"Target column '{target_column}' not found")
            y = None
            X = data
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        # Step 4: Identify feature types
        self.categorical_features = X.select_dtypes(include=['object']).columns.tolist()
        self.numerical_features = X.select_dtypes(include=[np.number]).columns.tolist()
        
        logger.info(f"Categorical features: {len(self.categorical_features)}")
        logger.info(f"Numerical features: {len(self.numerical_features)}")
        
        # Step 5: Encode categorical variables
        X = self._encode_categorical(X)
        
        # Step 6: Normalize numerical features
        if normalize:
            X = self._normalize_features(X)
        
        # Step 7: Create binary labels
        y_binary = None
        if y is not None:
            y_binary = self._create_binary_labels(y)
            self.preprocessing_stats['normal_samples'] = (y_binary == 0).sum()
            self.preprocessing_stats['attack_samples'] = (y_binary == 1).sum()
        
        # Final statistics
        self.preprocessing_stats['final_records'] = len(X)
        self.preprocessing_stats['final_features'] = len(X.columns)
        
        logger.info("Preprocessing complete!")
        logger.info(f"Final shape: {X.shape}")
        if y_binary is not None:
            logger.info(f"Class distribution - Normal: {(y_binary==0).sum()}, Attack: {(y_binary==1).sum()}")
        
        return X, y, y_binary
    
    def _handle_missing_values(self, df: pd.DataFrame, strategy: str = 'zero') -> pd.DataFrame:
        """Handle missing values in the dataset."""
        # Replace infinite values with NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        
        missing_count = df.isnull().sum().sum()
        if missing_count > 0:
            logger.info(f"Found {missing_count} missing values")
            
            if strategy == 'zero':
                df = df.fillna(0)
            elif strategy == 'mean':
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())
            elif strategy == 'median':
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
            elif strategy == 'drop':
                df = df.dropna()
            else:
                logger.warning(f"Unknown strategy '{strategy}', using 'zero'")
                df = df.fillna(0)
            
            logger.info(f"Handled missing values using strategy: {strategy}")
        
        return df
    
    def _encode_categorical(self, X: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical variables."""
        X_encoded = X.copy()
        
        for col in self.categorical_features:
            if col not in X_encoded.columns:
                continue
            
            le = LabelEncoder()
            try:
                X_encoded[col] = le.fit_transform(X_encoded[col].astype(str))
                self.label_encoders[col] = le
                logger.debug(f"Encoded categorical feature: {col}")
            except Exception as e:
                logger.warning(f"Could not encode {col}: {e}")
        
        return X_encoded
    
    def _normalize_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Normalize numerical features."""
        X_normalized = X.copy()
        
        if self.numerical_features:
            try:
                X_normalized[self.numerical_features] = self.scaler.fit_transform(
                    X[self.numerical_features]
                )
                logger.info("Normalized numerical features")
            except Exception as e:
                logger.warning(f"Could not normalize features: {e}")
        
        return X_normalized
    
    def _create_binary_labels(self, y: pd.Series) -> pd.Series:
        """Create binary labels (0: normal, 1: attack)."""
        # Convert to lowercase for comparison
        y_lower = y.astype(str).str.lower()
        
        # Create binary labels
        y_binary = (y_lower != 'normal').astype(int)
        
        return y_binary
    
    # ========================================================================
    # ATTACK MAPPING METHODS
    # ========================================================================
    
    def _setup_nsl_kdd_attack_mapping(self):
        """Set up attack category mapping for NSL-KDD."""
        self.attack_category_mapping = {
            'normal': 'Normal',
            
            # DoS attacks
            'back': 'DoS',
            'land': 'DoS',
            'neptune': 'DoS',
            'pod': 'DoS',
            'smurf': 'DoS',
            'teardrop': 'DoS',
            'mailbomb': 'DoS',
            'apache2': 'DoS',
            'processtable': 'DoS',
            'udpstorm': 'DoS',
            
            # Probe attacks
            'ipsweep': 'Probe',
            'nmap': 'Probe',
            'portsweep': 'Probe',
            'satan': 'Probe',
            'mscan': 'Probe',
            'saint': 'Probe',
            
            # R2L attacks
            'ftp_write': 'R2L',
            'guess_passwd': 'R2L',
            'imap': 'R2L',
            'multihop': 'R2L',
            'phf': 'R2L',
            'spy': 'R2L',
            'warezclient': 'R2L',
            'warezmaster': 'R2L',
            'sendmail': 'R2L',
            'named': 'R2L',
            'snmpgetattack': 'R2L',
            'snmpguess': 'R2L',
            'xlock': 'R2L',
            'xsnoop': 'R2L',
            'worm': 'R2L',
            
            # U2R attacks
            'buffer_overflow': 'U2R',
            'loadmodule': 'U2R',
            'perl': 'U2R',
            'rootkit': 'U2R',
            'httptunnel': 'U2R',
            'ps': 'U2R',
            'sqlattack': 'U2R',
            'xterm': 'U2R'
        }
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def get_feature_importance_data(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        top_n: int = 20
    ) -> pd.DataFrame:
        """
        Calculate feature importance using Random Forest.
        
        Args:
            X: Feature matrix
            y: Target labels
            top_n: Number of top features to return
        
        Returns:
            DataFrame with features and their importance scores
        """
        from sklearn.ensemble import RandomForestClassifier
        
        logger.info("Calculating feature importance...")
        
        rf = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            max_depth=10
        )
        rf.fit(X, y)
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False).head(top_n)
        
        logger.info(f"Top {top_n} most important features calculated")
        
        return importance_df
    
    def create_attack_summary(
        self,
        df: pd.DataFrame,
        target_column: str = 'attack_type'
    ) -> pd.DataFrame:
        """
        Create summary statistics of attack types.
        
        Args:
            df: DataFrame containing attack data
            target_column: Name of the attack type column
        
        Returns:
            DataFrame with attack statistics
        """
        if target_column not in df.columns:
            logger.warning(f"Column '{target_column}' not found")
            return None
        
        attack_counts = df[target_column].value_counts()
        attack_percentages = df[target_column].value_counts(normalize=True) * 100
        
        summary = pd.DataFrame({
            'count': attack_counts,
            'percentage': attack_percentages
        })
        
        logger.info("Attack summary created")
        
        return summary
    
    def get_preprocessing_stats(self) -> Dict:
        """Get preprocessing statistics."""
        return self.preprocessing_stats
    
    def save_preprocessed_data(
        self,
        X: pd.DataFrame,
        y: Optional[pd.Series],
        y_binary: Optional[pd.Series],
        output_dir: str = 'data/processed'
    ):
        """
        Save preprocessed data to disk.
        
        Args:
            X: Feature matrix
            y: Original labels
            y_binary: Binary labels
            output_dir: Directory to save files
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Save features
        X.to_csv(f"{output_dir}/X.csv", index=False)
        logger.info(f"Saved features to {output_dir}/X.csv")
        
        # Save labels
        if y is not None:
            y.to_csv(f"{output_dir}/y.csv", index=False)
            logger.info(f"Saved labels to {output_dir}/y.csv")
        
        if y_binary is not None:
            y_binary.to_csv(f"{output_dir}/y_binary.csv", index=False)
            logger.info(f"Saved binary labels to {output_dir}/y_binary.csv")
        
        # Save feature names
        with open(f"{output_dir}/feature_names.txt", 'w') as f:
            f.write('\n'.join(self.feature_names))
        logger.info(f"Saved feature names to {output_dir}/feature_names.txt")
    
    def load_preprocessed_data(
        self,
        input_dir: str = 'data/processed'
    ) -> Tuple[pd.DataFrame, Optional[pd.Series], Optional[pd.Series]]:
        """
        Load preprocessed data from disk.
        
        Args:
            input_dir: Directory containing saved files
        
        Returns:
            Tuple of (X, y, y_binary)
        """
        X = pd.read_csv(f"{input_dir}/X.csv")
        
        y = None
        if os.path.exists(f"{input_dir}/y.csv"):
            y = pd.read_csv(f"{input_dir}/y.csv").squeeze()
        
        y_binary = None
        if os.path.exists(f"{input_dir}/y_binary.csv"):
            y_binary = pd.read_csv(f"{input_dir}/y_binary.csv").squeeze()
        
        # Load feature names
        if os.path.exists(f"{input_dir}/feature_names.txt"):
            with open(f"{input_dir}/feature_names.txt", 'r') as f:
                self.feature_names = [line.strip() for line in f]
        
        logger.info(f"Loaded preprocessed data from {input_dir}")
        
        return X, y, y_binary


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Preprocess network intrusion detection datasets'
    )
    parser.add_argument(
        '--dataset',
        type=str,
        choices=['NSL-KDD', 'CICIDS2017', 'UNSW-NB15'],
        default='NSL-KDD',
        help='Dataset type'
    )
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Input data file path'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/processed',
        help='Output directory for preprocessed data'
    )
    parser.add_argument(
        '--test-size',
        type=float,
        default=0.2,
        help='Test set size (0.0 to 1.0)'
    )
    parser.add_argument(
        '--normalize',
        action='store_true',
        default=True,
        help='Normalize numerical features'
    )
    
    args = parser.parse_args()
    
    # Initialize preprocessor
    preprocessor = NetworkDataPreprocessor(dataset_type=args.dataset)
    
    # Load data
    print(f"Loading {args.dataset} dataset from {args.input}...")
    df = preprocessor.load_data(args.input)
    
    # Preprocess
    print("Preprocessing data...")
    X, y, y_binary = preprocessor.preprocess_data(
        df,
        normalize=args.normalize,
        test_size=args.test_size
    )
    
    # Save preprocessed data
    print(f"Saving preprocessed data to {args.output}...")
    preprocessor.save_preprocessed_data(X, y, y_binary, args.output)
    
    # Display statistics
    print("\n" + "=" * 60)
    print("PREPROCESSING STATISTICS")
    print("=" * 60)
    stats = preprocessor.get_preprocessing_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    # Display attack summary
    if y is not None:
        print("\n" + "=" * 60)
        print("ATTACK DISTRIBUTION")
        print("=" * 60)
        summary = preprocessor.create_attack_summary(df)
        print(summary)
    
    print("\nPreprocessing complete!")


if __name__ == "__main__":
    # Check if run as script
    if len(sys.argv) > 1:
        main()
    else:
        # Demo mode
        print("=" * 80)
        print("LLM-Guided Explainable IDS - Data Preprocessing Module")
        print("=" * 80)
        
        preprocessor = NetworkDataPreprocessor(dataset_type='NSL-KDD')
        
        print("\n[INFO] Preprocessor initialized for NSL-KDD dataset")
        print("\nSupported datasets:")
        print("  1. NSL-KDD (KDD Cup 99 improved)")
        print("  2. CICIDS2017 (Canadian Institute for Cybersecurity)")
        print("  3. UNSW-NB15 (University of New South Wales)")
        
        print("\n[INFO] Usage:")
        print("  # As module")
        print("  from data_preprocessing import NetworkDataPreprocessor")
        print("  preprocessor = NetworkDataPreprocessor('NSL-KDD')")
        print("  df = preprocessor.load_nsl_kdd('path/to/data.csv')")
        print("  X, y, y_binary = preprocessor.preprocess_data(df)")
        
        print("\n  # As command-line tool")
        print("  python data_preprocessing.py --dataset NSL-KDD --input data.csv")
        
        print("\n[INFO] Features:")
        print("  Automatic missing value handling")
        print("  Categorical encoding")
        print("  Feature normalization")
        print("  Attack type mapping")
        print("  Binary label generation")
        print("  Feature importance analysis")
        
        print("\n" + "=" * 80)