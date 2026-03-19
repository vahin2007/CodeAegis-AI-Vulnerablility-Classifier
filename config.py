import os
import random
import numpy as np
import torch
from datetime import datetime

# ==================== CONFIGURATION ====================
class Config:
    MODEL_DIR = 'models'
    DATA_DIR = 'data'
    RESULTS_DIR = 'results'
    
    BEST_MODEL_PATH = os.path.join(MODEL_DIR, 'best_model_minimal.pth')
    FULL_DATA_PATH = os.path.join(DATA_DIR, 'full_dataset_minimal.csv')
    TRAIN_DATA_PATH = os.path.join(DATA_DIR, 'train_dataset_minimal.csv')
    VAL_DATA_PATH = os.path.join(DATA_DIR, 'val_dataset_minimal.csv')
    TEST_DATA_PATH = os.path.join(DATA_DIR, 'test_dataset_minimal.csv')
    RESULTS_PATH = os.path.join(RESULTS_DIR, 'test_results_minimal.json')
    REPORT_PATH = os.path.join(RESULTS_DIR, 'classification_report_minimal.txt')
    
    RANDOM_SEED = 42
    SAMPLES_PER_CATEGORY = 500     
    AUGMENTATION_FACTOR = 4         
    ADVERSARIAL_SAMPLES = 1000      
    RESOLVED_VULN_SAMPLES = 1500    
    EPOCHS = 20                 
    BATCH_SIZE = 16
    MAX_LEN = 256
    LEARNING_RATE = 1.5e-5          
    PRETRAINED_MODEL = 'bert-base-uncased'
    
    USE_CLASS_WEIGHTS = True
    USE_FOCAL_LOSS = True
    LABEL_SMOOTHING = 0.05        
    DROPOUT_PROB = 0.3           
    
    CONFIDENCE_THRESHOLD_HIGH = 0.90
    CONFIDENCE_THRESHOLD_MEDIUM = 0.75
    
    @classmethod
    def create_directories(cls):
        for dir_path in [cls.MODEL_DIR, cls.DATA_DIR, cls.RESULTS_DIR]:
            os.makedirs(dir_path, exist_ok=True)

def set_seed(seed=42):
    torch.manual_seed(seed)
    np.random.seed(seed)
    random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

set_seed(Config.RANDOM_SEED)
Config.create_directories()

# ==================== LOGGER ====================
class Logger:
    @staticmethod
    def log(message, level='INFO'):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    @staticmethod
    def section(title):
        print("\n" + "=" * 80)
        print(f"  {title}")
        print("=" * 80)
    
    @staticmethod
    def subsection(title):
        print("\n" + "-" * 80)
        print(f"  {title}")
        print("-" * 80)
    
    @staticmethod
    def success(message):
        Logger.log(f"✓ {message}", 'SUCCESS')
    
    @staticmethod
    def error(message):
        Logger.log(f"✗ {message}", 'ERROR')
    
    @staticmethod
    def warning(message):
        Logger.log(f"⚠ {message}", 'WARNING')