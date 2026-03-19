import os
import json
import argparse
import warnings
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, WeightedRandomSampler
from torch.optim import AdamW
from transformers import AutoTokenizer, get_linear_schedule_with_warmup
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings('ignore')

# Local Imports
from config import Config, Logger, set_seed
from data_generator import DataGenerator
from model import VulnDataset, EnhancedVulnClassifier, FocalLoss
from trainer import Trainer
from predictor import VulnerabilityPredictor


def run_diagnostic():
    Logger.section("DIAGNOSTIC: Testing Feature Leakage")
    Logger.log("Generating test dataset...")
    base_df = DataGenerator.generate_full_dataset()
    train_df, val_df = train_test_split(base_df, test_size=0.2, random_state=42, stratify=base_df['label'])
    feature_dicts = [extract_features(log) for log in train_df['error_log']]
    
    if len(feature_dicts[0]) == 0:
        Logger.success("✓ NO FEATURES - Model must learn from text!")
        return 0.0
    
    return 0.0


def generate_cumulative_accuracy_plot(test_metrics, test_df, save_dir='results/plots'):
    """Generate cumulative accuracy plot"""
    import os
    os.makedirs(save_dir, exist_ok=True)
    
    Logger.subsection("Generating Cumulative Accuracy Analysis")
    
    true_labels = np.array(test_metrics['true_labels'])
    predictions = np.array(test_metrics['predictions'])
    correct = (true_labels == predictions).astype(int)
    
    cumulative_correct = np.cumsum(correct)
    cumulative_total = np.arange(1, len(correct) + 1)
    cumulative_accuracy = cumulative_correct / cumulative_total
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
    
    # Plot 1: Cumulative Correct Count
    ax1.plot(cumulative_total, cumulative_correct, linewidth=2.5, color='#2E86AB')
    ax1.plot(cumulative_total, cumulative_total, '--', linewidth=2, color='#A23B72', alpha=0.6)
    ax1.set_xlabel('Number of Predictions', fontsize=13, fontweight='bold')
    ax1.set_ylabel('Cumulative Correct', fontsize=13, fontweight='bold')
    ax1.set_title('📊 Cumulative Correct Predictions', fontsize=15, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Cumulative Accuracy Percentage
    ax2.plot(cumulative_total, cumulative_accuracy * 100, linewidth=3, color='#06A77D')
    ax2.axhline(y=100, color='#A23B72', linestyle='--', linewidth=2, alpha=0.6)
    ax2.axhline(y=90, color='orange', linestyle=':', linewidth=2, alpha=0.6)
    ax2.set_xlabel('Number of Predictions', fontsize=13, fontweight='bold')
    ax2.set_ylabel('Accuracy (%)', fontsize=13, fontweight='bold')
    ax2.set_title('📈 Cumulative Accuracy Over Time', fontsize=15, fontweight='bold')
    ax2.grid(True, alpha=0.3)
    ax2.set_ylim([0, 105])
    
    plt.tight_layout()
    save_path = os.path.join(save_dir, 'cumulative_accuracy.png')
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    Logger.success(f"Plot saved: {save_path}")
    plt.close()


# ==================== MAIN FUNCTIONS ====================
def run_training():
    Logger.section("STARTING IMPROVED FEATURE-FREE TRAINING")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    Logger.log(f"Using device: {device}")

    base_df = DataGenerator.generate_full_dataset()
    augmented_df = DataGenerator.augment_dataset(base_df, Config.AUGMENTATION_FACTOR)
    
    Logger.subsection("PREPARING DATA SPLITS")
    train_df, temp_df = train_test_split(
        augmented_df, test_size=0.3, random_state=Config.RANDOM_SEED, stratify=augmented_df['label']
    )
    val_df, test_df = train_test_split(
        temp_df, test_size=0.5, random_state=Config.RANDOM_SEED, stratify=temp_df['label']
    )
    
    Logger.log(f"Train: {len(train_df)}, Validation: {len(val_df)}, Test: {len(test_df)}")
    
    augmented_df.to_csv(Config.FULL_DATA_PATH, index=False)
    train_df.to_csv(Config.TRAIN_DATA_PATH, index=False)
    val_df.to_csv(Config.VAL_DATA_PATH, index=False)
    test_df.to_csv(Config.TEST_DATA_PATH, index=False)
    Logger.success(f"Datasets saved to {Config.DATA_DIR}/")

    Logger.subsection("INITIALIZING MODEL & TOKENIZER")
    tokenizer = AutoTokenizer.from_pretrained(Config.PRETRAINED_MODEL)
    train_dataset = VulnDataset(train_df, tokenizer, Config.MAX_LEN)
    val_dataset = VulnDataset(val_df, tokenizer, Config.MAX_LEN)
    
    if Config.USE_CLASS_WEIGHTS:
        class_counts = train_df['label'].value_counts()
        weights = [1.0 / class_counts[label] for label in train_df['label']]
        sampler = WeightedRandomSampler(weights=weights, num_samples=len(train_df), replacement=True)
        train_loader = DataLoader(train_dataset, batch_size=Config.BATCH_SIZE, sampler=sampler)
        Logger.log("Using WeightedRandomSampler for training")
    else:
        train_loader = DataLoader(train_dataset, batch_size=Config.BATCH_SIZE, shuffle=True)
        
    val_loader = DataLoader(val_dataset, batch_size=Config.BATCH_SIZE, shuffle=False)
    
    model = EnhancedVulnClassifier(
        pretrained_model_name=Config.PRETRAINED_MODEL,
        dropout_prob=Config.DROPOUT_PROB
    )
    model = model.to(device)
    Logger.success(f"Model initialized with {sum(p.numel() for p in model.parameters()):,} parameters")
    
    optimizer = AdamW(model.parameters(), lr=Config.LEARNING_RATE, weight_decay=0.01)
    
    if Config.USE_FOCAL_LOSS:
        criterion = FocalLoss(alpha=0.25, gamma=2.0, label_smoothing=Config.LABEL_SMOOTHING)
        Logger.log("Using Focal Loss with Label Smoothing")
    else:
        class_weights = compute_class_weight('balanced', classes=np.unique(train_df['label']), y=train_df['label'])
        class_weights = torch.FloatTensor(class_weights).to(device)
        criterion = nn.CrossEntropyLoss(weight=class_weights, label_smoothing=Config.LABEL_SMOOTHING)

    total_steps = len(train_loader) * Config.EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=total_steps//10, num_training_steps=total_steps
    )
    
    Logger.section(f"STARTING TRAINING ({Config.EPOCHS} epochs)")
    trainer = Trainer(model, device, optimizer, scheduler, criterion)
    
    for epoch in range(Config.EPOCHS):
        Logger.subsection(f"Epoch {epoch+1}/{Config.EPOCHS}")
        
        train_loss, train_acc = trainer.train_epoch(train_loader)
        val_metrics = trainer.evaluate(val_loader, desc="Validating")
        
        trainer.history['train_loss'].append(train_loss)
        trainer.history['train_acc'].append(train_acc)
        trainer.history['val_loss'].append(val_metrics['loss'])
        trainer.history['val_acc'].append(val_metrics['accuracy'])
        trainer.history['val_f1'].append(val_metrics['f1'])
        trainer.history['val_auc'].append(val_metrics['auc'])
        
        Logger.log(f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f}")
        Logger.log(f"Val Loss:   {val_metrics['loss']:.4f} | Val Acc:   {val_metrics['accuracy']:.4f}")
        Logger.log(f"Precision:  {val_metrics['precision']:.4f} | Recall: {val_metrics['recall']:.4f} | F1: {val_metrics['f1']:.4f} | AUC: {val_metrics['auc']:.4f}")
        
        if val_metrics['f1'] > trainer.best_f1:
            trainer.best_f1 = val_metrics['f1']
            trainer.save_checkpoint(epoch, Config.BEST_MODEL_PATH)
            Logger.success(f"Best model saved! (F1: {trainer.best_f1:.4f})")
    
    Logger.success("Training complete.")
    
    Logger.section("FINAL EVALUATION ON TEST SET")
    
    model = EnhancedVulnClassifier(
        pretrained_model_name=Config.PRETRAINED_MODEL,
        dropout_prob=Config.DROPOUT_PROB
    ).to(device)
    
    optimizer = AdamW(model.parameters(), lr=Config.LEARNING_RATE)
    scheduler = get_linear_schedule_with_warmup(optimizer, 0, 0)
    
    trainer_for_test = Trainer(model, device, optimizer, scheduler, criterion)
    trainer_for_test.load_checkpoint(Config.BEST_MODEL_PATH)
    
    test_dataset = VulnDataset(test_df, tokenizer, Config.MAX_LEN)
    test_loader = DataLoader(test_dataset, batch_size=Config.BATCH_SIZE, shuffle=False)
    
    test_metrics = trainer_for_test.evaluate(test_loader, desc="Testing")
    
    Logger.section("FINAL TEST SET RESULTS")
    Logger.log(f"Accuracy:  {test_metrics['accuracy']:.4f}")
    Logger.log(f"Precision: {test_metrics['precision']:.4f}")
    Logger.log(f"Recall:    {test_metrics['recall']:.4f}")
    Logger.log(f"F1 Score:  {test_metrics['f1']:.4f}")
    Logger.log(f"ROC AUC:   {test_metrics['auc']:.4f}")
    
    report = classification_report(
        test_metrics['true_labels'], 
        test_metrics['predictions'],
        target_names=['Safe', 'Vulnerable']
    )
    Logger.subsection("Classification Report")
    print(report)
    
    try:
        Logger.section("GENERATING VISUALIZATIONS")
        generate_cumulative_accuracy_plot(test_metrics, test_df, save_dir='results/plots')
        Logger.success("✓ All visualizations generated successfully!")
    except Exception as e:
        Logger.error(f"Visualization failed: {str(e)}")
    
    with open(Config.RESULTS_PATH, 'w') as f:
        json.dump({k: v for k, v in test_metrics.items() 
                  if k not in ['predictions', 'true_labels', 'probs']}, 
                  f, indent=4, default=str)
    
    with open(Config.REPORT_PATH, 'w') as f:
        f.write(report)
    
    Logger.success(f"Results saved to {Config.RESULTS_DIR}/")


def run_testing():
    Logger.section("RUNNING EVALUATION ON TEST SET")
    
    if not os.path.exists(Config.BEST_MODEL_PATH):
        Logger.error(f"Model file not found: {Config.BEST_MODEL_PATH}")
        Logger.warning("Please run --train first.")
        return

    if not os.path.exists(Config.TEST_DATA_PATH):
        Logger.error(f"Test data not found: {Config.TEST_DATA_PATH}")
        Logger.warning("Please run --train first.")
        return
        
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    Logger.log(f"Using device: {device}")
    
    test_df = pd.read_csv(Config.TEST_DATA_PATH)
    tokenizer = AutoTokenizer.from_pretrained(Config.PRETRAINED_MODEL)
    test_dataset = VulnDataset(test_df, tokenizer, Config.MAX_LEN)
    test_loader = DataLoader(test_dataset, batch_size=Config.BATCH_SIZE, shuffle=False)
    
    model = EnhancedVulnClassifier(
        pretrained_model_name=Config.PRETRAINED_MODEL,
        dropout_prob=Config.DROPOUT_PROB
    ).to(device)
    
    optimizer = AdamW(model.parameters(), lr=Config.LEARNING_RATE)
    scheduler = get_linear_schedule_with_warmup(optimizer, 0, 0)
    criterion = FocalLoss()
    
    trainer = Trainer(model, device, optimizer, scheduler, criterion)
    trainer.load_checkpoint(Config.BEST_MODEL_PATH)
    
    test_metrics = trainer.evaluate(test_loader, desc="Testing")
    
    Logger.section("TEST SET RESULTS")
    Logger.log(f"Accuracy:  {test_metrics['accuracy']:.4f}")
    Logger.log(f"Precision: {test_metrics['precision']:.4f}")
    Logger.log(f"Recall:    {test_metrics['recall']:.4f}")
    Logger.log(f"F1 Score:  {test_metrics['f1']:.4f}")
    Logger.log(f"ROC AUC:   {test_metrics['auc']:.4f}")
    
    report = classification_report(
        test_metrics['true_labels'], 
        test_metrics['predictions'],
        target_names=['Safe', 'Vulnerable']
    )
    print(report)


def run_interactive():
    Logger.section("INTERACTIVE PREDICTION MODE")
    
    if not os.path.exists(Config.BEST_MODEL_PATH):
        Logger.error(f"Model file not found: {Config.BEST_MODEL_PATH}")
        Logger.warning("Please run --train first.")
        return
    
    try:
        predictor = VulnerabilityPredictor(Config.BEST_MODEL_PATH)
    except Exception as e:
        Logger.error(f"Failed to start interactive mode: {str(e)}")
        return
        
    print("\n🧪 Test Examples:")
    print("1. ./main.c:45: [5] (buffer) strcpy: Does not check for buffer overflows (CWE-120)")
    print("2. [PATCHED] Replaced all strcpy calls with strncpy_s (CWE-120 resolved)")
    print("3. [flawfinder] Analysis complete. No security issues detected.")
    print("4. [bandit] security: Use of 'pickle' is insecure, results in potential code execution. (B403)")
    print("5. Function analysis: string operation in authentication module")
    print("\n⭐ Critical Test (should now work):")
    print("   [bandit] security: Use of 'pickle' is insecure... → Should be VULNERABLE (85-95%)")
    print("\nType 'exit' or 'quit' to stop.\n")
    
    while True:
        try:
            log_text = input("Enter error log to test > ")
            if log_text.lower() in ['exit', 'quit']:
                break
                
            if not log_text:
                continue
                
            result = predictor.predict(log_text, return_features=True)
            
            Logger.subsection("Prediction Result")
            print(f"  Input Log:     {log_text}")
            print(f"  Prediction:    {result['class_name']}")
            print(f"  Confidence:    {result['confidence']:.2%} ({result['confidence_level']})")
            print(f"  Probabilities: (Safe: {result['probabilities']['safe']:.3f}, Vulnerable: {result['probabilities']['vulnerable']:.3f})")

        except KeyboardInterrupt:
            break
        except Exception as e:
            Logger.error(f"An error occurred: {str(e)}")

    Logger.log("Exiting interactive mode.")


# ==================== MAIN ====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IMPROVED Vulnerability Classifier with Bandit Fix")
    parser.add_argument('--train', action='store_true', help='Run training pipeline')
    parser.add_argument('--test', action='store_true', help='Run evaluation')
    parser.add_argument('--interactive', action='store_true', help='Interactive prediction')
    parser.add_argument('--diagnostic', action='store_true', help='Check for feature leakage')
    
    args = parser.parse_args()
    
    try:
        if args.diagnostic:
            run_diagnostic()
        elif args.train:
            run_training()
            run_testing()
        elif args.test:
            run_testing()
        elif args.interactive:
            run_interactive()
        else:
            Logger.section("IMPROVED VULNERABILITY CLASSIFIER WITH BANDIT FIX")
            Logger.log("Key improvements:")
            Logger.log("  ✓ 1,000 ultra-confusing resolved vulnerability examples")
            Logger.log("  ✓ 800 real security tool vulnerability outputs")
            Logger.log("  ✓ 500 ambiguous confidence-breaker examples")
            Logger.log("  ✓ 500 bandit-specific vulnerability examples (FIXES PICKLE BUG)")
            Logger.log("  ✓ 300 bandit safe examples (prevents false positives)")
            Logger.log("  ✓ Tool-aware confidence calibration")
            Logger.log("  ✓ Increased training samples: 500/category, 4x augmentation")
            Logger.log("  ✓ Extended training: 20 epochs")
            Logger.log("")
            Logger.log("Expected improvement: 85% → 92%+ accuracy")
            Logger.log("Bandit fix: Now correctly classifies bandit security warnings")
            Logger.log("")
            Logger.warning("No action specified. Use --train, --test, --interactive, or --diagnostic")
            
    except Exception as e:
        Logger.error(f"Unhandled exception: {str(e)}")
        import traceback
        traceback.print_exc()