import torch
import torch.nn.functional as F
import numpy as np
from tqdm import tqdm
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support, 
                             roc_auc_score)

# Local Imports
from config import Config, Logger

class Trainer:
    def __init__(self, model, device, optimizer, scheduler, criterion):
        self.model = model
        self.device = device
        self.optimizer = optimizer
        self.scheduler = scheduler
        self.criterion = criterion
        self.history = {
            'train_loss': [], 'train_acc': [],
            'val_loss': [], 'val_acc': [], 'val_f1': [], 'val_auc': []
        }
        self.best_f1 = 0
    
    def train_epoch(self, data_loader):
        self.model.train()
        total_loss = 0
        predictions, true_labels = [], []
        
        progress_bar = tqdm(data_loader, desc="Training")
        
        try:
            for batch in progress_bar:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                features = batch['features'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                self.optimizer.zero_grad()
                logits = self.model(input_ids, attention_mask, features)
                loss = self.criterion(logits, labels)
                
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                self.optimizer.step()
                self.scheduler.step()
                
                total_loss += loss.item()
                preds = torch.argmax(logits, dim=1)
                predictions.extend(preds.cpu().numpy())
                true_labels.extend(labels.cpu().numpy())
                
                progress_bar.set_postfix({'loss': f'{loss.item():.4f}'})
            
            avg_loss = total_loss / len(data_loader)
            accuracy = accuracy_score(true_labels, predictions)
            
            return avg_loss, accuracy
            
        except Exception as e:
            Logger.error(f"Training epoch failed: {str(e)}")
            raise
    
    def evaluate(self, data_loader, desc="Evaluating"):
        self.model.eval()
        total_loss = 0
        predictions, true_labels, probs = [], [], []
        
        try:
            with torch.no_grad():
                for batch in tqdm(data_loader, desc=desc):
                    input_ids = batch['input_ids'].to(self.device)
                    attention_mask = batch['attention_mask'].to(self.device)
                    features = batch['features'].to(self.device)
                    labels = batch['labels'].to(self.device)
                    
                    logits = self.model(input_ids, attention_mask, features)
                    loss = self.criterion(logits, labels)
                    total_loss += loss.item()
                    
                    prob = F.softmax(logits, dim=1)
                    preds = torch.argmax(logits, dim=1)
                    
                    predictions.extend(preds.cpu().numpy())
                    true_labels.extend(labels.cpu().numpy())
                    probs.extend(prob[:, 1].cpu().numpy())
            
            accuracy = accuracy_score(true_labels, predictions)
            precision, recall, f1, _ = precision_recall_fscore_support(
                true_labels, predictions, average='binary', pos_label=1, zero_division=0
            )
            
            try:
                auc = roc_auc_score(true_labels, probs)
            except:
                auc = 0.0
            
            return {
                'loss': total_loss / len(data_loader),
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'auc': auc,
                'predictions': predictions,
                'true_labels': true_labels,
                'probs': probs
            }
            
        except Exception as e:
            Logger.error(f"Evaluation failed: {str(e)}")
            raise
    
    def save_checkpoint(self, epoch, filepath):
        try:
            torch.save({
                'epoch': epoch,
                'model_state_dict': self.model.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict(),
                'scheduler_state_dict': self.scheduler.state_dict(),
                'f1_score': self.best_f1,
                'history': self.history
            }, filepath)
            Logger.success(f"Checkpoint saved: {filepath}")
        except Exception as e:
            Logger.error(f"Failed to save checkpoint: {str(e)}")
            raise
    
    def load_checkpoint(self, filepath):
        try:
            checkpoint = torch.load(filepath, map_location=self.device)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            if 'scheduler_state_dict' in checkpoint:
                self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
            self.best_f1 = checkpoint.get('f1_score', 0)
            self.history = checkpoint.get('history', self.history)
            Logger.success(f"Checkpoint loaded from {filepath}")
            return checkpoint.get('epoch', 0)
        except Exception as e:
            Logger.error(f"Failed to load checkpoint: {str(e)}")
            raise

