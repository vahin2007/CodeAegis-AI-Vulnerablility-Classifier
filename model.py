import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset
from transformers import AutoModel

# Local Imports
from config import Logger

def extract_features(log_text):
    """NO FEATURES - Force BERT to learn everything from text."""
    return {}

class VulnDataset(Dataset):
    """Dataset without any engineered features"""
    
    def __init__(self, dataframe, tokenizer, max_len=256):
        self.tokenizer = tokenizer
        self.max_len = max_len
        self.error_logs = dataframe['error_log'].values
        self.labels = dataframe['label'].values
    
    def __len__(self):
        return len(self.error_logs)
    
    def __getitem__(self, idx):
        try:
            error_log = str(self.error_logs[idx])
            label = self.labels[idx]
            
            encoding = self.tokenizer.encode_plus(
                error_log,
                add_special_tokens=True,
                max_length=self.max_len,
                padding='max_length',
                truncation=True,
                return_attention_mask=True,
                return_tensors='pt'
            )
            
            feature_tensor = torch.zeros(0, dtype=torch.float)
            
            return {
                'input_ids': encoding['input_ids'].flatten(),
                'attention_mask': encoding['attention_mask'].flatten(),
                'features': feature_tensor,
                'labels': torch.tensor(label, dtype=torch.long)
            }
        except Exception as e:
            Logger.error(f"Error loading item {idx}: {str(e)}")
            raise


class FocalLoss(nn.Module):
    def __init__(self, alpha=0.25, gamma=2.0, label_smoothing=0.0, reduction='mean'):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.label_smoothing = label_smoothing
        self.reduction = reduction
    
    def forward(self, inputs, targets):
        num_classes = inputs.shape[-1]
        if self.label_smoothing > 0:
            one_hot = torch.zeros_like(inputs)
            one_hot.scatter_(1, targets.unsqueeze(1), 1)
            smooth_targets = one_hot * (1 - self.label_smoothing) + self.label_smoothing / num_classes
            log_probs = F.log_softmax(inputs, dim=1)
            ce_loss = -(smooth_targets * log_probs).sum(dim=1)
        else:
            ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss
        
        if self.reduction == 'mean':
            return focal_loss.mean()
        return focal_loss


class EnhancedVulnClassifier(nn.Module):
    """Classifier with NO hand-crafted features - pure BERT"""
    
    def __init__(self, n_classes=2, pretrained_model_name='bert-base-uncased', 
                 dropout_prob=0.3):
        super(EnhancedVulnClassifier, self).__init__()
        
        try:
            self.encoder = AutoModel.from_pretrained(pretrained_model_name)
        except Exception as e:
            Logger.error(f"Failed to load pretrained model: {str(e)}")
            raise
            
        hidden_size = self.encoder.config.hidden_size
        
        self.attention = nn.MultiheadAttention(
            hidden_size, num_heads=8, 
            dropout=dropout_prob, batch_first=True
        )
        
        self.dropout = nn.Dropout(dropout_prob)
        
        self.fc1 = nn.Linear(hidden_size, 512)
        self.bn1 = nn.BatchNorm1d(512)
        self.fc2 = nn.Linear(512, 128)
        self.bn2 = nn.BatchNorm1d(128)
        self.fc3 = nn.Linear(128, n_classes)
    
    def forward(self, input_ids, attention_mask, features=None):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        sequence_output = outputs.last_hidden_state
        
        attn_output, _ = self.attention(
            sequence_output, sequence_output, sequence_output,
            key_padding_mask=~attention_mask.bool()
        )
        
        pooled = (attn_output * attention_mask.unsqueeze(-1)).sum(1) / \
                 attention_mask.sum(1, keepdim=True)
        
        x = self.dropout(pooled)
        x = F.relu(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = F.relu(self.bn2(self.fc2(x)))
        x = self.dropout(x)
        logits = self.fc3(x)
        
        return logits
