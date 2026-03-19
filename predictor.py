import torch
import torch.nn.functional as F
from transformers import AutoTokenizer
from tqdm import tqdm

# Local Imports
from config import Config, Logger
from model import EnhancedVulnClassifier

class VulnerabilityPredictor:
    def __init__(self, model_path, device=None):
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = device
        
        try:
            Logger.log("Loading model and tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(Config.PRETRAINED_MODEL)
            
            self.model = EnhancedVulnClassifier(
                pretrained_model_name=Config.PRETRAINED_MODEL,
                dropout_prob=Config.DROPOUT_PROB
            )
            
            checkpoint = torch.load(model_path, map_location=self.device)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()
            
            Logger.success(f"Model loaded successfully from {model_path}")
            
        except Exception as e:
            Logger.error(f"Failed to initialize predictor: {str(e)}")
            raise
    
    def predict(self, error_text, return_features=False):
        try:
            feature_tensor = torch.zeros(0, dtype=torch.float).unsqueeze(0).to(self.device)
            
            encoding = self.tokenizer.encode_plus(
                error_text,
                add_special_tokens=True,
                max_length=Config.MAX_LEN,
                padding='max_length',
                truncation=True,
                return_attention_mask=True,
                return_tensors='pt'
            )
            
            input_ids = encoding['input_ids'].to(self.device)
            attention_mask = encoding['attention_mask'].to(self.device)
            
            with torch.no_grad():
                logits = self.model(input_ids, attention_mask, feature_tensor)
                probabilities = F.softmax(logits, dim=1)
                predicted_class = torch.argmax(probabilities, dim=1).item()
                confidence = probabilities[0][predicted_class].item()
            
            # ========== NEW: CONFIDENCE CALIBRATION ==========
            confidence = self._calibrate_confidence(confidence, error_text)
            # ========== END NEW CODE ==========
            
            result = {
                'predicted_class': predicted_class,
                'class_name': 'Vulnerable' if predicted_class == 1 else 'Safe',
                'confidence': confidence,
                'probabilities': {
                    'safe': probabilities[0][0].item(),
                    'vulnerable': probabilities[0][1].item()
                },
                'confidence_level': self._get_confidence_level(confidence)
            }
            
            if return_features:
                result['features'] = {}
            
            return result
            
        except Exception as e:
            Logger.error(f"Prediction failed: {str(e)}")
            return {
                'error': str(e),
                'predicted_class': None,
                'class_name': 'Error',
                'confidence': 0.0
            }
    
    # ========== NEW METHOD: CONFIDENCE CALIBRATION ==========
    def _calibrate_confidence(self, confidence, text):
        """
        Reduce confidence for ambiguous cases to prevent overconfidence.
        ENHANCED with tool-specific pattern recognition.
        """
        text_lower = text.lower()
        
        # ========== TOOL-SPECIFIC BOOST ==========
        # If it's a security tool reporting vulnerability patterns, BOOST confidence
        vulnerability_tools = ['[bandit]', '[sonar', '[checkmarx]', '[fortify]', 
                               '[snyk]', '[semgrep]', '[cppcheck]', '[flawfinder]']
        
        vulnerability_keywords = [
            'insecure', 'unsafe', 'vulnerable', 'injection', 'overflow',
            'exploit', 'malicious', 'dangerous', 'attack', 'risk',
            'security implications', 'code execution', 'arbitrary code',
            'possible security', 'can lead to', 'results in potential'
        ]
        
        # Check if it's a tool reporting a vulnerability
        has_tool = any(tool in text_lower for tool in vulnerability_tools)
        has_vuln_keyword = any(kw in text_lower for kw in vulnerability_keywords)
        
        # If tool + vulnerability language + NOT marked as fixed
        fixed_markers = ['fixed', 'resolved', 'patched', 'remediated', 'historical', 
                        'false positive', 'not a risk', 'safe', 'passed']
        has_fixed_marker = any(marker in text_lower for marker in fixed_markers)
        
        if has_tool and has_vuln_keyword and not has_fixed_marker:
            # This looks like a real vulnerability report - BOOST confidence
            confidence = min(0.95, confidence * 1.15)  # Boost by 15%, cap at 95%
            return confidence
        # ========== END TOOL-SPECIFIC BOOST ==========
        
        # Ambiguity indicators (original logic)
        ambiguous_keywords = [
            'analysis', 'review', 'documentation', 'module', 
            'component', 'specification', 'assessment', 'evaluation',
            'function', 'implementation', 'study', 'reference',
            'overview', 'description', 'definition', 'interface'
        ]
        
        # Count ambiguity signals
        ambiguity_score = sum(1 for kw in ambiguous_keywords if kw in text_lower)
        
        # Very short and ambiguous text
        word_count = len(text.split())
        if word_count < 15 and ambiguity_score >= 2:
            confidence *= 0.70  # Reduce by 30%
        
        # Mentions CWE but no clear vulnerability markers
        vulnerability_markers = [
            'overflow', 'injection', 'vulnerable', 'exploitable', 
            'risk', 'unsafe', 'insecure', 'dangerous', 'attack',
            'exploit', 'malicious', 'threat'
        ]
        
        has_cwe = 'cwe-' in text_lower
        has_vuln_marker = any(marker in text_lower for marker in vulnerability_markers)
        
        if has_cwe and not has_vuln_marker and ambiguity_score > 0:
            confidence *= 0.80  # Reduce by 20%
        
        # Generic technical terms without context
        if word_count < 10 and ambiguity_score >= 1:
            confidence *= 0.75  # Reduce by 25%
        
        # Very generic statements
        generic_patterns = ['code location', 'line', 'file:', 'src/']
        if any(pattern in text_lower for pattern in generic_patterns) and word_count < 12:
            confidence *= 0.85  # Reduce by 15%
        
        return confidence
    # ========== END NEW METHOD ==========
    
    def predict_batch(self, error_texts):
        results = []
        for text in tqdm(error_texts, desc="Predicting"):
            results.append(self.predict(text))
        return results
    
    @staticmethod
    def _get_confidence_level(confidence):
        if confidence >= Config.CONFIDENCE_THRESHOLD_HIGH:
            return "HIGH"
        elif confidence >= Config.CONFIDENCE_THRESHOLD_MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
