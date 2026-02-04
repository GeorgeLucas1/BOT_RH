# bot/extrair.py
import re


class EmailExtractor:
    
    def __init__(self):
        self.patterns = {
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'telefones': r'(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\s?)?\d{4}[-\s]?\d{4}',
            'cpfs': r'\d{3}\.?\d{3}\.?\d{3}[-.]?\d{2}',
            'cnpjs': r'\d{2}\.?\d{3}\.?\d{3}/?\d{4}[-.]?\d{2}',
            'valores': r'R\$\s*[\d.,]+',
            'datas': r'\d{2}/\d{2}/\d{4}',
            'urls': r'https?://[^\s<>"{}|\\^`\[\]]+'
        }
    
    def extract_all(self, text):
        results = {}
        
        if not text:
            return results
        
        for name, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            results[name] = list(set(matches))
        
        return results
    
    def extract_emails(self, text):
        return re.findall(self.patterns['emails'], text)
    
    def extract_phones(self, text):
        return re.findall(self.patterns['telefones'], text)