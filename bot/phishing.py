# bot/phishing.py
import re
from urllib.parse import urlparse
from datetime import datetime
import tldextract


class PhishingDetector:
    """Detector de e-mails de phishing"""
    
    def __init__(self):
        # Palavras suspeitas no assunto/corpo
        self.suspicious_words = [
            # Urgência
            'urgente', 'urgent', 'imediato', 'immediate', 'ação requerida',
            'action required', 'expire', 'expira', 'suspens', 'bloqueado',
            'blocked', 'limited', 'limitado', 'verify', 'verificar',"sua conta esta bloqueada"
            
            # Financeiro
            'senha', 'password', 'cartão', 'card', 'banco', 'bank',
            'conta', 'account', 'pix', 'transferência', 'transfer',
            'pagamento', 'payment', 'fatura', 'invoice', 'boleto',
            'prêmio', 'prize', 'ganhou', 'winner', 'lottery', 'loteria',
            'herança', 'inheritance', 'milhões', 'millions','voce ganhou','pague agora'
            
            # Ameaças
            'encerrar', 'cancelar', 'cancel', 'desativar', 'deactivate',
            'unauthorized', 'não autorizado', 'suspicious activity',
            'atividade suspeita', 'security alert', 'alerta de segurança',
            
            # Ação
            'clique aqui', 'click here', 'acesse agora', 'access now',
            'atualize', 'update', 'confirme', 'confirm', 'validate',
            'validar', 'reset', 'redefinir'
        ]
        
        # Domínios legítimos (whitelist)
        self.trusted_domains = [
            'google.com', 'gmail.com', 'microsoft.com', 'outlook.com',
            'apple.com', 'amazon.com', 'facebook.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'github.com', 'netflix.com',
            'spotify.com', 'paypal.com', 'mercadolivre.com.br',
            'nubank.com.br', 'itau.com.br', 'bradesco.com.br',
            'santander.com.br', 'bb.com.br', 'caixa.gov.br'
        ]
        
        # Domínios conhecidos de phishing (blacklist)
        self.blacklisted_patterns = [
            r'.*\.tk$', r'.*\.ml$', r'.*\.ga$', r'.*\.cf$', r'.*\.gq$',  # TLDs suspeitos
            r'.*-secure.*', r'.*-login.*', r'.*-verify.*', r'.*-update.*',
            r'.*account.*\..*\..*',  # Subdomínios suspeitos
            r'.*\d{5,}.*',  # Muitos números
        ]
        
        # Padrões de URL suspeita
        self.suspicious_url_patterns = [
            r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co', r'ow\.ly',  # Encurtadores
            r'@',  # URL com @ (redirecionamento)
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP direto
            r'\.php\?', r'\.asp\?',  # Scripts com parâmetros
        ]
    
    def analyze_email(self, email_data: dict) -> dict:
        """
        Analisa um e-mail e retorna score de phishing
        
        Returns:
            dict com score (0-100), is_phishing, reasons, risk_level
        """
        score = 0
        reasons = []
        
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        sender = email_data.get('sender', '').lower()
        sender_email = email_data.get('sender_email', '').lower()
        
        # ===== 1. ANÁLISE DO REMETENTE =====
        sender_score, sender_reasons = self._analyze_sender(sender_email, sender)
        score += sender_score
        reasons.extend(sender_reasons)
        
        # ===== 2. ANÁLISE DO ASSUNTO =====
        subject_score, subject_reasons = self._analyze_subject(subject)
        score += subject_score
        reasons.extend(subject_reasons)
        
        # ===== 3. ANÁLISE DO CORPO =====
        body_score, body_reasons = self._analyze_body(body)
        score += body_score
        reasons.extend(body_reasons)
        
        # ===== 4. ANÁLISE DE URLs =====
        urls = self._extract_urls(body)
        url_score, url_reasons = self._analyze_urls(urls)
        score += url_score
        reasons.extend(url_reasons)
        
        # ===== 5. ANÁLISE DE ANEXOS =====
        if email_data.get('has_attachments'):
            attachment_reasons = self._check_attachment_context(subject, body)
            if attachment_reasons:
                score += 15
                reasons.extend(attachment_reasons)
        
        # Limitar score a 100
        score = min(score, 100)
        
        # Determinar nível de risco
        if score >= 70:
            risk_level = "CRÍTICO"
            is_phishing = True
        elif score >= 50:
            risk_level = "ALTO"
            is_phishing = True
        elif score >= 30:
            risk_level = "MÉDIO"
            is_phishing = False
        elif score >= 15:
            risk_level = "BAIXO"
            is_phishing = False
        else:
            risk_level = "SEGURO"
            is_phishing = False
        
        return {
            'score': score,
            'is_phishing': is_phishing,
            'risk_level': risk_level,
            'reasons': reasons,
            'analyzed_at': datetime.now().isoformat(),
            'urls_found': urls
        }
    
    def _analyze_sender(self, sender_email: str, sender_name: str) -> tuple:
        """Analisa o remetente"""
        score = 0
        reasons = []
        
        if not sender_email:
            score += 20
            reasons.append("Remetente sem e-mail visível")
            return score, reasons
        
        # Extrair domínio
        try:
            ext = tldextract.extract(sender_email.split('@')[-1])
            domain = f"{ext.domain}.{ext.suffix}"
        except:
            domain = sender_email.split('@')[-1] if '@' in sender_email else ''
        
        # Verificar se é domínio confiável
        if domain and domain not in self.trusted_domains:
            # Verificar padrões suspeitos
            for pattern in self.blacklisted_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    score += 25
                    reasons.append(f"Domínio suspeito: {domain}")
                    break
        
        # Nome não combina com e-mail (spoofing)
        if sender_name:
            # Ex: Nome diz "Banco do Brasil" mas e-mail é xxx@gmail.com
            trusted_names = ['banco', 'bank', 'nubank', 'itau', 'bradesco', 'paypal', 'microsoft', 'apple', 'google']
            for name in trusted_names:
                if name in sender_name.lower():
                    if domain not in self.trusted_domains:
                        score += 30
                        reasons.append(f"Possível spoofing: '{sender_name}' com domínio '{domain}'")
                        break
        
        # E-mail com muitos números
        if re.search(r'\d{5,}', sender_email):
            score += 10
            reasons.append("E-mail com muitos números")
        
        return score, reasons
    
    def _analyze_subject(self, subject: str) -> tuple:
        """Analisa o assunto"""
        score = 0
        reasons = []
        
        # Contar palavras suspeitas
        suspicious_found = []
        for word in self.suspicious_words:
            if word in subject:
                suspicious_found.append(word)
        
        if len(suspicious_found) >= 3:
            score += 25
            reasons.append(f"Assunto muito suspeito: {', '.join(suspicious_found[:3])}")
        elif len(suspicious_found) >= 1:
            score += 10
            reasons.append(f"Palavras de alerta no assunto: {', '.join(suspicious_found[:2])}")
        
        # Muitos caracteres especiais
        special_chars = len(re.findall(r'[!?🚨⚠️🔴❗]', subject))
        if special_chars >= 3:
            score += 10
            reasons.append("Excesso de caracteres de urgência no assunto")
        
        # Todo em maiúsculas
        if subject.isupper() and len(subject) > 10:
            score += 10
            reasons.append("Assunto todo em maiúsculas")
        
        return score, reasons
    
    def _analyze_body(self, body: str) -> tuple:
        """Analisa o corpo do e-mail"""
        score = 0
        reasons = []
        
        # Contar palavras suspeitas
        suspicious_count = 0
        found_words = []
        for word in self.suspicious_words:
            count = body.count(word)
            if count > 0:
                suspicious_count += count
                found_words.append(word)
        
        if suspicious_count >= 10:
            score += 25
            reasons.append(f"Corpo com muitas palavras de phishing ({suspicious_count}x)")
        elif suspicious_count >= 5:
            score += 15
            reasons.append(f"Corpo suspeito: {', '.join(found_words[:3])}")
        
        # Solicita informações sensíveis
        sensitive_patterns = [
            r'(digite|informe|envie).*(senha|password|cpf|cartão|card)',
            r'(confirm|verificar).*(dados|account|conta)',
            r'(clique|click).*(link|botão|button).*(verificar|confirm)',
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                score += 20
                reasons.append("Solicita informações sensíveis")
                break
        
        # Erros de português (comum em phishing)
        grammar_errors = [
            r'voce\s', r'\bvc\b', r'pra\s', r'tá\s', r'agente\s(?!de)',
        ]
        error_count = sum(1 for p in grammar_errors if re.search(p, body))
        if error_count >= 2:
            score += 5
            reasons.append("Possíveis erros gramaticais")
        
        return score, reasons
    
    def _extract_urls(self, text: str) -> list:
        """Extrai URLs do texto"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        return list(set(urls))
    
    def _analyze_urls(self, urls: list) -> tuple:
        """Analisa URLs encontradas"""
        score = 0
        reasons = []
        
        if not urls:
            return score, reasons
        
        suspicious_urls = []
        
        for url in urls:
            url_lower = url.lower()
            
            # Verificar padrões suspeitos
            for pattern in self.suspicious_url_patterns:
                if re.search(pattern, url_lower):
                    suspicious_urls.append(url[:50])
                    break
            
            # URL muito longa
            if len(url) > 100:
                suspicious_urls.append(f"URL longa: {url[:30]}...")
            
            # Verificar domínio
            try:
                parsed = urlparse(url)
                ext = tldextract.extract(parsed.netloc)
                domain = f"{ext.domain}.{ext.suffix}"
                
                # Domínio imita marca conhecida
                fake_patterns = [
                    r'g[o0][o0]gle', r'faceb[o0][o0]k', r'amaz[o0]n',
                    r'micr[o0]s[o0]ft', r'paypai', r'netf[l1]ix',
                    r'app[l1]e', r'bank', r'secure', r'login'
                ]
                
                for pattern in fake_patterns:
                    if re.search(pattern, domain) and domain not in self.trusted_domains:
                        score += 20
                        reasons.append(f"URL imita marca conhecida: {domain}")
                        break
                
            except:
                pass
        
        if suspicious_urls:
            score += 15
            reasons.append(f"URLs suspeitas encontradas: {len(suspicious_urls)}")
        
        return score, reasons
    
    def _check_attachment_context(self, subject: str, body: str) -> list:
        """Verifica contexto de anexos"""
        reasons = []
        
        dangerous_context = [
            'fatura', 'invoice', 'nota fiscal', 'boleto', 'comprovante',
            'documento', 'contrato', 'pdf', 'planilha', 'excel'
        ]
        
        text = f"{subject} {body}"
        
        for context in dangerous_context:
            if context in text.lower():
                reasons.append(f"Anexo em contexto suspeito: '{context}'")
                break
        
        return reasons
    
    def get_risk_emoji(self, risk_level: str) -> str:
        """Retorna emoji baseado no nível de risco"""
        emojis = {
            'CRÍTICO': '🔴',
            'ALTO': '🟠',
            'MÉDIO': '🟡',
            'BAIXO': '🟢',
            'SEGURO': '✅'
        }
        return emojis.get(risk_level, '❓')