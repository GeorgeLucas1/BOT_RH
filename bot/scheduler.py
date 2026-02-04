# bot/scheduler.py
import os
import time
import schedule
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class EmailScheduler:
    """Agendador para verificação contínua de e-mails"""
    
    def __init__(self, email_reader, database, extractor, phishing_detector):
        self.reader = email_reader
        self.db = database
        self.extractor = extractor
        self.phishing = phishing_detector
        self.interval = int(os.getenv('CHECK_INTERVAL_MINUTES', 5))
        self.max_emails = int(os.getenv('MAX_EMAILS_PER_CHECK', 10))
        self.running = False
        self.stats = {
            'total_checked': 0,
            'phishing_detected': 0,
            'last_check': None,
            'started_at': None
        }
    
    def check_emails(self):
        """Verifica novos e-mails"""
        try:
            logger.info("=" * 50)
            logger.info("🔍 Verificando novos e-mails...")
            
            # Ir para inbox
            self.reader.page.goto(
                "https://mail.google.com/mail/u/0/#inbox", 
                wait_until="load"
            )
            time.sleep(3)
            
            # Contar e-mails
            total = self.reader.get_email_count()
            
            if total == 0:
                logger.info("📭 Nenhum e-mail na caixa de entrada")
                return
            
            check_count = min(self.max_emails, total)
            logger.info(f"📬 Verificando {check_count} e-mails...")
            
            phishing_found = 0
            
            for i in range(check_count):
                try:
                    content = self.reader.read_email_by_index(i)
                    
                    if not content:
                        continue
                    
                    # Verificar se já processado
                    if self.db.email_exists(content.get('message_id', '')):
                        continue
                    
                    # Analisar phishing
                    analysis = self.phishing.analyze_email(content)
                    content['phishing_score'] = analysis['score']
                    content['phishing_result'] = analysis
                    
                    # Salvar no banco
                    email_id = self.db.save_email(content)
                    
                    if email_id > 0:
                        # Salvar análise de phishing
                        self.db.save_phishing_analysis(email_id, analysis)
                        
                        # Extrair dados
                        extracted = self.extractor.extract_all(content.get('body', ''))
                        for data_type, values in extracted.items():
                            for value in values:
                                self.db.save_extracted_data(email_id, data_type, value)
                        
                        # Log do resultado
                        emoji = self.phishing.get_risk_emoji(analysis['risk_level'])
                        logger.info(
                            f"   {emoji} [{analysis['risk_level']}] "
                            f"Score: {analysis['score']} | "
                            f"{content.get('sender', 'N/A')[:20]} - "
                            f"{content.get('subject', 'N/A')[:30]}"
                        )
                        
                        if analysis['is_phishing']:
                            phishing_found += 1
                            logger.warning(f"   ⚠️ PHISHING: {', '.join(analysis['reasons'][:2])}")
                        
                        self.stats['total_checked'] += 1
                    
                    time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"   ❌ Erro no e-mail {i}: {e}")
                    continue
            
            self.stats['phishing_detected'] += phishing_found
            self.stats['last_check'] = datetime.now().isoformat()
            
            logger.info(f"✅ Verificação concluída! Phishing encontrados: {phishing_found}")
            logger.info(f"📊 Total processados: {self.stats['total_checked']} | "
                       f"Total phishing: {self.stats['phishing_detected']}")
            
        except Exception as e:
            logger.error(f"❌ Erro na verificação: {e}")
    
    def start(self):
        """Inicia o agendador"""
        self.running = True
        self.stats['started_at'] = datetime.now().isoformat()
        
        logger.info("=" * 50)
        logger.info("🚀 BOT DE E-MAILS INICIADO")
        logger.info(f"⏰ Verificando a cada {self.interval} minutos")
        logger.info(f"📧 Máximo de {self.max_emails} e-mails por verificação")
        logger.info("=" * 50)
        
        # Primeira verificação imediata
        self.check_emails()
        
        # Agendar verificações
        schedule.every(self.interval).minutes.do(self.check_emails)
        
        # Loop principal
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(30)  # Verificar agenda a cada 30 segundos
            except KeyboardInterrupt:
                logger.info("\n⚠️ Interrompido pelo usuário")
                self.stop()
                break
            except Exception as e:
                logger.error(f"❌ Erro no loop: {e}")
                time.sleep(60)
    
    def stop(self):
        """Para o agendador"""
        self.running = False
        logger.info("🛑 Bot parado")
        logger.info(f"📊 Estatísticas finais:")
        logger.info(f"   Total verificados: {self.stats['total_checked']}")
        logger.info(f"   Phishing detectados: {self.stats['phishing_detected']}")