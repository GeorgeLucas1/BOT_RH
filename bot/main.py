# main.py
import os
import sys
import time

# Criar pastas necessárias
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('browser_session', exist_ok=True)

from bot.ler_email import EmailReader
from bot.database import EmailDatabase
from bot.extrair import EmailExtractor
from bot.phishing import PhishingDetector
from bot.scheduler import EmailScheduler


def main():
    print("=" * 60)
    print("🤖 BOT DE E-MAILS COM DETECÇÃO DE PHISHING")
    print("=" * 60)
    
    # Inicializar componentes
    db = EmailDatabase()
    extractor = EmailExtractor()
    phishing = PhishingDetector()
    
    # Modo headless para Docker
    headless = os.getenv('HEADLESS', 'false').lower() == 'true'
    reader = EmailReader(headless=headless)
    
    try:
        # Iniciar navegador
        if not reader.start_browser("chrome"):
            print("❌ Falha ao iniciar navegador")
            return
        
        # Login
        if not reader.login_gmail():
            print("❌ Falha no login")
            return
        
        time.sleep(2)
        
        # Verificar se é modo contínuo (24/7)
        mode = os.getenv('MODE', 'single').lower()
        
        if mode == 'continuous' or '--continuous' in sys.argv:
            # Modo 24/7
            scheduler = EmailScheduler(reader, db, extractor, phishing)
            scheduler.start()
        else:
            # Modo único (uma verificação)
            print("\n📊 Modo: Verificação única")
            run_single_check(reader, db, extractor, phishing)
        
    except KeyboardInterrupt:
        print("\n⚠️ Interrompido")
    
    except Exception as e:
        print(f"\n❌ Erro: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        reader.close_browser()


def run_single_check(reader, db, extractor, phishing):
    """Executa uma única verificação"""
    reader.page.goto("https://mail.google.com/mail/u/0/#inbox", wait_until="load")
    time.sleep(3)
    
    total = reader.get_email_count()
    max_emails = min(10, total)
    
    if total == 0:
        print("📭 Nenhum e-mail encontrado!")
        return
    
    print(f"\n📬 Processando {max_emails} e-mails...\n")
    
    phishing_count = 0
    
    for i in range(max_emails):
        print(f"\n{'─' * 50}")
        print(f"📧 E-mail {i+1}/{max_emails}")
        
        content = reader.read_email_by_index(i)
        
        if not content:
            continue
        
        # Analisar phishing
        analysis = phishing.analyze_email(content)
        content['phishing_result'] = analysis
        
        # Salvar
        email_id = db.save_email(content)
        
        if email_id > 0:
            db.save_phishing_analysis(email_id, analysis)
            
            extracted = extractor.extract_all(content.get('body', ''))
            for data_type, values in extracted.items():
                for value in values:
                    db.save_extracted_data(email_id, data_type, value)
            
            # Mostrar resultado
            emoji = phishing.get_risk_emoji(analysis['risk_level'])
            print(f"   {emoji} Risco: {analysis['risk_level']} (Score: {analysis['score']})")
            print(f"   📝 {content.get('subject', 'N/A')[:45]}")
            print(f"   👤 {content.get('sender', 'N/A')}")
            
            if analysis['is_phishing']:
                phishing_count += 1
                print(f"   ⚠️ MOTIVOS: {', '.join(analysis['reasons'][:3])}")
        
        time.sleep(1)
    
    # Estatísticas finais
    print(f"\n{'=' * 60}")
    print("📊 RESUMO")
    print(f"{'=' * 60}")
    print(f"   Total verificados: {max_emails}")
    print(f"   🔴 Phishing detectados: {phishing_count}")
    
    stats = db.get_stats()
    print(f"\n   Banco de dados:")
    print(f"   📧 Total de e-mails: {stats['total_emails']}")
    print(f"   ⚠️ Total phishing: {stats['phishing_detected']}")


if __name__ == "__main__":
    main()