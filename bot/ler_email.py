# bot/ler_email.py
import os
import time
from datetime import datetime
from playwright.sync_api import sync_playwright
from dotenv import load_dotenv

load_dotenv()


class EmailReader:
    
    def __init__(self, headless=False):
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.user_data_dir = os.path.join(os.getcwd(), "browser_session")
    
    def start_browser(self, browser_type="chrome"):
        try:
            self.playwright = sync_playwright().start()
            os.makedirs(self.user_data_dir, exist_ok=True)
            
            self.context = self.playwright.chromium.launch_persistent_context(
                self.user_data_dir,
                headless=self.headless,
                channel="chrome",
                viewport={"width": 1366, "height": 768},
                locale="pt-BR",
                timeout=60000,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage"
                ]
            )
            
            self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
            self.page.set_default_timeout(60000)
            self.page.set_default_navigation_timeout(60000)
            
            print(f"🌐 Navegador iniciado!")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao iniciar navegador: {e}")
            return False
    
    def login_gmail(self):
        try:
            print("🔐 Acessando Gmail...")
            
            for tentativa in range(3):
                try:
                    self.page.goto("https://mail.google.com/", wait_until="load", timeout=60000)
                    time.sleep(5)
                    break
                except:
                    if tentativa < 2:
                        print(f"   🔄 Tentativa {tentativa + 2}...")
                        time.sleep(3)
            
            if "mail.google.com/mail" in self.page.url:
                print("✅ Já está logado!")
                return True
            
            print("\n" + "=" * 50)
            print("⚠️  FAÇA LOGIN NO NAVEGADOR QUE ABRIU")
            print("=" * 50)
            input("\n👉 Pressione ENTER após fazer login... ")
            
            if "mail.google.com/mail" in self.page.url:
                print("✅ Login OK!")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Erro: {e}")
            return False
    
    def get_email_count(self):
        """Conta quantos e-mails existem na lista"""
        try:
            email_rows = self.page.query_selector_all('tr.zA')
            return len(email_rows)
        except:
            return 0
    
    def read_email_by_index(self, index):
        """Lê um e-mail pelo índice (re-busca o elemento cada vez)"""
        try:
            # Garantir que está na inbox
            if "inbox" not in self.page.url:
                self.page.goto("https://mail.google.com/mail/u/0/#inbox", wait_until="load")
                time.sleep(3)
            
            # Buscar todos os e-mails NOVAMENTE
            email_rows = self.page.query_selector_all('tr.zA')
            
            if index >= len(email_rows):
                print(f"   ⚠️ Índice {index} não existe mais")
                return None
            
            row = email_rows[index]
            
            # Pegar preview
            sender = "Desconhecido"
            subject = "Sem assunto"
            
            sender_el = row.query_selector('span.bA4, span.yP')
            if sender_el:
                sender = sender_el.inner_text()
            
            subject_el = row.query_selector('span.bog, span.y2')
            if subject_el:
                subject = subject_el.inner_text()
            
            print(f"   📧 {sender[:25]} - {subject[:35]}")
            
            # Clicar para abrir
            row.click()
            time.sleep(3)
            
            # Extrair conteúdo
            content = {
                'subject': '',
                'sender': sender,
                'sender_email': '',
                'date': '',
                'body': '',
                'has_attachments': False,
                'message_id': f"{index}_{int(time.time())}",
                'read_at': datetime.now().isoformat()
            }
            
            # Assunto
            el = self.page.query_selector('h2.hP')
            if el:
                content['subject'] = el.inner_text()
            
            # Remetente com email
            el = self.page.query_selector('span.gD, span.go')
            if el:
                content['sender'] = el.inner_text()
                content['sender_email'] = el.get_attribute('email') or ''
            
            # Data
            el = self.page.query_selector('span.g3')
            if el:
                content['date'] = el.inner_text()
            
            # Corpo
            el = self.page.query_selector('div.a3s.aiL, div.a3s')
            if el:
                content['body'] = el.inner_text()
            
            # Anexos
            if self.page.query_selector('div.aZo'):
                content['has_attachments'] = True
            
            # Voltar para inbox
            self.page.goto("https://mail.google.com/mail/u/0/#inbox", wait_until="load")
            time.sleep(2)
            
            return content
            
        except Exception as e:
            print(f"   ❌ Erro: {e}")
            # Tentar voltar para inbox
            try:
                self.page.goto("https://mail.google.com/mail/u/0/#inbox", wait_until="load")
                time.sleep(2)
            except:
                pass
            return None
    
    def close_browser(self):
        try:
            if self.context:
                self.context.close()
            if self.playwright:
                self.playwright.stop()
            print("🔒 Navegador fechado!")
        except Exception as e:
            print(f"⚠️ Erro ao fechar: {e}")