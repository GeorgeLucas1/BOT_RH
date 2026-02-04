# bot/database.py
import sqlite3
import json
from datetime import datetime


class EmailDatabase:
    
    def __init__(self, db_path="data/emails.db"):
        self.db_path = db_path
        self.create_tables()
    
    def create_tables(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabela de e-mails
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                subject TEXT,
                sender TEXT,
                sender_email TEXT,
                email_date TEXT,
                body TEXT,
                has_attachments INTEGER DEFAULT 0,
                phishing_score INTEGER DEFAULT 0,
                is_phishing INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'SEGURO',
                read_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de análise de phishing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phishing_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                score INTEGER,
                risk_level TEXT,
                is_phishing INTEGER,
                reasons TEXT,
                urls_found TEXT,
                analyzed_at TEXT,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        ''')
        
        # Tabela de dados extraídos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extracted_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id INTEGER,
                data_type TEXT,
                value TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        ''')
        
        # Tabela de estatísticas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT UNIQUE,
                emails_checked INTEGER DEFAULT 0,
                phishing_detected INTEGER DEFAULT 0,
                high_risk INTEGER DEFAULT 0,
                medium_risk INTEGER DEFAULT 0,
                low_risk INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def email_exists(self, message_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM emails WHERE message_id = ?', (message_id,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    
    def save_email(self, email_data):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            phishing_result = email_data.get('phishing_result', {})
            
            cursor.execute('''
                INSERT INTO emails (
                    message_id, subject, sender, sender_email, email_date, 
                    body, has_attachments, phishing_score, is_phishing, 
                    risk_level, read_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_data.get('message_id', ''),
                email_data.get('subject', ''),
                email_data.get('sender', ''),
                email_data.get('sender_email', ''),
                email_data.get('date', ''),
                email_data.get('body', ''),
                1 if email_data.get('has_attachments') else 0,
                phishing_result.get('score', 0),
                1 if phishing_result.get('is_phishing') else 0,
                phishing_result.get('risk_level', 'SEGURO'),
                email_data.get('read_at', datetime.now().isoformat())
            ))
            
            email_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return email_id
            
        except sqlite3.IntegrityError:
            return -1
        except Exception as e:
            print(f"❌ Erro ao salvar: {e}")
            return -1
    
    def save_phishing_analysis(self, email_id, analysis):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO phishing_analysis (
                    email_id, score, risk_level, is_phishing, 
                    reasons, urls_found, analyzed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_id,
                analysis.get('score', 0),
                analysis.get('risk_level', 'SEGURO'),
                1 if analysis.get('is_phishing') else 0,
                json.dumps(analysis.get('reasons', []), ensure_ascii=False),
                json.dumps(analysis.get('urls_found', []), ensure_ascii=False),
                analysis.get('analyzed_at', datetime.now().isoformat())
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Erro ao salvar análise: {e}")
    
    def save_extracted_data(self, email_id, data_type, value):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO extracted_data (email_id, data_type, value)
                VALUES (?, ?, ?)
            ''', (email_id, data_type, value))
            conn.commit()
            conn.close()
        except:
            pass
    
    def get_phishing_emails(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT e.*, p.reasons 
            FROM emails e 
            LEFT JOIN phishing_analysis p ON e.id = p.email_id
            WHERE e.is_phishing = 1 
            ORDER BY e.created_at DESC 
            LIMIT ?
        ''', (limit,))
        emails = cursor.fetchall()
        conn.close()
        return emails
    
    def get_stats(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM emails')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM emails WHERE is_phishing = 1')
        phishing = cursor.fetchone()[0]
        
        cursor.execute('SELECT risk_level, COUNT(*) FROM emails GROUP BY risk_level')
        by_risk = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_emails': total,
            'phishing_detected': phishing,
            'by_risk_level': by_risk
        }