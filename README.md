# Automação para RH – Cadastro Automático via RPA

## Descrição
Este projeto implementa uma automação RPA para o setor de RH, responsável por realizar o cadastro automático de colaboradores a partir de uma planilha Excel em um sistema web. A automação reduz trabalho manual, erros de digitação e tempo operacional.

## Objetivo
Automatizar o processo de cadastro de colaboradores utilizando Python, Selenium, Pandas e banco de dados SQL para registro de logs.

## Fluxo do Bot
1. Abrir uma planilha Excel.
2. Ler os dados linha por linha.
3. Para cada registro:
   - Abrir o navegador.
   - Acessar a página de cadastro.
   - Preencher os campos obrigatórios (nome, e-mail, CPF, cargo, etc.).
   - Submeter o formulário (salvar).
   - Registrar o resultado (sucesso ou erro).
4. Salvar logs em banco de dados SQL ou planilha.
5. Encerrar a execução.

## Tecnologias Utilizadas
- Python 
- Selenium WebDriver  
- Pandas  
- Banco de dados SQLite
- Excel (.xlsx)  

## Estrutura do Projeto
