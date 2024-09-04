import tkinter as tk
import os
from tkinter import simpledialog, messagebox
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET
import re
import ntsecuritycon as con
import os

# Função para exibir o diálogo Tkinter para entrada de dados
def get_user_input():
    root = tk.Tk()
    root.withdraw()  # Esconde a janela principal

    # Coleta das entradas
    dir_glassfish = simpledialog.askstring("ServiceGlassfish", "Informe a unidade de disco da pasta Glassfish [Exemplo: C]")
    user = simpledialog.askstring("ServiceGlassfish", "Informe o usuário do servidor com o domínio [Exemplo: srvlocal\\senior]")
    password = simpledialog.askstring("ServiceGlassfish", "Informe a senha do usuário", show='*')
    port_console = simpledialog.askstring("ServiceGlassfish", "Informe a porta do console Glassfish [Exemplo: 4848]")
    port_http = simpledialog.askstring("ServiceGlassfish", "Informe a porta HTTP Listener1 [Exemplo: 8080]")
    port_https = simpledialog.askstring("ServiceGlassfish", "Informe a porta do HTTPS Listener2 [Exemplo: 8181]")
    name_domain = simpledialog.askstring("ServiceGlassfish", "Informe o nome do domínio [Exemplo: domain, domainteste, gestaoponto, gestaopontoteste]")
    
    # Exibe um resumo dos dados coletados
    #messagebox.showinfo("Resumo", f"Unidade Glassfish: {dir_glassfish}\nUsuário: {user}\n"
    #                               f"Console: {port_console}\nHTTP: {port_http}\nHTTPS: {port_https}\nDomínio: {name_domain}")

    messagebox.showinfo("Importante", f"Aguarde a conclusão do processo...")

    return {
        "dir_glassfish": dir_glassfish,
        "user": user,
        "password": password,
        "port_console": port_console,
        "port_http": port_http,
        "port_https": port_https,
        "name_domain": name_domain
    }

# Função para criar o domínio e serviços do Glassfish
def setup_glassfish_services(data):
    scriptdir = Path(f"{data['dir_glassfish']}:") / "glassfish4" / "Configura_glassfish_full"
    scriptdir = Path(f"{data['dir_glassfish']}:\\glassfish4\\Configura_glassfish_full").resolve()
    gfdir = Path(f"{data['dir_glassfish']}:") / "glassfish4" / "glassfish" / "bin"
    gfdir = Path(f"{data['dir_glassfish']}:\\glassfish4\\glassfish\\bin").resolve()
    gfdirdom = Path(f"{data['dir_glassfish']}:") / "glassfish4" / "glassfish" / "domains"
    gfdirdom = Path(f"{data['dir_glassfish']}:\\glassfish4\\glassfish\\domains").resolve()

    # Assume que $dirGlassfish contém a letra da unidade, como "C:"
    basePath = os.path.join(scriptdir, "Senha_Glassfish")

    # Verifica se a pasta "Senha_Glassfish" já existe, se não, cria
    if not os.path.exists(basePath):
        os.makedirs(basePath)

    # Conteúdo do arquivo "pwdfile"
    pwdfileContent = "AS_ADMIN_PASSWORD=adminadmin"
    pwdfilePath = os.path.join(basePath, "pwdfile")

    with open(pwdfilePath, 'w') as pwdfile:
        pwdfile.write(pwdfileContent)

    # Conteúdo do arquivo "tmpfile"
    tmpfileContent = (
        "AS_ADMIN_PASSWORD=\n"
        "AS_ADMIN_NEWPASSWORD=adminadmin\n"
    )
    tmpfilePath = os.path.join(basePath, "tmpfile")

    with open(tmpfilePath, 'w') as tmpfile:
        tmpfile.write(tmpfileContent)

    # Construção dos scripts .bat
    scripts = {
        "1_Cria_Dominio.bat": [
            f"cd {gfdir}",
            f"asadmin.bat create-domain --user admin --nopassword true --savelogin --checkports=false --adminport {data['port_console']} --instanceport {data['port_http']} {data['name_domain']}"
        ],
        "2_Inicia_Dominio.bat": [
            f"cd {gfdir}",
            f"asadmin.bat start-domain {data['name_domain']}"
        ],
        "3_Altera_Senha_Dominio.bat": [
            f"cd {gfdir}",
            f"asadmin.bat change-admin-password --user admin --domain_name {data['name_domain']} --passwordfile={tmpfilePath}"
        ],
        "4_Reinicia_Dominio.bat": [
            f"cd {gfdir}",
            f"asadmin.bat restart-domain {data['name_domain']}"
        ],
        "5_Ativa_Secure_Admin.bat": [
            f"cd {gfdir}",
            f"asadmin.bat enable-secure-admin --port {data['port_console']} --passwordfile={pwdfilePath}"
        ],
        "6_Cria_Servico.bat": [
            f"cd {gfdir}",
            f"asadmin.bat create-service --name={data['name_domain']} --serviceproperties=DISPLAY_NAME=\"Senior Glassfish 4 {data['name_domain']}\" {data['name_domain']}"
        ],
        "7_Parar_Dominio.bat": [
            f"cd {gfdir}",
            f"asadmin.bat stop-domain {data['name_domain']}"
        ]
    }

    for script_name, commands in scripts.items():
        # Criação do arquivo .bat
        script_path = os.path.join(scriptdir, script_name)
        with open(script_path, 'w') as script_file:
            script_file.write("\n".join(commands))

    os.chdir(scriptdir)
    # Executa o script .bat
    subprocess.run(["1_Cria_Dominio.bat"], shell=True)
    time.sleep(30)
    # Executa o script .bat
    subprocess.run(["2_Inicia_Dominio.bat"], shell=True)
    time.sleep(15)
    # Executa o script .bat
    subprocess.run(["3_Altera_Senha_Dominio.bat"], shell=True)
    time.sleep(10)
    # Executa o script .bat
    subprocess.run(["4_Reinicia_Dominio.bat"], shell=True)
    time.sleep(30)
    # Executa o script .bat
    subprocess.run(["5_Ativa_Secure_Admin.bat"], shell=True)
    time.sleep(15)
    # Executa o script .bat
    subprocess.run(["4_Reinicia_Dominio.bat"], shell=True)
    time.sleep(30)
    # Executa o script .bat
    subprocess.run(["6_Cria_Servico.bat"], shell=True)
    time.sleep(15)

    os.chdir(gfdir)

    # Cálculo automático das portas
    jmxPort = int(data['port_https']) + 505
    iioplistener = int(data['port_console']) - 1148
    portSSL = int(data['port_console']) - 1028
    portSSLMUTUALAUTH = int(data['port_console']) - 928

    # Configuração do Glassfish
    commands = [
    f'.\\asadmin.bat delete-jvm-options "-XX\\:MaxPermSize=192m" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-XX\\:MaxPermSize=768m" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat delete-jvm-options "-client" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-server" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat delete-jvm-options "-XX\\:NewRatio=2" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-Xrs" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat delete-jvm-options "-Xmx512m" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-Xmx2g" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-Xms2g" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-Xmn512m" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-XX\\:+UseConcMarkSweepGC" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-XX\\:+UseParNewGC" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-XX\\:SurvivorRatio=20" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat create-jvm-options "-XX\\:+CMSParallelRemarkEnabled" --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set server.thread-pools.thread-pool.http-thread-pool.max-thread-pool-size=200 --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set configs.config.server-config.network-config.protocols.protocol.http-listener-1.http.request-timeout-seconds=3600 --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set configs.config.server-config.network-config.network-listeners.network-listener.http-listener-2.port={data["port_https"]} --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set configs.config.server-config.admin-service.jmx-connector.system.port={jmxPort} --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set configs.config.server-config.iiop-service.iiop-listener.orb-listener-1.port={iioplistener} --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set configs.config.server-config.iiop-service.iiop-listener.SSL.port={portSSL} --port {data["port_console"]} --passwordfile={pwdfilePath}',
    f'.\\asadmin.bat set configs.config.server-config.iiop-service.iiop-listener.SSL_MUTUALAUTH.port={portSSLMUTUALAUTH} --port {data["port_console"]} --passwordfile={pwdfilePath}'
]

    for command in commands:
        print(f'Comando executado: {command}')  # Exibe o comando que está sendo executado
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        print(result.stdout)

    ################################################################
    # Cálculo automático da porta JMSProviderPort
    jms_provider_port = int(data['port_https']) - 505

    # Caminho para o arquivo de configuração do Glassfish
    config_file_path = os.path.join(gfdirdom, data['name_domain'], 'config', 'domain.xml')
    print(config_file_path)
    # Nova porta que deseja definir
    new_port = str(jms_provider_port)
    # Ler o conteúdo do arquivo XML
    with open(config_file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    # Substituir a porta antiga pela nova
    content = re.sub(r'value="7676"', f'value="{new_port}"', content)
    # Salvar o conteúdo modificado de volta no arquivo
    with open(config_file_path, 'w', encoding='utf-8') as file:
        file.write(content)
    ################################################################

    # Comando PowerShell para criar o compartilhamento SMB
    ps_command = f"""
    New-SMBShare -Name '{data['name_domain']}$' -Path '{gfdirdom}\\{data['name_domain']}' -FullAccess '{data['user']}'
    """
    # Executando o comando PowerShell a partir do Python
    try:
        subprocess.run(["powershell", "-Command", ps_command], check=True)
        print(f"Compartilhamento {data['name_domain']}$ criado com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao criar compartilhamento: {e}")

    # Comando PowerShell para criar as permissões da pasta
    ps_command2 = f"""
    $acl = Get-Acl '{gfdirdom}\\{data['name_domain']}'
    $acl.SetAccessRuleProtection($true, $false)
    $acl | Set-Acl "{gfdirdom}\\{data['name_domain']}"

    $ACLRULE = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($ACLRULE)
    Set-Acl '{gfdirdom}\\{data['name_domain']}' $acl

    $ACLRULE = New-Object System.Security.AccessControl.FileSystemAccessRule("{data['user']}", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($ACLRULE)
    Set-Acl '{gfdirdom}\\{data['name_domain']}' $acl
    """

    # Executando o comando PowerShell a partir do Python
    try:
        subprocess.run(["powershell", "-Command", ps_command2], check=True)
        print(f"Permissões Aplicadas com sucesso!!")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao aplicar permissões: {e}")

    # Comando PowerShell para corrigir o serviço
    ps_command3 = f"""
    cmd.exe /c sc config "{data['name_domain']}" obj="{data['user']}" password="{data['password']}"
    cmd.exe /c sc config "{data['name_domain']}" start=demand
    """
    subprocess.run(["powershell", "-Command", ps_command3], check=True)

    # Definição se usa ou não o Gestão do Ponto
    def_domain = simpledialog.askstring("ServiceGlassfish", "O domínio será do Gestão do Ponto? (S)Sim, (N)Não")

    # Caso utilize o Gestão do Ponto, realiza o processo de criação...
    if def_domain == "S":
        usr_database = simpledialog.askstring("ServiceGlassfish", "Digite o nome do usuário da base de dados [Exemplo: sa]")
        pass_database = simpledialog.askstring("ServiceGlassfish", "Digite a senha do usuário", show='*')
        database = simpledialog.askstring("ServiceGlassfish", "Digite o nome da base de dados [Exemplo: vetorh]")
        server_database = simpledialog.askstring("ServiceGlassfish", "Digite o IP do banco [Exemplo: 192.168.3.5]")
        port_number = simpledialog.askstring("ServiceGlassfish", "Qual a porta utilizada pelo banco? [Exemplo: 1433]")

        tipBanco = simpledialog.askstring("Entrada de Banco de Dados", "Qual o banco de dados utilizado? (1)SQL Server, (2)Oracle")

        urlBanco = f"{server_database}:{port_number}"
        infoBancoSQL = f"user={usr_database}:password={pass_database}:url="
        infoBancoORA = f"user={usr_database}:password={pass_database}:url="

        # Banco SQL Server
        if tipBanco == "1":

            scripts = {
                "8_Cria_Connection_Pool_GP.bat": [
                    f"cd {gfdir}",
                    f"asadmin.bat --port {data['port_console']} --passwordfile={scriptdir}\\Senha_Glassfish\\pwdfile create-jdbc-connection-pool --restype=java.sql.Driver --driverclassname=com.microsoft.sqlserver.jdbc.SQLServerDriver --property {infoBancoSQL}'jdbc:sqlserver://{urlBanco};instanceName=MSSQLSERVER;databaseName={database}' {data['name_domain']}-dataaccess"
                ],
                "9_Cria_Connection_Resource_GP.bat": [
                    f"cd {gfdir}",
                    f"asadmin.bat --port {data['port_console']} --passwordfile={scriptdir}\\Senha_Glassfish\\pwdfile create-jdbc-resource --connectionpoolid {data['name_domain']}-dataaccess jdbc/{data['name_domain']}-dataaccess__pm"
                ],
                "91_Cria_Connection_Resource_GP.bat": [
                    f"cd {gfdir}",
                    f"asadmin.bat --port {data['port_console']} --passwordfile={scriptdir}\\Senha_Glassfish\\pwdfile create-jdbc-resource --connectionpoolid {data['name_domain']}-dataaccess jdbc/{data['name_domain']}-dataaccess__nontx"
                ]
            }

            for script_name, commands in scripts.items():
                # Criação do arquivo .bat
                script_path = os.path.join(scriptdir, script_name)
                with open(script_path, 'w') as script_file:
                    script_file.write("\n".join(commands))

            os.chdir(scriptdir)
            # Executa os scripts .bat
            subprocess.run(["8_Cria_Connection_Pool_GP.bat"], shell=True)
            time.sleep(10)
            subprocess.run(["9_Cria_Connection_Resource_GP.bat"], shell=True)
            time.sleep(10)
            subprocess.run(["91_Cria_Connection_Resource_GP.bat"], shell=True)
            time.sleep(10)

        # Banco Oracle
        if tipBanco == "2":

            scripts = {
                "8_Cria_Connection_Pool_GP.bat": [
                    f"cd {gfdir}",
                    f"asadmin.bat --port {data['port_console']} --passwordfile={scriptdir}\\Senha_Glassfish\\pwdfile create-jdbc-connection-pool --restype=java.sql.Driver --driverclassname=oracle.jdbc.driver.OracleDriver --property {infoBancoORA}'jdbc:oracle:thin:@{urlBanco}/{database}.landb.lan.oraclevcn.com' {data['name_domain']}-dataaccess"
                ],
                "9_Cria_Connection_Resource_GP.bat": [
                    f"cd {gfdir}",
                    f"asadmin.bat --port {data['port_console']} --passwordfile={scriptdir}\\Senha_Glassfish\\pwdfile create-jdbc-resource --connectionpoolid {data['name_domain']}-dataaccess jdbc/{data['name_domain']}-dataaccess__pm" 
                ],
                "91_Cria_Connection_Resource_GP.bat": [
                    f"cd {gfdir}",
                    f"asadmin.bat --port {data['port_console']} --passwordfile={scriptdir}\\Senha_Glassfish\\pwdfile create-jdbc-resource --connectionpoolid {data['name_domain']}-dataaccess jdbc/{data['name_domain']}-dataaccess__nontx"
                ]
            }

            for script_name, commands in scripts.items():
                # Criação do arquivo .bat
                script_path = os.path.join(scriptdir, script_name)
                with open(script_path, 'w') as script_file:
                    script_file.write("\n".join(commands))

            os.chdir(scriptdir)
            # Executa os scripts .bat
            subprocess.run(["8_Cria_Connection_Pool_GP.bat"], shell=True)
            time.sleep(10)
            subprocess.run(["9_Cria_Connection_Resource_GP.bat"], shell=True)
            time.sleep(10)
            subprocess.run(["91_Cria_Connection_Resource_GP.bat"], shell=True)
            time.sleep(10)
                
    else:
        usr_database = pass_database = database = server_database = port_number = None

    messagebox.showinfo("Sucesso!!!", f"Domínio criado com sucesso!!!\nReinicie o serviço se necessário...\n")

# Execução principal
if __name__ == "__main__":
    user_data = get_user_input()
    setup_glassfish_services(user_data)
