using IniParser;
using IniParser.Model;
using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using MySql.Data.MySqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    static readonly string SecurityFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "security.dat");
    static string EncryptionKey = "ChaveDeCriptografiaSegura";
    static string SenhaValida = "SenhaSegura";
    static string Servidor = "Não Definido";
    static string Version = "1.0.1";
    static string aplicacao = "RRWindows";
    static string contatoWhatsApp = "556784578078@c.us";
    static bool ReiniciaServer = true;
    static bool AtualizarXbox = true;
    static bool RequisitosValidados = false;
    static string plataformaConnect = "";
    static string connectionString = "Server=sukeserver.ddns.net;Database=db;User ID=sukeee;Password=Unreal05;Port=3306;SslMode=None;";
    static string connectionStringPostgres = "Host=sukeserver.ddns.net;Database=palbot_db;Username=PalAdm;Password=joga10";
    static string deployValor = "";


    static string hostname = "";



    static async System.Threading.Tasks.Task Main(string[] args)
    {
        Console.WriteLine(aplicacao + " Created by Suke CodeCraft versão " + Version);
        Console.WriteLine("https://github.com/FellipeSuke");
        Console.WriteLine("Contato WhatsApp: +55 67 3325-8870");

        
        if (!RequisitosChecker.VerificarRequisitos()) 
        {
            Console.WriteLine("Pressione Qualquer tecla para sair");
            Console.ReadKey();
            return;
        }


        bool sucesso = AtualizarDadosSeguranca();
        if (sucesso)
        {
            Console.WriteLine("Iniciando Processo");
        }
        else
        {
            Console.WriteLine("Não foi possível atualizar aplicação");
        }

        SystemInfo systemInfo = new SystemInfo();
        hostname = systemInfo.GetHostname();
        Console.WriteLine($"{hostname}");


        // Verificar se a segurança está OK (arquivo de segurança existe e é válido)
        if (!VerificarSeguranca())
        {
            // Se a verificação falhar, solicitar senha
            // Tenta atualizar as variáveis da aplicação a partir do banco de dados

            ReiniciaServer = false;
            Console.WriteLine("Arquivo de segurança não encontrado. Insira a senha para continuar:");
            string senhaInserida = Console.ReadLine();


            if (senhaInserida == SenhaValida)
            {
                // Senha correta, cria o arquivo de segurança com o UUID da máquina
                await EnviarMensagemWhatsApp($"{Servidor} {hostname} - Nova Instalação Identificada", "556784578078@c.us");
                Console.WriteLine("Iniciando Instalação. Insira um nome para o Servidor:");
                Servidor = Console.ReadLine();
                Console.WriteLine("Insira o ContatoWhatsApp:");
                string contatoWhatsRead = Console.ReadLine();
                if (!string.IsNullOrEmpty(contatoWhatsRead))
                {
                    contatoWhatsApp = contatoWhatsRead;
                }

                ProcessarPlataforma();

                CriarArquivoSeguranca(Servidor, contatoWhatsApp);
                Console.WriteLine("Arquivo de segurança criado com sucesso. Aplicação liberada.");

            }
            else
            {
                Console.WriteLine("Senha incorreta. Encerrando aplicação.");
                return;
            }
        }

        string[] encryptedServer = File.ReadLines(SecurityFilePath).ToArray();
        string decrypteServer = Decrypt(encryptedServer[1], EncryptionKey);
        string decrypteContato = Decrypt(encryptedServer[2], EncryptionKey);
        string decryptePlataforma = Decrypt(encryptedServer[3], EncryptionKey);

        Servidor = decrypteServer;
        contatoWhatsApp = decrypteContato;
        plataformaConnect = decryptePlataforma;
        if (!ReiniciaServer)
        {
            AtualizarXbox = true;
        }


        // Configuração da data e hora
        string datetime = DateTime.Now.ToString("yyyy-MM-dd_HH-mm");
        Console.WriteLine($"'{datetime}'");

        // Diretórios de origem, destino e backup
        string origemDir = @"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\WindowsServer";
        string destinoDir = @"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\WindowsServer";
        string backupDir = @$"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\Backup\Backup_{datetime}";
        string palserverExe = @$"C:\steamcmd\steamapps\common\PalServer\PalServer.exe";
        string destinoEngineIni = System.IO.Path.Combine(destinoDir, "Engine.ini");


        RRLogger logger = new RRLogger();
        string aplicacaoVersion = aplicacao + " " + Version;

        // Enviar mensagem via curl
        await EnviarMensagemWhatsApp($"{Servidor} ALERT - Servidor em RR!", contatoWhatsApp);

        // Atualizar servidor
        if (plataformaConnect != "Xbox" || (plataformaConnect == "Xbox" && AtualizarXbox))
        {
            logger.LogExecution(Servidor, hostname, DateTime.Now, "Atualizando", contatoWhatsApp, aplicacaoVersion);
            AtualizarServidor(datetime);
        }

        // Aguardar 2 segundos após update Steam
        await System.Threading.Tasks.Task.Delay(2000);




        // Verificar se o diretório de backup existe, caso contrário, criar
        if (!Directory.Exists(destinoDir))
        {
            Directory.CreateDirectory(destinoDir);
        }
        if (!Directory.Exists(origemDir))
        {
            Directory.CreateDirectory(origemDir);
        }
        // Obter todos os arquivos da pasta de origem
        var arquivosOrigem = Directory.GetFiles(origemDir);

        string outputFilePath = Path.Combine(origemDir, "PalWorldSettings.ini"); // Caminho completo para "PalWorldSettings.ini";

        try
        {
            var configManager = new ConfigManager(hostname);
            configManager.GenerateConfigFile(outputFilePath);
            configManager.UpdateUsageCounts();
        }
        catch (Exception ex)
        {
            logger.LogExecution(Servidor, hostname, DateTime.Now, ex.Message, contatoWhatsApp, aplicacaoVersion);
        }



        // Iterar sobre todos os arquivos de origem
        foreach (var arquivoOrigem in arquivosOrigem)
        {
            string nomeArquivo = Path.GetFileName(arquivoOrigem);
            string arquivoDestino = Path.Combine(destinoDir, nomeArquivo);
            string arquivoBackup = Path.Combine(backupDir, $"{nomeArquivo}_{datetime}");

            if (VerificarDiferencaArquivos(arquivoOrigem, arquivoDestino))
            {
                Console.WriteLine($"Arquivos diferentes, realizando o backup e deploy de {nomeArquivo}...");
                string messageConfig = $"{Servidor} - Arquivos diferentes, realizando o backup e deploy {nomeArquivo}...\n";
                messageConfig += CompareOptionSettings(arquivoOrigem, arquivoDestino);
                Console.WriteLine(messageConfig);
                
                await EnviarMensagemWhatsApp(messageConfig, contatoWhatsApp);

                

                // Mover o arquivo de destino para o diretório de backup
                if (File.Exists(arquivoDestino))
                {
                    if (!Directory.Exists(backupDir))
                    {
                        Directory.CreateDirectory(backupDir);
                    }

                    File.Move(arquivoDestino, arquivoBackup);
                }

                // Copiar o arquivo de origem para o destino
                File.Copy(arquivoOrigem, arquivoDestino, true);
            }
            else
            {
                Console.WriteLine($"Arquivos são iguais, nenhuma cópia realizada para {nomeArquivo}.");
            }
        }


        // Substituir todos os arquivos na pasta Palguardupdate
        SubstituirArquivosPalguardupdate(datetime);


        logger.LogExecution(Servidor, hostname, DateTime.Now, "Success", contatoWhatsApp, aplicacaoVersion);

        if (!ReiniciaServer)
        {
            try
            {
                System.Diagnostics.Process.Start(palserverExe);
                Console.WriteLine("Aplicação PalServer iniciada. Avaliando arquitetura e desempenho...");

                // Aguardar 2 minutos para a criação dos diretórios
                await System.Threading.Tasks.Task.Delay(30000);

                Console.WriteLine("Encerrando processo de aplicação PalServer...");
                // Encerrar o processo após 2 minutos
                foreach (var process in System.Diagnostics.Process.GetProcessesByName("PalServer-Win64-Shipping-Cmd"))
                {
                    process.Kill();
                }
                await System.Threading.Tasks.Task.Delay(50000);






                // Copiar o conteúdo do Engine.ini dos recursos para o diretório de destino
                Console.WriteLine("Alterando aplicação para melhores niveis de performance");
                if (!System.IO.Directory.Exists(destinoDir))
                {
                    System.IO.Directory.CreateDirectory(destinoDir);
                }

                // Ler o conteúdo do Engine.ini do Resources
                var engineIniContent = RRWindows.Properties.Resources.Engine; // 'Engine' é o nome do recurso sem extensão

                // Gravar o conteúdo no destino
                System.IO.File.WriteAllText(destinoEngineIni, engineIniContent);
                Console.WriteLine("Corrigido niveis de performance");


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao iniciar ou encerrar a aplicação PalServer: {ex.Message}");
            }

            CriarTarefaAgendada();
            
            FirewallManager.AbrirPortasFirewall();

            Console.WriteLine("Aplicação instalada, arquivos de configuração padrão");
            Console.WriteLine("Deseja Reiniciar o servidor agora? S/N");
            if (Console.ReadLine().ToLower() == "s")
            {
                // Iniciar a aplicação PalServer.exe
                Console.WriteLine("Iniciando aplicação PalServer...");
                Console.WriteLine("Aguardando 5 segundos... REINICIANDO MÁQUINA...");
                await System.Threading.Tasks.Task.Delay(5000);
                ReiniciarMaquina();

            }
        }
        else
        {
            ReiniciarMaquina();
        }

    }


    enum Plataforma
    {
        Steam,
        Xbox,
        PlayStation,
        Invalido
    }

    static Plataforma ObterPlataforma()
    {
        Console.WriteLine("Selecione a plataforma:");
        Console.WriteLine("1. Steam");
        Console.WriteLine("2. Xbox");
        Console.WriteLine("3. PlayStation");

        Console.Write("Digite o número correspondente: ");
        string entrada = Console.ReadLine();

        switch (entrada)
        {
            case "1":
                return Plataforma.Steam;
            case "2":
                return Plataforma.Xbox;
            case "3":
                return Plataforma.PlayStation;
            default:
                Console.WriteLine("Opção inválida! Selecione novamente.");
                return Plataforma.Invalido;
        }
    }

    static void ProcessarPlataforma()
    {
        Plataforma plataforma;

        do
        {
            plataforma = ObterPlataforma();
        } while (plataforma == Plataforma.Invalido);

        Console.WriteLine($"Plataforma selecionada: {plataforma}");

        // Lógica de processamento com base na plataforma
        switch (plataforma)
        {
            case Plataforma.Steam:
                Console.WriteLine("Iniciando configuração para Steam...");
                plataformaConnect = "Steam";
                break;
            case Plataforma.Xbox:
                Console.WriteLine("Iniciando configuração para Xbox e GamePass...");
                plataformaConnect = "Xbox";
                break;
            case Plataforma.PlayStation:
                Console.WriteLine("Iniciando configuração para PlayStation...");
                plataformaConnect = "PlayStation";
                break;
        }
    }

    static Dictionary<string, string> GetOptionSettings(string filePath)
    {
        // Cria o parser para ler o arquivo INI
        var parser = new FileIniDataParser();

        // Lê o arquivo INI
        IniData data = parser.ReadFile(filePath);

        // Acessa a seção desejada e a chave OptionSettings
        string optionSettings = data["/Script/Pal.PalGameWorldSettings"]["OptionSettings"];

        // Cria um dicionário para armazenar as configurações
        var settingsDict = new Dictionary<string, string>();

        // Divide as configurações separadas por vírgulas
        string[] options = optionSettings.Split(',');

        // Processa cada configuração e adiciona ao dicionário
        foreach (var option in options)
        {
            var parts = option.Split('=');
            if (parts.Length == 2)
            {
                settingsDict[parts[0].Trim()] = parts[1].Trim();
            }
        }

        // Retorna o dicionário com as configurações
        return settingsDict;
    }

    static string CompareOptionSettings(string filePath1, string filePath2)
    {
        // Obtém as configurações dos dois arquivos INI
        var settings1 = GetOptionSettings(filePath1);
        var settings2 = GetOptionSettings(filePath2);

        // Armazena as chaves que são diferentes
        var differences = new List<string>();

        // Compara as chaves e valores entre os dois dicionários
        foreach (var setting in settings1)
        {
            if (settings2.ContainsKey(setting.Key))
            {
                // Se o valor for diferente, armazena a chave
                if (settings1[setting.Key] != settings2[setting.Key])
                {
                    differences.Add(setting.Key);
                }
            }
            else
            {
                // Se a chave não estiver no segundo arquivo
                differences.Add(setting.Key);
            }
        }

        // Verifica as chaves presentes no segundo arquivo, mas não no primeiro
        foreach (var setting in settings2)
        {
            if (!settings1.ContainsKey(setting.Key))
            {
                differences.Add(setting.Key);
            }
        }

        // Exibe as diferenças
        if (differences.Count > 0)
        {
            string mensagemCompoleta = "";
            Console.WriteLine("Diferenças encontradas nas configurações:");
            foreach (var diff in differences)
            {
                // Exibe a chave e os valores dos dois arquivos
                string value1 = settings1.ContainsKey(diff) ? settings1[diff] : "Não presente";
                string value2 = settings2.ContainsKey(diff) ? settings2[diff] : "Não presente";

                mensagemCompoleta +=($"- {diff}: {value2} para {value1}\n");
            }
            return mensagemCompoleta;
        }
        else
        {
            Console.WriteLine("Nenhuma diferença encontrada nas configurações.");
            return "";
        }
    }

    static bool AtualizarDadosSeguranca()
    {
        // String de conexão com o banco de dados MySQL


        try
        {
            using (MySqlConnection conn = new MySqlConnection(connectionString))
            {
                conn.Open();

                // Consulta SQL para buscar as informações da aplicação DiscordWebHookPlayersPalworld
                string query = $"SELECT senha, chave_criptografia, atualizarXbox FROM security_info WHERE nome_aplicacao = '{aplicacao}' LIMIT 1";

                using (MySqlCommand cmd = new MySqlCommand(query, conn))
                {
                    using (MySqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            SenhaValida = reader["senha"].ToString();
                            EncryptionKey = reader["chave_criptografia"].ToString();
                            AtualizarXbox = Boolean.Parse(reader["atualizarXbox"].ToString());
                            return true; // Atualização bem-sucedida
                        }
                        else
                        {
                            Console.WriteLine($"Aplicação '{aplicacao}' não encontrada no banco de dados.");
                            return false; // Aplicação não encontrada
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao acessar o banco de dados: {ex.Message}");
            return false; // Ocorreu algum erro
        }
    }

    static bool VerificarSeguranca()
    {
        string uuid = ObterUUID();

        // Verifica se o arquivo de segurança existe
        if (!File.Exists(SecurityFilePath))
        {
            Console.WriteLine("Arquivo de segurança não encontrado.");
            return false; // Se o arquivo não existir, bloqueia a execução e solicita a senha
        }

        try
        {
            string[] encryptedUUID = File.ReadLines(SecurityFilePath).ToArray();
            string decryptedUUID = Decrypt(encryptedUUID[0], EncryptionKey);

            if (decryptedUUID == uuid)
            {
                return true; // UUID corresponde, pode continuar sem pedir senha
            }
            else
            {
                Console.WriteLine("UUID da máquina não corresponde. A execução foi bloqueada.");
                return false; // UUID diferente, não pode executar
            }
        }
        catch
        {
            Console.WriteLine("Erro ao verificar o arquivo de segurança.");
            return false;
        }
    }

    static void CriarArquivoSeguranca(string Servidor, string contato)
    {
        // Extrai o diretório do caminho do arquivo
        string directoryPath = Path.GetDirectoryName(SecurityFilePath);

        // Verifica se o diretório existe, caso contrário, cria o diretório
        if (!Directory.Exists(directoryPath))
        {
            Directory.CreateDirectory(directoryPath); // Cria todos os diretórios no caminho, se necessário
        }

        string uuid = ObterUUID();
        string encryptedUUID = Encrypt(uuid, EncryptionKey);
        string encryptedServer = Encrypt(Servidor, EncryptionKey);
        string encryptedContato = Encrypt(contato, EncryptionKey);
        string encryptedPlataforma = Encrypt(plataformaConnect, EncryptionKey);

        // Salva o UUID criptografado no arquivo de segurança
        File.WriteAllText(SecurityFilePath, $"{encryptedUUID}\n{encryptedServer}\n{encryptedContato}\n{encryptedPlataforma}");

        // Define o arquivo como oculto
        File.SetAttributes(SecurityFilePath, FileAttributes.Hidden);
    }

    static string ObterUUID()
    {
        // Configurando o processo para executar o PowerShell
        ProcessStartInfo processInfo = new ProcessStartInfo("powershell", "Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID")
        {
            RedirectStandardOutput = true, // Redireciona a saída para capturar o UUID
            UseShellExecute = false,       // Evita o uso do shell do sistema
            CreateNoWindow = true          // Não cria uma janela visível
        };

        using (Process process = Process.Start(processInfo))
        {
            process.WaitForExit(); // Espera o processo terminar

            string uuidOutput = process.StandardOutput.ReadToEnd(); // Lê a saída do processo
            return uuidOutput.Trim(); // Retorna o UUID (sem linhas vazias)
        }
    }

    // Funções de criptografia
    static string Encrypt(string plainText, string key)
    {
        byte[] iv = new byte[16];
        byte[] array;

        using (Aes aes = Aes.Create())
        {
            aes.Key = GetValidKey(key);  // Garante que a chave tenha o tamanho correto
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                    array = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(array);
    }

    static string Decrypt(string cipherText, string key)
    {
        byte[] iv = new byte[16];
        byte[] buffer = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = GetValidKey(key);  // Garante que a chave tenha o tamanho correto
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }

    // Função para garantir que a chave tenha 32 bytes (256 bits)
    static byte[] GetValidKey(string key)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        Array.Resize(ref keyBytes, 32);  // Redimensiona para 32 bytes
        return keyBytes;
    }

    static void AtualizarServidor(string datetime)
    {
        Console.WriteLine("Atualizando servidor PalWorld...");

        // Caminho fixo para steamcmd
        string steamCmdPath = @"C:\steamcmd";
        string logPath = Path.Combine(steamCmdPath, "steamapps", "common", "PalServer", "UpLog");

        // Verifica se o diretório steamCmdPath existe, caso contrário, cria o diretório
        if (!Directory.Exists(steamCmdPath))
        {
            Console.WriteLine("Diretório C:\\steamcmd não encontrado, criando o diretório...");
            Directory.CreateDirectory(steamCmdPath);
        }

        // Verifica se o arquivo steamcmd.exe existe no diretório, se não, copia de um local predefinido
        string steamCmdExecutable = Path.Combine(steamCmdPath, "steamcmd.exe");

        if (!File.Exists(steamCmdExecutable))
        {
            // Caminho de origem do steamcmd.exe dentro da aplicação
            string steamCmdSourcePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "steamcmd.exe");

            if (File.Exists(steamCmdSourcePath))
            {
                // Copia o arquivo steamcmd.exe para o diretório C:\steamcmd
                Console.WriteLine("steamcmd.exe não encontrado, copiando da aplicação...");
                File.Copy(steamCmdSourcePath, steamCmdExecutable);
            }
            else
            {
                Console.WriteLine("Arquivo steamcmd.exe não encontrado no diretório de recursos da aplicação.");
                return;
            }
        }

        // Verifica se o diretório UpLog existe, caso contrário, cria o diretório
        if (!Directory.Exists(logPath))
        {
            Directory.CreateDirectory(logPath);
        }

        string logFilePath = Path.Combine(logPath, $"update_log_{datetime}.txt");

        using (StreamWriter logFile = new StreamWriter(logFilePath, true))
        {
            logFile.WriteLine($"{DateTime.Now} - Iniciando a atualização...");

            ProcessStartInfo processInfo = new ProcessStartInfo(steamCmdExecutable, "+login anonymous +app_update 2394010 validate +quit")
            {
                WorkingDirectory = steamCmdPath,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Process process = Process.Start(processInfo);

            if (process != null)
            {
                System.Threading.Tasks.Task.Run(() =>
                {
                    using (StreamReader reader = process.StandardOutput)
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            Console.WriteLine(line);
                            logFile.WriteLine($"{DateTime.Now} - {line}");
                        }
                    }
                });

                // Atualiza o console a cada 10 segundos com uma mensagem
                while (!process.HasExited)
                {
                    //Console.WriteLine($"{DateTime.Now} - Atualização em andamento...");
                    Thread.Sleep(TimeSpan.FromSeconds(1));
                }

                // Espera o processo terminar
                process.WaitForExit();

                logFile.WriteLine($"{DateTime.Now} - Atualização concluída.");
            }
        }
        Console.WriteLine("Atualização do servidor PalWorld concluída 100%.");
    }

    static bool VerificarDiferencaArquivos(string file1, string file2)
    {
        // Diretório onde o arquivo DefaultPalWorldSettings.ini está localizado
        string defaultConfigDirectory = @"C:\steamcmd\steamapps\common\PalServer";
        string defaultConfigFile = Path.Combine(defaultConfigDirectory, "DefaultPalWorldSettings.ini");

        if (file1.Contains("Engine.ini"))
        {
            string resourcesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources");
            defaultConfigFile = Path.Combine(resourcesDirectory, "Engine.ini");
        }


        // Verificar e criar o diretório do arquivo se não existir
        string directory1 = Path.GetDirectoryName(file1);
        string directory2 = Path.GetDirectoryName(file2);

        if (!Directory.Exists(directory1))
        {
            Console.WriteLine($"Diretório {directory1} não encontrado, criando...");
            Directory.CreateDirectory(directory1);
        }

        if (!Directory.Exists(directory2))
        {
            Console.WriteLine($"Diretório {directory2} não encontrado, criando...");
            Directory.CreateDirectory(directory2);
        }

        // Verificar se o arquivo file1 (PalWorldSettings.ini) existe
        if (!File.Exists(file1))
        {
            Console.WriteLine($"Arquivo {file1} não encontrado.");

            // Verificar se o arquivo DefaultPalWorldSettings.ini existe
            if (File.Exists(defaultConfigFile))
            {
                Console.WriteLine($"Copiando {defaultConfigFile} para {file1}...");
                File.Copy(defaultConfigFile, file1);  // Copiar e renomear
            }
            else
            {
                Console.WriteLine($"Arquivo {defaultConfigFile} não encontrado, impossível criar {file1}.");
                return false;  // Não podemos proceder sem o arquivo padrão
            }
        }

        // Verificar se o arquivo file2 (comparação) existe, se não, criar um arquivo vazio
        if (!File.Exists(file2))
        {
            Console.WriteLine($"Arquivo {file2} não encontrado, criando arquivo vazio...");
            File.WriteAllText(file2, ""); // Cria arquivo vazio para comparação
        }

        // Implementar lógica de comparação dos arquivos aqui (pode ser leitura linha por linha ou hash)
        return !File.ReadAllText(file1).Equals(File.ReadAllText(file2));
    }

    static Dictionary<string, string> ExtrairConfiguracoes(string content)
    {
        var settings = new Dictionary<string, string>();

        // Regex para capturar chave e valor no formato chave=valor
        var regex = new Regex(@"^([a-zA-Z0-9_]+)\s*=\s*(\"".*?\"")|([^,\n]+)(?=\s*,|$)", RegexOptions.Multiline);

        var matches = regex.Matches(content);

        foreach (Match match in matches)
        {
            var key = match.Groups[1].Value.Trim();
            var value = match.Groups[2].Value.Length > 0 ? match.Groups[2].Value.Trim() : match.Groups[3].Value.Trim();

            // Adiciona ao dicionário com a chave e o valor
            if (!string.IsNullOrEmpty(key))
            {
                settings[key] = value;
            }
        }

        return settings;
    }

    static async System.Threading.Tasks.Task SubstituirArquivosPalguardupdate(string datetime)
    {
        string updateDir = @"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\Palguardupdate";
        string win64Dir = @"C:\steamcmd\steamapps\common\PalServer\Pal\Binaries\Win64";
        string backupDir = @$"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\BackupPalguard\{datetime}";

        // Verifica se o diretório de atualização existe
        if (Directory.Exists(updateDir))
        {
            Console.WriteLine("Arquivos de atualização encontrados, iniciando processo...");
            bool hasUpdates = false; // Variável para controlar se houve atualizações

            // Substitui os arquivos do Win64 com os arquivos do updateDir
            foreach (string updateFile in Directory.GetFiles(updateDir))
            {
                string fileName = Path.GetFileName(updateFile);
                string destinationFilePath = Path.Combine(win64Dir, fileName);
                string backupFilePath = Path.Combine(backupDir, fileName);

                // Se o arquivo já existir no diretório de destino (Win64), faça o backup
                if (File.Exists(destinationFilePath))
                {
                    // Cria o diretório de backup se não existir
                    if (!Directory.Exists(backupDir))
                    {
                        Directory.CreateDirectory(backupDir);
                    }

                    Console.WriteLine($"Fazendo backup de {destinationFilePath} para {backupFilePath}...");
                    File.Copy(destinationFilePath, backupFilePath, true); // Copia com substituição, se necessário
                }

                // Substitui o arquivo no diretório Win64
                Console.WriteLine($"Substituindo {destinationFilePath} com {updateFile}...");
                File.Copy(updateFile, destinationFilePath, true); // Copia com substituição
                hasUpdates = true; // Marca que houve atualizações
            }

            // Limpa o diretório de atualização após a substituição dos arquivos
            Console.WriteLine("Limpando diretório de atualização...");
            foreach (string file in Directory.GetFiles(updateDir))
            {
                File.Delete(file); // Remove os arquivos do diretório de atualização
            }

            Console.WriteLine("Processo de atualização do Palguard concluído e diretório de atualização limpo.");

            // Se houve atualizações, envia uma notificação via WhatsApp
            if (hasUpdates)
            {
                await EnviarMensagemWhatsApp($"{Servidor} ALERT - Atualização realizada em Palguard! Arquivos substituídos.", contatoWhatsApp);
            }
        }
        else
        {
            Console.WriteLine($"Diretório de atualização {updateDir} não encontrado. Nenhuma atualização realizada.");

            // Se o diretório de atualização não existir, cria o diretório vazio
            if (!Directory.Exists(updateDir))
            {
                Directory.CreateDirectory(updateDir);
                Console.WriteLine("Criando diretório de atualização Palguard.");
            }
        }
    }
   
    static void CriarTarefaAgendada()
    {
        string taskName = aplicacao;

        // Verifica se a tarefa já existe
        using (TaskService ts = new TaskService())
        {
            Microsoft.Win32.TaskScheduler.Task existingTask = ts.FindTask(taskName, true);

            if (existingTask == null)
            {
                Console.WriteLine("Tarefa não encontrada, criando nova tarefa...");

                // Cria uma nova definição de tarefa
                TaskDefinition td = ts.NewTask();
                td.RegistrationInfo.Description = $"Tarefa para atualizar PalServer e executar {aplicacao}.exe";

                // Usar um serviço de conta para execução independente do login do usuário
                td.Principal.UserId = "SYSTEM"; // Executa como SYSTEM
                td.Principal.LogonType = TaskLogonType.ServiceAccount;
                td.Principal.RunLevel = TaskRunLevel.Highest;

                // Gatilho: executa ao iniciar o sistema
                td.Triggers.Add(new BootTrigger());

                // Ação: Executa o PalServer
                td.Actions.Add(new ExecAction(@"C:\CodeCraft\Palserver_log_Discord\start.bat"));

                // Ação: Executa a própria aplicação (DiscordWebHookPlayers.exe)
                string appPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"{aplicacao}.exe");
                td.Actions.Add(new ExecAction(appPath));

                // Configurações de tarefa
                td.Settings.MultipleInstances = TaskInstancesPolicy.IgnoreNew;
                td.Settings.DisallowStartIfOnBatteries = true;
                td.Settings.StopIfGoingOnBatteries = true;
                td.Settings.ExecutionTimeLimit = TimeSpan.FromHours(72);

                // Registra a tarefa
                ts.RootFolder.RegisterTaskDefinition(taskName, td);

                Console.WriteLine("Tarefa agendada criada com sucesso.");
            }

        }
    }

    static void ReiniciarMaquina()
    {
#if !DEBUG
        Process.Start(new ProcessStartInfo("shutdown", "/r /t 0") { CreateNoWindow = true });
#endif
    }

    static async System.Threading.Tasks.Task EnviarMensagemWhatsApp(string mensagem, string contato)
    {
        try
        {
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, "http://sukeserver.ddns.net:3000/client/sendMessage/suke");
                request.Headers.Add("x-api-key", "SukeApiWhatsApp");

                // Substitui \n por uma nova linha real
                mensagem = mensagem.Replace("\\n", "\n");

                // Formata o JSON para envio
                var json = new
                {
                    chatId = contato,
                    contentType = "string",
                    content = mensagem
                };

                var jsonString = System.Text.Json.JsonSerializer.Serialize(json);
                request.Content = new StringContent(jsonString, Encoding.UTF8, "application/json");

                // Envia a requisição e obtém a resposta
                var response = await client.SendAsync(request);

                // Lê e exibe o resultado
                var responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Mensagem enviada com sucesso: {mensagem} para {contato}");
                    Console.WriteLine($"Response: {response.StatusCode}");
                }
                else
                {
                    Console.WriteLine($"Erro ao enviar mensagem. Status: {response.StatusCode}");
                    Console.WriteLine($"Detalhes: {responseContent}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro: {ex.Message}");
        }
    }
}
public class RRLogger
{
    private string connectionString = "Server=sukeserver.ddns.net;Database=db;User ID=sukeee;Password=Unreal05;Port=3306;SslMode=None;";

    public void LogExecution(string serverName, string hostname, DateTime executionTime, string executionStatus, string whatsappContact, string appVersion)
    {
        using (MySqlConnection conn = new MySqlConnection(connectionString))
        {
            try
            {
                conn.Open();

                // Query ajustada para incluir o campo AppVersion
                string query = "INSERT INTO db.RRLogs (ServerName, Hostname, ExecutionTime, ExecutionStatus, WhatsAppContact, AppVersion) " +
                               "VALUES (@ServerName, @Hostname, @ExecutionTime, @ExecutionStatus, @WhatsAppContact, @AppVersion)";

                using (MySqlCommand cmd = new MySqlCommand(query, conn))
                {
                    // Definindo os parâmetros da consulta
                    cmd.Parameters.AddWithValue("@ServerName", serverName);
                    cmd.Parameters.AddWithValue("@Hostname", hostname);
                    cmd.Parameters.AddWithValue("@ExecutionTime", executionTime);
                    cmd.Parameters.AddWithValue("@ExecutionStatus", executionStatus);
                    cmd.Parameters.AddWithValue("@WhatsAppContact", whatsappContact);
                    cmd.Parameters.AddWithValue("@AppVersion", appVersion);  // Adicionando a versão da aplicação

                    // Executando o comando
                    cmd.ExecuteNonQuery();
                }

                Console.WriteLine("Log de execução inserido com sucesso.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao inserir log de execução: {ex.Message}");
            }
        }
    }
}

public class SystemInfo
{
    public string GetHostname()
    {
        try
        {
            // Obtém o nome do host local (nome da máquina)
            string hostname = Environment.MachineName;
            return hostname;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao obter o hostname: {ex.Message}");
            return null;
        }
    }
}

public class FirewallManager
{
    // Método para abrir portas no firewall
    public static void AbrirPortasFirewall()
    {
        try
        {
            // Verifica se a regra já existe antes de tentar criar
            CriarRegraSeNaoExistir("Palworld CodeCraft TCP 8211", "8211", "TCP");
            CriarRegraSeNaoExistir("Palworld CodeCraft UDP 8211", "8211", "UDP");

            CriarRegraSeNaoExistir("Palworld CodeCraft TCP 8212", "8212", "TCP");
            CriarRegraSeNaoExistir("Palworld CodeCraft UDP 8212", "8212", "UDP");

            CriarRegraSeNaoExistir("Palworld CodeCraft TCP 25575", "25575", "TCP");
            CriarRegraSeNaoExistir("Palworld CodeCraft UDP 25575", "25575", "UDP");

            Console.WriteLine("Portas abertas com sucesso.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao abrir portas no firewall: {ex.Message}");
        }
    }

    // Método para criar uma regra de firewall, se não existir
    private static void CriarRegraSeNaoExistir(string nomeRegra, string porta, string protocolo)
    {
        // Comando para verificar se a regra já existe
        string verificarComando = $"netsh advfirewall firewall show rule name=\"{nomeRegra}\"";

        // Executa o comando de verificação
        var processoVerificar = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/C {verificarComando}",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });

        // Captura a saída do comando
        string resultadoVerificacao = processoVerificar.StandardOutput.ReadToEnd();
        processoVerificar.WaitForExit();

        // Se a regra não existir (resultado não contém o nome da regra), cria a regra
        if (!resultadoVerificacao.Contains(nomeRegra))
        {
            // Comando para criar a regra no firewall
            string criarComando = $"netsh advfirewall firewall add rule name=\"{nomeRegra}\" protocol={protocolo} dir=in localport={porta} action=allow";

            // Executa o comando para adicionar a regra
            var processoCriar = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/C {criarComando}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            processoCriar.WaitForExit();

            Console.WriteLine($"Regra de firewall '{nomeRegra}' criada para porta {porta} ({protocolo}).");
        }
        else
        {
            Console.WriteLine($"A regra de firewall '{nomeRegra}' já existe.");
        }
    }
}

public class RequisitosChecker
{
    public static bool VerificarRequisitos()
    {
        List<string> faltando = new List<string>();

        //if (!VerificarDotnetRuntime())
        //{
        //    faltando.Add(".NET Runtime");
        //}

        if (!VerificarDirectX())
        {
            faltando.Add("DirectX");
        }

        if (!VerificarVCRedist())
        {
            faltando.Add("Visual C++ Redistributable");
        }

        if (faltando.Count == 0)
        {
            Console.WriteLine("Todos os requisitos estão presentes.");
            return true;
        }
        else
        {
            Console.WriteLine("Os seguintes requisitos estão faltando:");
            foreach (var requisito in faltando)
            {
                Console.WriteLine($"- {requisito}");
            }
            return false;
        }
    }

    // Verificar .NET Runtime
    private static bool VerificarDotnetRuntime()
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/C dotnet --list-runtimes",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var process = Process.Start(psi);
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // Verifica se o .NET 6 (ou outra versão necessária) está instalado
            return output.Contains("Microsoft.NETCore.App 6");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao verificar .NET Runtime: {ex.Message}");
            return false;
        }
    }

    // Verificar DirectX
    private static bool VerificarDirectX()
    {
        try
        {
            // Verificar no registro do Windows para DirectX
            var directxKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\DirectX");
            if (directxKey != null)
            {
                var version = directxKey.GetValue("Version")?.ToString();
                if (!string.IsNullOrEmpty(version))
                {
                    Console.WriteLine($"DirectX versão: {version}");
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao verificar DirectX: {ex.Message}");
            return false;
        }
    }

    // Verificar Visual C++ Redistributable
    private static bool VerificarVCRedist()
    {
        try
        {
            // Caminho para a chave do registro que lista o Visual C++ Redistributable
            string[] vcKeys = new string[]
            {
                @"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
                @"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86"
            };

            foreach (var keyPath in vcKeys)
            {
                var regKey = Registry.LocalMachine.OpenSubKey(keyPath);
                if (regKey != null)
                {
                    var installed = regKey.GetValue("Installed")?.ToString();
                    if (installed == "1")
                    {
                        Console.WriteLine("Visual C++ Redistributable está instalado.");
                        return true;
                    }
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao verificar Visual C++ Redistributable: {ex.Message}");
            return false;
        }
    }
}
