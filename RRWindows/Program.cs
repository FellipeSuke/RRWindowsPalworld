using Microsoft.Win32.TaskScheduler;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static readonly string SecurityFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "security.dat");
    static readonly string EncryptionKey = "ChaveDeCriptografiaSegura"; // Defina uma chave forte
    static readonly string SenhaValida = "SenhaSegura"; // Defina aqui a senha para a primeira execução ou recuperação
    static string Servidor = "Não Definido";
    static string contatoWhatsApp = "556784578078@c.us";
    

    static async System.Threading.Tasks.Task Main(string[] args)
    {
        // Verificar se a segurança está OK (arquivo de segurança existe e é válido)
        if (!VerificarSeguranca())
        {
            // Se a verificação falhar, solicitar senha
            Console.WriteLine("Arquivo de segurança não encontrado. Insira a senha para continuar:");
            string senhaInserida = Console.ReadLine();
            

            if (senhaInserida == SenhaValida)
            {
                // Senha correta, cria o arquivo de segurança com o UUID da máquina
                Console.WriteLine("Iniciando Instalação. Insira um nome para o Servidor:");
                Servidor = Console.ReadLine();
                Console.WriteLine("Insira o ContatoWhatsApp:");
                string contatoWhatsRead = Console.ReadLine();
                if (!string.IsNullOrEmpty(contatoWhatsRead))
                {
                    contatoWhatsApp = contatoWhatsRead;
                }

                CriarArquivoSeguranca(Servidor,contatoWhatsApp);
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

        Servidor = decrypteServer;
        
        // Configuração da data e hora
        string datetime = DateTime.Now.ToString("yyyy-MM-dd_HH-mm");
        Console.WriteLine($"'{datetime}'");

        // Diretórios de origem, destino e backup
        string origem = @"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\PalWorldSettings.ini";
        string destino = @"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\WindowsServer\PalWorldSettings.ini";
        string backup = @$"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\Backup\Backup_{datetime}";

        // Enviar mensagem via curl
        await EnviarMensagemWhatsApp($"{Servidor} ALERT - Servidor em RR!",contatoWhatsApp);

        // Atualizar servidor
        AtualizarServidor(datetime);

        // Aguardar 2 segundos após update Steam
        await System.Threading.Tasks.Task.Delay(2000);

        // Comparar arquivos e realizar backup se necessário
        if (VerificarDiferencaArquivos(origem, destino))
        {
            Console.WriteLine("Arquivos diferentes, realizando o backup e deploy...");
            await EnviarMensagemWhatsApp($"{Servidor} - Arquivos diferentes, realizando o backup e deploy PALWORLD SERVER INI...", contatoWhatsApp);

            if (!Directory.Exists(backup))
            {
                Directory.CreateDirectory(backup);
            }

            File.Move(destino, Path.Combine(backup, $"PalWorldSettings_{datetime}.ini"));
            File.Copy(origem, destino, true);
        }
        else
        {
            Console.WriteLine("Arquivos são iguais, nenhuma cópia realizada.");
        }

        // Substituir todos os arquivos na pasta Palguardupdate
        SubstituirArquivosPalguardupdate(datetime);

        CriarTarefaAgendada();
        // Aguardar 5 segundos antes de reiniciar a máquina
        Console.WriteLine("Aguardando 5 segundos REINICIANDO MAQUINA...");
        await System.Threading.Tasks.Task.Delay(5000);

        // Reiniciar a máquina
        ReiniciarMaquina();
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
        
        // Salva o UUID criptografado no arquivo de segurança
        File.WriteAllText(SecurityFilePath, $"{encryptedUUID}\n{encryptedServer}\n{encryptedContato}");
        
    }

    static string ObterUUID()
    {
        ProcessStartInfo processInfo = new ProcessStartInfo("wmic", "csproduct get UUID")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        Process process = Process.Start(processInfo);
        process.WaitForExit();

        string uuidOutput = process.StandardOutput.ReadToEnd();
        string[] lines = uuidOutput.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
        return lines.Length > 1 ? lines[1].Trim() : string.Empty;
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
            logFile.WriteLine($"{DateTime.Now} - Updating server...");

            ProcessStartInfo processInfo = new ProcessStartInfo(steamCmdExecutable, "+login anonymous +app_update 2394010 validate +quit")
            {
                WorkingDirectory = steamCmdPath,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Process process = Process.Start(processInfo);
            process.WaitForExit();

            logFile.WriteLine($"{DateTime.Now} - Update complete.");
        }
    }


    static bool VerificarDiferencaArquivos(string file1, string file2)
    {
        // Diretório onde o arquivo DefaultPalWorldSettings.ini está localizado
        string defaultConfigDirectory = @"C:\steamcmd\steamapps\common\PalServer";
        string defaultConfigFile = Path.Combine(defaultConfigDirectory, "DefaultPalWorldSettings.ini");

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


    static void SubstituirArquivosPalguardupdate(string datetime)
    {
        string updateDir = @"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\Palguardupdate";
        string win64Dir = @"C:\steamcmd\steamapps\common\PalServer\Pal\Binaries\Win64";
        string backupDir = @$"C:\steamcmd\steamapps\common\PalServer\Pal\Saved\Config\DeployConfigServer\BackupPalguard\{datetime}";

        // Verifica se o diretório de atualização existe
        if (Directory.Exists(updateDir))
        {
            Console.WriteLine("Arquivos de atualização encontrados, iniciando processo...");

            // Cria o diretório de backup se não existir
            if (!Directory.Exists(backupDir))
            {
                Directory.CreateDirectory(backupDir);
            }

            // Substitui os arquivos do Win64 com os arquivos do updateDir
            foreach (string updateFile in Directory.GetFiles(updateDir))
            {
                string fileName = Path.GetFileName(updateFile);
                string destinationFilePath = Path.Combine(win64Dir, fileName);
                string backupFilePath = Path.Combine(backupDir, fileName);

                // Se o arquivo já existir no diretório de destino (Win64), faça o backup
                if (File.Exists(destinationFilePath))
                {
                    Console.WriteLine($"Fazendo backup de {destinationFilePath} para {backupFilePath}...");
                    File.Copy(destinationFilePath, backupFilePath, true); // Copia com substituição, se necessário
                }

                // Substitui o arquivo no diretório Win64
                Console.WriteLine($"Substituindo {destinationFilePath} com {updateFile}...");
                File.Copy(updateFile, destinationFilePath, true); // Copia com substituição
            }

            // Limpa o diretório de atualização após a substituição dos arquivos
            Console.WriteLine("Limpando diretório de atualização...");
            foreach (string file in Directory.GetFiles(updateDir))
            {
                File.Delete(file); // Remove os arquivos do diretório de atualização
            }

            Console.WriteLine("Processo de atualização do Palguard concluído e diretório de atualização limpo.");
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
        string taskName = "PalServerTask";

        // Verifica se a tarefa já existe
        using (TaskService ts = new TaskService())
        {
            Microsoft.Win32.TaskScheduler.Task existingTask = ts.FindTask(taskName, true);

            if (existingTask == null)
            {
                Console.WriteLine("Tarefa não encontrada, criando nova tarefa...");

                // Cria uma nova definição de tarefa
                TaskDefinition td = ts.NewTask();
                td.RegistrationInfo.Description = "Tarefa para atualizar PalServer e executar RRWindows.exe";

                // Usar um serviço de conta para execução independente do login do usuário
                td.Principal.UserId = "SYSTEM"; // Executa como SYSTEM
                td.Principal.LogonType = TaskLogonType.ServiceAccount;
                td.Principal.RunLevel = TaskRunLevel.Highest;

                // Gatilho: executa ao iniciar o sistema
                td.Triggers.Add(new BootTrigger());

                // Ação: Executa o PalServer
                td.Actions.Add(new ExecAction(@"C:\steamcmd\steamapps\common\PalServer\PalServer.exe",
                    "-useperfthreads -NoAsyncLoadingThread -UseMultithreadForDS -publiclobby"));

                // Ação: Executa a própria aplicação (RRWindows.exe)
                string appPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RRWindows.exe");
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
            else
            {
                Console.WriteLine("A tarefa já existe.");
            }
        }
    }



    static void ReiniciarMaquina()
    {
        Process.Start(new ProcessStartInfo("shutdown", "/r /t 0") { CreateNoWindow = true });
    }

    static async System.Threading.Tasks.Task EnviarMensagemWhatsApp(string mensagem, string contato)
    {
        // Implementar a lógica para enviar mensagem via WhatsApp aqui
        var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Post, "http://sukeserver.ddns.net:3000/client/sendMessage/suke");
        request.Headers.Add("x-api-key", "SukeApiWhatsApp");
        var content = new StringContent("{" + $"\r\n  \"chatId\": \"{contato}\",\r\n  \"contentType\": \"string\",\r\n  \"content\": \"{mensagem}\"\r\n" + "}", null, "application/json");
        request.Content = content;
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response: {response.StatusCode}");
        Console.WriteLine($"Mensagem enviada: {mensagem} para {contato}");
    }
}
