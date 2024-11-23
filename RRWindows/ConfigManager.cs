using System;
using System.Data;
using System.IO;
using System.Text;
using Npgsql;

public class ConfigManager
{
    private static string connectionPostgres = "Host=sukeserver.ddns.net;Database=palbot_db;Username=PalAdm;Password=joga10";
    private readonly string _hostname;

    public ConfigManager(string hostname)
    {
        _hostname = hostname;
#if DEBUG
        _hostname = "r9steam";
#endif  
    }

    public void GenerateConfigFile(string outputFilePath)
    {
        // Carregar dados das tabelas
        var serverSettings = LoadSettings($"{_hostname}.server_settings");
        var optionSettings = LoadSettings("config_server.option_settings");

        // Montar o conteúdo do arquivo
        var iniContent = GenerateIniContent(serverSettings, optionSettings);

        // Salvar o arquivo
        File.WriteAllText(outputFilePath, iniContent);
        Console.WriteLine($"Arquivo de configuração gerado com sucesso em: {outputFilePath}");
    }

    private DataTable LoadSettings(string tableName)
    {
        using var connection = new NpgsqlConnection(connectionPostgres);
        connection.Open();

        var query = $"SELECT config, valor, deploy_valor, quantidade_de_uso FROM {tableName} Order by id ASC";
        using var command = new NpgsqlCommand(query, connection);
        using var adapter = new NpgsqlDataAdapter(command);
        var dataTable = new DataTable();
        adapter.Fill(dataTable);

        return dataTable;
    }

    private string GenerateIniContent(DataTable serverSettings, DataTable optionSettings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("[/Script/Pal.PalGameWorldSettings]");
        sb.Append("OptionSettings=(");

        // Adiciona configurações de optionSettings
        foreach (DataRow row in optionSettings.Rows)
        {
            string config = row["config"].ToString();
            string valor = row["valor"].ToString();
            string deployValor = row["deploy_valor"].ToString();
            int quantidadeDeUso = Convert.ToInt32(row["quantidade_de_uso"]);

            string finalValue = quantidadeDeUso > 0 ? deployValor : valor;
            sb.Append($"{config}={finalValue},");
        }

        // Adiciona configurações de serverSettings como parte de OptionSettings
        foreach (DataRow row in serverSettings.Rows)
        {
            string config = row["config"].ToString();
            string valor = row["valor"].ToString();
            string deployValor = row["deploy_valor"].ToString();
            int quantidadeDeUso = Convert.ToInt32(row["quantidade_de_uso"]);

            string finalValue = quantidadeDeUso > 0 ? deployValor : valor;

            // Verifica tipos de valores para formatação adequada
            if (bool.TryParse(finalValue, out _))
            {
                sb.Append($"{config}={finalValue.ToLower()},");
            }
            else if (int.TryParse(finalValue, out _) || float.TryParse(finalValue, out _))
            {
                sb.Append($"{config}={finalValue},");
            }
            else
            {
                sb.Append($"{config}=\"{finalValue}\",");
            }
        }

        sb.Length--; // Remove a última vírgula
        sb.AppendLine(")");

        return sb.ToString();
    }



    public void UpdateUsageCounts()
    {
        // Atualiza a quantidade de uso, reduzindo 1 onde necessário
        UpdateUsageCount($"{_hostname}.server_settings");
        UpdateUsageCount("config_server.option_settings");
    }

    private void UpdateUsageCount(string tableName)
    {
        using var connection = new NpgsqlConnection(connectionPostgres);
        connection.Open();

        var query = $@"
            UPDATE {tableName}
            SET quantidade_de_uso = CASE
                WHEN quantidade_de_uso > 0 THEN quantidade_de_uso - 1
                ELSE 0
            END";

        using var command = new NpgsqlCommand(query, connection);
        command.ExecuteNonQuery();
    }
}
