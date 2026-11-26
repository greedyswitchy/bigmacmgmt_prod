using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace ArmDeviceAgent;

public sealed record StoredBatch(long RowId, string BatchId, string PayloadJson);

public sealed class SqliteBatchQueue
{
    private readonly string _connectionString;
    private readonly SemaphoreSlim _dbLock = new(1, 1);

    public SqliteBatchQueue(IOptions<AgentOptions> options)
    {
        string dbPath = Path.IsPathRooted(options.Value.SqliteDbPath)
            ? options.Value.SqliteDbPath
            : Path.Combine(AppContext.BaseDirectory, options.Value.SqliteDbPath);

        _connectionString = $"Data Source={dbPath};Cache=Shared";
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS pending_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task EnqueueAsync(Guid batchId, string json, CancellationToken ct)
    {
        await _dbLock.WaitAsync(ct);
        try
        {
            await using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO pending_batches (batch_id, payload_json, created_at) VALUES ($bid, $json, $ts)";
            cmd.Parameters.AddWithValue("$bid", batchId.ToString());
            cmd.Parameters.AddWithValue("$json", json);
            cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally
        {
            _dbLock.Release();
        }
    }

    public async Task<List<StoredBatch>> PeekOldestAsync(int limit, CancellationToken ct)
    {
        await _dbLock.WaitAsync(ct);
        try
        {
            var result = new List<StoredBatch>();
            await using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, batch_id, payload_json FROM pending_batches ORDER BY id ASC LIMIT $lim";
            cmd.Parameters.AddWithValue("$lim", limit);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                result.Add(new StoredBatch(
                    RowId: reader.GetInt64(0),
                    BatchId: reader.GetString(1),
                    PayloadJson: reader.GetString(2)
                ));
            }
            return result;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    public async Task DeleteAsync(long rowId, CancellationToken ct)
    {
        await _dbLock.WaitAsync(ct);
        try
        {
            await using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM pending_batches WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", rowId);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        finally
        {
            _dbLock.Release();
        }
    }
}