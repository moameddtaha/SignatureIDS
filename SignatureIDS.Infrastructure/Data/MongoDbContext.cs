using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using SignatureIDS.Core.Domain.Entity;
using System;
using System.Collections.Generic;
using System.Text;

namespace SignatureIDS.Infrastructure.Data
{
    public class MongoDbContext
    {
        private readonly IMongoDatabase _database;

        public MongoDbContext(IConfiguration configuration)
        {
            var connectionString = configuration["MONGODB_CONNECTION_STRING"] ?? throw new InvalidOperationException("MONGODB_CONNECTION_STRING is not configured");
            var databaseName = configuration["MONGODB_DATABASE_NAME"] ?? throw new InvalidOperationException("MONGODB_DATABASE_NAME is not configured");
            
            var client = new MongoClient(connectionString);
            _database = client.GetDatabase(databaseName);
        }

        public IMongoCollection<Rule> Rules => _database.GetCollection<Rule>("Rules");
        public IMongoCollection<SyncMetadata> SyncMetadata => _database.GetCollection<SyncMetadata>("SyncMetadata");
    }
}
