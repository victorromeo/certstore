using System.Data.SQLite;

namespace certstore.cli
{

    /// <summary>
    /// Represents a store for managing certificates.
    /// </summary>
    public interface ICertificateStore
    {
        /// <summary>
        /// Adds a certificate to the store.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="certificateData"></param>
        void AddCertificate(Certificate certificate);
        
        /// <summary>
        /// Retrieves a certificate from the store by its name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        Certificate? GetCertificate(string name);
    }

    /// <summary>
    /// Represents a store for managing certificates using SQLite database.
    /// </summary>
    public class CertificateStore : ICertificateStore
    {
        /// <summary>
        /// The connection string to the SQLite database.
        /// </summary>
        private readonly string _connectionString;

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateStore"/> class.
        /// Creates the database file if it does not exist and initializes the database schema.
        /// </summary>
        /// <param name="databasePath">The file path to the SQLite database.</param>
        public CertificateStore(string databasePath)
        {
            // Implementation
            _connectionString = $"Data Source={databasePath}";

            InitializeDatabase();
        }

        /// <summary>
        /// Initializes the database by creating the Certificates table if it does not exist.
        /// </summary>
        private void InitializeDatabase()
        {
            // Create the database file if it does not exist
            using (var connection = new SQLiteConnection(_connectionString))
            {
                connection.Open();

                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "CREATE TABLE IF NOT EXISTS Certificates (Name TEXT PRIMARY KEY, Issuer TEXT, ValidFrom TEXT, ValidTo TEXT, Thumbprint TEXT, Subject TEXT, PublicKey BLOB, PrivateKey BLOB)";
                    command.ExecuteNonQuery();
                }
            }
        }

        /// <summary>
        /// Adds a certificate to the store.
        /// </summary>
        /// <param name="name">The name of the certificate.</param>
        /// <param name="certificateData">The certificate data as a byte array.</param>
        public void AddCertificate(Certificate certificate)
        {
            // Implementation
            using (var connection = new SQLiteConnection(_connectionString))
            {
                connection.Open();
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "INSERT INTO Certificates (Name, Issuer, ValidFrom, ValidTo, Thumbprint, Subject, PublicKey, PrivateKey) VALUES (@name, @issuer, @validFrom, @validTo, @thumbprint, @subject, @publicKey, @privateKey)";
                    
                    command.Parameters.AddWithValue("@name", certificate.Name);
                    command.Parameters.AddWithValue("@issuer", certificate.Issuer);
                    command.Parameters.AddWithValue("@validFrom", certificate.ValidFrom);
                    command.Parameters.AddWithValue("@validTo", certificate.ValidTo);
                    command.Parameters.AddWithValue("@thumbprint", certificate.Thumbprint);
                    command.Parameters.AddWithValue("@subject", certificate.Subject);
                    command.Parameters.AddWithValue("@publicKey", certificate.PublicKey);
                    command.Parameters.AddWithValue("@privateKey", certificate.PrivateKey);

                    command.ExecuteNonQuery();
                }
            }
        }

        public Certificate? GetCertificate(string certIdentifier) {
            // Implementation
            using (var connection = new SQLiteConnection(_connectionString))
            {
                connection.Open();
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "SELECT * FROM Certificates WHERE Name = @certIdentifier or Thumbprint = @certIdentifier";
                    command.Parameters.AddWithValue("@certIdentifier", certIdentifier);

                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            var certificate = new Certificate
                            {
                                Name = reader.GetString(0),
                                Issuer = reader.GetString(1),
                                ValidFrom = reader.GetDateTime(2),
                                ValidTo = reader.GetDateTime(3),
                                Thumbprint = reader.GetString(4),
                                Subject = reader.GetString(5),
                                PublicKey = reader["PublicKey"] as byte[] ?? new byte[0],
                                PrivateKey =  reader["PrivateKey"] as byte[] ?? new byte[0]
                            };

                            return certificate;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Retrieves the names of all certificates in the store.
        /// </summary>
        /// <returns></returns>
        public List<Certificate> GetCertificates() {
            // Implementation
            var certificates = new List<Certificate>();

            using (var connection = new SQLiteConnection(_connectionString))
            {
                connection.Open();
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "SELECT * FROM Certificates";

                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var certificate = new Certificate
                            {
                                Name = reader.GetString(0),
                                Issuer = reader.GetString(1),
                                ValidFrom = reader.GetDateTime(2),
                                ValidTo = reader.GetDateTime(3),
                                Thumbprint = reader.GetString(4),
                                Subject = reader.GetString(5),
                                PublicKey = reader["PublicKey"] as byte[] ?? new byte[0],
                                PrivateKey =  reader["PrivateKey"] as byte[] ?? new byte[0]
                            };

                            certificates.Add(certificate);
                        }
                    }
                }
            }

            return certificates;
        }

        public void RemoveCertificate(string name) 
        {    
            using (var connection = new SQLiteConnection(_connectionString))
            {
                connection.Open();

                // Check if the certificate is used by any other certificate
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "SELECT COUNT(*) FROM Certificates WHERE Issuer = @name";
                    command.Parameters.AddWithValue("@name", name);

                    var count = (long)command.ExecuteScalar();

                    if (count > 0)
                    {
                        throw new InvalidOperationException("Cannot delete a certificate that is used by other certificates");
                    }
                }

                // Delete the certificate
                using (var command = new SQLiteCommand(connection))
                {
                    command.CommandText = "DELETE FROM Certificates WHERE Name = @name";
                    command.Parameters.AddWithValue("@name", name);

                    command.ExecuteNonQuery();
                }
            }
        }
    }

}
