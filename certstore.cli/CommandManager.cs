namespace certstore.cli
{
    public class CommandManager
    {
        public static void Do(string[] args)
        {
            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            var command = args[0].ToLower();
            switch (command)
            {
                case "export-public-key":
                    ExportPublicKey(args);
                    break;
                case "export-private-key":
                    ExportPrivateKey(args);
                    break;
                case "list-certificates":
                    ListCertificates(args);
                    break;
                case "remove-certificate":
                    RemoveCertificate(args);
                    break;
                case "list-expired-certificates":
                    ListExpiredCertificates(args);
                    break;
                case "get-certificate-thumbprint":
                    GetCertificateThumbprint(args);
                    break;
                case "add-certificate-file":
                    AddCertificateFile(args);
                    break;
                case "export-public-key-chain":
                    ExportPublicKeyChain(args);
                    break;
                
                default:
                    Console.WriteLine("Unknown command: " + command);
                    ShowUsage();
                    break;
            }
        }

        private static void ShowUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  export-public-key <certId>");
            Console.WriteLine("  export-private-key <certId>");
            Console.WriteLine("  export-public-key-chain <certId>");
            Console.WriteLine("  list-certificates");
            Console.WriteLine("  list-expired-certificates");
            Console.WriteLine("  get-certificate-thumbprint <certId>");
            Console.WriteLine("  add-certificate-file <filePath>");
            Console.WriteLine("  remove-certificate <certId>");
        }

        /// <summary>
        /// Exports the public key of a certificate to a file.
        /// </summary>
        /// <param name="args"></param>
        private static void ExportPublicKey(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: export-public-key <certId|certThumbprint> <exportFilePath>");
                return;
            }

            var certIdentifier = args[1];
            var exportFilePath = args[2];

            // Implement export public key logic here
            CertificateStore store = new CertificateStore("certstore.db");
            var certificate = store.GetCertificate(certIdentifier);

            if (certificate == null)
            {
                Console.WriteLine("Certificate not found: " + certIdentifier);
                return;
            }

            // Export the public key to the specified file path
            try
            {
                if (File.Exists(exportFilePath))
                {
                    Console.WriteLine("File already exists: " + exportFilePath);
                    return;
                }

                var fileStream = File.OpenWrite(exportFilePath);
                fileStream.Write(certificate.PublicKey, 0, certificate.PublicKey.Length);
                fileStream.Flush();
                fileStream.Close();

                Console.WriteLine("Public key exported to: " + exportFilePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to export public key: " + ex.Message);
            }
        }

        private static void ExportPublicKeyChain(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: export-public-key-chain <certId|certThumbprint> <exportFilePath>");
                return;
            }

            var certIdentifier = args[1];
            var exportFilePath = args[2];

            var store = new CertificateStore("certstore.db");
            var certificate = store.GetCertificate(certIdentifier);

            if (certificate == null)
            {
                Console.WriteLine("Certificate not found: " + certIdentifier);
                return;
            }

            if (File.Exists(exportFilePath))
            {
                Console.WriteLine("File already exists: " + exportFilePath);
                return;
            }

            var fileStream = File.OpenWrite(exportFilePath);

            for (var currentCertificate = certificate; currentCertificate != null; currentCertificate = store.GetCertificate(currentCertificate.Issuer))
            {
                Console.WriteLine("Exporting public key: " + currentCertificate.Name);

                // Append the public key to the file
                fileStream.Write(currentCertificate.PublicKey);
                fileStream.Flush();
            }

            fileStream.Close();
        }

        /// <summary>
        /// Exports the private key of a certificate to a file.
        /// </summary>
        /// <param name="args"></param>
        private static void ExportPrivateKey(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: export-private-key <certId|certThumbprint> <exportFilePath>");
                return;
            }

            var certIdentifier = args[1];
            var exportFilePath = args[2];

            // Implement export public key logic here
            CertificateStore store = new CertificateStore("certstore.db");
            var certificate = store.GetCertificate(certIdentifier);

            if (certificate == null)
            {
                Console.WriteLine("Certificate not found: " + certIdentifier);
                return;
            }

            // Export the public key to the specified file path
            try
            {
                if (File.Exists(exportFilePath))
                {
                    Console.WriteLine("File already exists: " + exportFilePath);
                    return;
                }

                var fileStream = File.OpenWrite(exportFilePath);
                fileStream.Write(certificate.PrivateKey, 0, certificate.PrivateKey.Length);
                fileStream.Flush();
                fileStream.Close();

                Console.WriteLine("Private key exported to: " + exportFilePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to export private key: " + ex.Message);
            }
        }

        /// <summary>
        /// Lists all certificates in the store.
        /// </summary>
        /// <param name="args"></param>
        private static void ListCertificates(string[] args)
        {
            // Implement list certificates logic here
            CertificateStore store = new CertificateStore("certstore.db");

            var certificates = store.GetCertificates().ToList();
            Console.WriteLine($"Certificates: (Found {certificates.Count} certificates)");

            foreach (var certificate in certificates)
            {
                Console.WriteLine(certificate);
            }
        }

        /// <summary>
        /// Lists all expired certificates in the store.
        /// </summary>
        /// <param name="args"></param>
        private static void ListExpiredCertificates(string[] args)
        {
            CertificateStore store = new CertificateStore("certstore.db");
            var certificates = store.GetCertificates().Where(i=>i.ValidTo>DateTime.Now).ToList();
            Console.WriteLine($"Certificates: (Found {certificates.Count} certificates)");

            foreach (var certificate in certificates)
            {
                Console.WriteLine(certificate);
            }
        }

        private static void RemoveCertificate(string[] args)
        {
            if (args.Length < 2)
            {
            Console.WriteLine("Usage: remove-certificate <certId|certThumbprint>");
            return;
            }
            var certIdentifier = args[1];
            // Implement remove certificate logic here
            CertificateStore store = new CertificateStore("certstore.db");
            var certificate = store.GetCertificate(certIdentifier);

            if (certificate == null)
            {
            Console.WriteLine("Certificate not found: " + certIdentifier);
            return;
            }

            store.RemoveCertificate(certIdentifier);
            Console.WriteLine("Certificate removed: " + certIdentifier);
        }



        private static void GetCertificateThumbprint(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: get-certificate-thumbprint <certId>");
                return;
            }
            var certId = args[1];
            
            var store = new CertificateStore("certstore.db");
            var certificate = store.GetCertificate(certId);
            
            if (certificate == null)
            {
                Console.WriteLine("Certificate not found: " + certId);
                return;
            }

            Console.WriteLine(certificate.Thumbprint);
        }

        private static void AddCertificateFile(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: add-certificate-file <filePath>");
                return;
            }
            var filePath = args[1];
            // Implement add certificate file logic here
        }
    }
}