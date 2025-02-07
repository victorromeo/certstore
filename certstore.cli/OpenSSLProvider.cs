using System.Diagnostics;
using certstore.cli;

namespace certstore.cli {
    public static class OpenSSLProvider 
    {
        /// <summary>
        /// Generates a Root CA certificate.
        /// </summary>
        /// <param name="country">Country code for the certificate subject</param>
        /// <param name="state">State or province for the certificate subject</param>
        /// <param name="locality">Locality or city for the certificate subject</param>
        /// <param name="organization">Organization name for the certificate subject</param>
        /// <param name="organizationalUnit">Organizational unit for the certificate subject</param>
        /// <param name="commonName">Common name for the certificate subject</param>
        /// <param name="expiresDays">Number of days until the certificate expires</param>
        /// <returns>A generated Root CA certificate</returns>
        /// <exception cref="ApplicationException">Thrown when the Root CA certificate generation fails</exception>
        internal static Certificate GenerateRootCACertificate(string country, string state, string locality, string organization, string organizationalUnit, string commonName, int expiresDays)
        {
            using (var tempFolder = new TempFolder())
            {
                var privateKeyPath = Path.Combine(tempFolder.FolderPath, "rootca.key");
                var publicKeyPath = Path.Combine(tempFolder.FolderPath, "rootca.crt");

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = $"req -x509 -newkey rsa:2048 -keyout rootca.key -out rootca.crt -days {expiresDays} -subj \"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizationalUnit}/CN={commonName}\"",
                        WorkingDirectory = tempFolder.FolderPath,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new ApplicationException("Failed to generate Root CA certificate");
                }

                var privateKey = File.ReadAllBytes(privateKeyPath);
                var publicKey = File.ReadAllBytes(publicKeyPath);

                var thumbprint = GetThumbprintByOpenSSL(publicKeyPath);

                return new Certificate
                {
                    Name = "RootCA",
                    Issuer = "CertStore.Cli",
                    ValidFrom = DateTime.UtcNow,
                    ValidTo = DateTime.UtcNow.AddDays(expiresDays),
                    Thumbprint = thumbprint,
                    Subject = commonName,
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                    Format = "PEM"
                };
            }
        }

        /// <summary>
        /// Generates a certificate signed by the root CA.
        /// </summary>
        /// <param name="rootCA"></param>
        /// <param name="name"></param>
        /// <param name="csrPath"></param>
        /// <param name="expiresDays"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        internal static Certificate GenerateCertificateFromRequest(Certificate rootCA, string name, string csrPath, int expiresDays)
        {
            using (var tempFolder = new TempFolder())
            {
                // Write the root CA to a file
                var rootCAPath = Path.Combine(tempFolder.FolderPath, "rootca.crt");
                File.WriteAllBytes(rootCAPath, rootCA.PublicKey);

                // Write the root CA private key to a file
                var rootCAPrivateKeyPath = Path.Combine(tempFolder.FolderPath, "rootca.key");
                File.WriteAllBytes(rootCAPrivateKeyPath, rootCA.PrivateKey);

                var privateKeyPath = Path.Combine(tempFolder.FolderPath, "signed.key");
                var publicKeyPath = Path.Combine(tempFolder.FolderPath, "signed.crt");

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = $"x509 -req -in {csrPath} -CA rootca.crt -CAkey rootca.key -CAcreateserial -out signed.crt -days {expiresDays} -sha256",
                        WorkingDirectory = tempFolder.FolderPath,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new Exception("Failed to generate certificate from request");
                }

                var privateKey = File.ReadAllBytes(privateKeyPath);
                var publicKey = File.ReadAllBytes(publicKeyPath);

                var thumbprint = GetThumbprintByOpenSSL(publicKeyPath);
                var subject = GetCertificateSubjectByOpenSSL(publicKeyPath);

                return new Certificate
                {
                    Name = name,
                    Issuer = rootCA.Name,
                    ValidFrom = DateTime.UtcNow,
                    ValidTo = DateTime.UtcNow.AddDays(expiresDays),
                    Thumbprint = thumbprint,
                    Subject = subject,
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                    Format = "PEM"
                };
            }
        }

        /// <summary>
        /// Generates an intermediate certificate signed by the issuer certificate.
        /// </summary>
        /// <param name="country">Country code for the certificate subject</param>
        /// <param name="state">State or province for the certificate subject</param>
        /// <param name="locality">Locality or city for the certificate subject</param>
        /// <param name="organization">Organization name for the certificate subject</param>
        /// <param name="organizationalUnit">Organizational unit for the certificate subject</param>
        /// <param name="commonName">Common name for the certificate subject</param>
        /// <param name="issuer">Issuer certificate used to sign the intermediate certificate</param>
        /// <param name="expiresDays">Number of days until the certificate expires</param>
        /// <returns>Generated intermediate certificate</returns>
        /// <exception cref="Exception">Thrown when certificate generation fails</exception>
        internal static Certificate GenerateIntermediateCACertificate(string country, string state, string locality, string organization, string organizationalUnit, string commonName, Certificate issuer, int expiresDays)
        {
            using (var tempFolder = new TempFolder())
            {
                // Write the issuer certificate to a file
                var issuerCertPath = Path.Combine(tempFolder.FolderPath, "issuer.crt");
                File.WriteAllBytes(issuerCertPath, issuer.PublicKey);

                // Write the issuer private key to a file
                var issuerPrivateKeyPath = Path.Combine(tempFolder.FolderPath, "issuer.key");
                File.WriteAllBytes(issuerPrivateKeyPath, issuer.PrivateKey);

                var privateKeyPath = Path.Combine(tempFolder.FolderPath, "intermediate.key");
                var publicKeyPath = Path.Combine(tempFolder.FolderPath, "intermediate.crt");

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = $"req -new -newkey rsa:2048 -keyout intermediate.key -out intermediate.csr -subj \"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizationalUnit}/CN={commonName}\"",
                        WorkingDirectory = tempFolder.FolderPath,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new ApplicationException("Failed to generate intermediate certificate request");
                }

                process.StartInfo.Arguments = $"x509 -req -in intermediate.csr -CA issuer.crt -CAkey issuer.key -CAcreateserial -out intermediate.crt -days {expiresDays} -sha256";
                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new ApplicationException("Failed to generate intermediate certificate");
                }

                var privateKey = File.ReadAllBytes(privateKeyPath);
                var publicKey = File.ReadAllBytes(publicKeyPath);

                var thumbprint = GetThumbprintByOpenSSL(publicKeyPath);

                return new Certificate
                {
                    Name = commonName,
                    Issuer = issuer.Name,
                    ValidFrom = DateTime.UtcNow,
                    ValidTo = DateTime.UtcNow.AddDays(expiresDays),
                    Thumbprint = thumbprint,
                    Subject = commonName,
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                    Format = "PEM"
                };
            }
        }

        internal static Certificate GenerateServerCertificate(string country, string state, string locality, string organization, string organizationalUnit, string commonName, Certificate issuer, int expiresDays)
        {
            using (var tempFolder = new TempFolder())
            {
                // Write the issuer certificate to a file
                var issuerCertPath = Path.Combine(tempFolder.FolderPath, "issuer.crt");
                File.WriteAllBytes(issuerCertPath, issuer.PublicKey);

                // Write the issuer private key to a file
                var issuerPrivateKeyPath = Path.Combine(tempFolder.FolderPath, "issuer.key");
                File.WriteAllBytes(issuerPrivateKeyPath, issuer.PrivateKey);

                var privateKeyPath = Path.Combine(tempFolder.FolderPath, "server.key");
                var publicKeyPath = Path.Combine(tempFolder.FolderPath, "server.crt");

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "openssl",
                        Arguments = $"req -new -newkey rsa:2048 -keyout server.key -out server.csr -subj \"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizationalUnit}/CN={commonName}\"",
                        WorkingDirectory = tempFolder.FolderPath,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new ApplicationException("Failed to generate server certificate request");
                }

                process.StartInfo.Arguments = $"x509 -req -in server.csr -CA issuer.crt -CAkey issuer.key -CAcreateserial -out server.crt -days {expiresDays} -sha256";
                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new ApplicationException("Failed to generate server certificate");
                }

                var privateKey = File.ReadAllBytes(privateKeyPath);
                var publicKey = File.ReadAllBytes(publicKeyPath);

                var thumbprint = GetThumbprintByOpenSSL(publicKeyPath);

                return new Certificate
                {
                    Name = commonName,
                    Issuer = issuer.Name,
                    ValidFrom = DateTime.UtcNow,
                    ValidTo = DateTime.UtcNow.AddDays(expiresDays),
                    Thumbprint = thumbprint,
                    Subject = commonName,
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                    Format = "PEM"
                };
            }
        }

        internal static Certificate SignCertificateRequest(string csrPath, string privateKeyPath, string issuerCertPath, int expiresDays)
        {
            using (var tempFolder = new TempFolder())
            {
                var signedCertPath = Path.Combine(tempFolder.FolderPath, "signed.crt");

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                    FileName = "openssl",
                    Arguments = $"x509 -req -in {csrPath} -CA {issuerCertPath} -CAkey {privateKeyPath} -CAcreateserial -out {signedCertPath} -days {expiresDays} -sha256",
                    WorkingDirectory = tempFolder.FolderPath,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new Exception("Failed to sign certificate request");
                }

                var signedCert = File.ReadAllBytes(signedCertPath);
                var thumbprint = GetThumbprintByOpenSSL(signedCertPath);
                var subject = GetCertificateSubjectByOpenSSL(signedCertPath);

                return new Certificate
                {
                    Name = "SignedCert",
                    Issuer = "IssuerCert",
                    ValidFrom = DateTime.UtcNow,
                    ValidTo = DateTime.UtcNow.AddDays(expiresDays),
                    Thumbprint = thumbprint,
                    Subject = subject,
                    PublicKey = signedCert,
                    PrivateKey = File.ReadAllBytes(privateKeyPath),
                    Format = "PEM"
                };
            }
        }

        /// <summary>
        /// Gets the thumbprint of a certificate using OpenSSL.
        /// </summary>
        /// <param name="certFilePath"> Path of the public key certificate file </param>
        /// <returns> String SHA256 thumbprint of public key </returns>
        /// <exception cref="ApplicationException"> Throws exception when the certificate was not found </exception>
        internal static string GetThumbprintByOpenSSL(string certFilePath) 
        {
            
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = $"x509 -in {certFilePath} -noout -fingerprint -sha256",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new ApplicationException("Failed to get thumbprint");
            }

            var output = process.StandardOutput.ReadToEnd();
            var thumbprint = output.Split('=')[1].Replace(":", string.Empty).Trim();

            return thumbprint;

        }

        internal static string GetCertificateSubjectByOpenSSL(string certFilePath)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = $"x509 -in {certFilePath} -noout -subject",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new ApplicationException("Failed to get certificate subject");
            }

            var output = process.StandardOutput.ReadToEnd();
            var subject = output.Split('=')[1].Trim();

            return subject;
        }
    }
}
