using certstore.cli;

Console.WriteLine("Certificate Store");

CertificateStore store = new CertificateStore("certstore.db");

// Generate a new Root CA if it does not exist
var rootCA = store.GetCertificate("RootCA");
if (rootCA == null)
{
    Console.WriteLine("Root CA not found. Generating a new one...");

    rootCA = OpenSSLProvider.GenerateRootCACertificate("US", "CA", "San Francisco", "Contoso", "IT", "RootCA", 365);

    store.AddCertificate(rootCA);

    Console.WriteLine($"Root CA   : {rootCA.Name}");
    Console.WriteLine($"Public Key: {rootCA.PublicKeyBase64}");
    Console.WriteLine($"Thumbprint: {rootCA.Thumbprint}");
}

var intermediateCA = store.GetCertificate("IntermediateCA");
if (intermediateCA == null)
{
    Console.WriteLine("Intermediate CA not found. Generating a new one...");

    intermediateCA = OpenSSLProvider.GenerateIntermediateCACertificate("US", "CA", "San Francisco", "Contoso", "IT", "IntermediateCA", rootCA, 365);

    store.AddCertificate(intermediateCA);

    Console.WriteLine($"Intermediate CA   : {intermediateCA.Name}");
    Console.WriteLine($"Public Key: {intermediateCA.PublicKeyBase64}");
    Console.WriteLine($"Thumbprint: {intermediateCA.Thumbprint}");
}

var serverCertificate = store.GetCertificate("ServerCertificate");
if (serverCertificate == null)
{
    Console.WriteLine("Server certificate not found. Generating a new one...");

    serverCertificate = OpenSSLProvider.GenerateServerCertificate("US", "CA", "San Francisco", "Contoso", "IT", "ServerCertificate", intermediateCA, 365);

    store.AddCertificate(serverCertificate);

    Console.WriteLine($"Server Certificate   : {serverCertificate.Name}");
    Console.WriteLine($"Public Key: {serverCertificate.PublicKeyBase64}");
    Console.WriteLine($"Thumbprint: {serverCertificate.Thumbprint}");
}

// Handle the command line arguments
CommandManager.Do(args);
