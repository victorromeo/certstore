namespace certstore.cli
{
    /// <summary>
    /// Model class for a certificate.
    /// </summary>
    public class Certificate
    {
        public string Name { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public DateTime ValidFrom { get; set; } = DateTime.MinValue;
        public DateTime ValidTo { get; set; } = DateTime.MinValue;
        public string Thumbprint { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;

        public byte[] PublicKey { get; set; } = new byte[0];
        public byte[] PrivateKey { get; set; } = new byte[0];

        public string PublicKeyBase64 => Convert.ToBase64String(PublicKey);
        public string PrivateKeyBase64 => Convert.ToBase64String(PrivateKey);

        public string Format { get; set; } = string.Empty;

        public override string ToString()
        {
            return $"Name: {Name}\nIssuer: {Issuer}\nValidFrom: {ValidFrom}\nValidTo: {ValidTo}\nThumbprint: {Thumbprint}\nSubject: {Subject}\nFormat: {Format}";
        }
    }
        
}