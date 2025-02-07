namespace certstore.cli
{
    /// <summary>
    /// Represents a temporary folder that will be deleted when disposed
    /// </summary>
    public class TempFolder : IDisposable
    {
        /// <summary>
        /// The path of the temporary folder
        /// </summary>
        public string FolderPath { get; }

        public TempFolder()
        {
            FolderPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(FolderPath);
        }

        public void Dispose()
        {
            if (Directory.Exists(FolderPath))
            {
                Directory.Delete(FolderPath, true);
            }
        }
    }
        
}