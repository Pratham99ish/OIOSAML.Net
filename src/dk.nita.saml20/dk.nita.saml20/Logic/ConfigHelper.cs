using Microsoft.Extensions.Configuration;
using System.IO;

namespace dk.nita.saml20.Logic
{
    public class ConfigHelper
    {
        private static IConfiguration? _configuration;

        public static void Initialize(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public static string GetIdpDataDirectory()
        {
            var dir = _configuration?["IDPDataDirectory"];
            if (dir != null && !Path.IsPathRooted(dir))
            {
                return Path.Combine(Directory.GetCurrentDirectory(), dir);
            }
            return dir ?? string.Empty;
        }
    }
}
