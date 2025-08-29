using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Security.Principal;
using dk.nita.saml20;
using IdentityProviderDemo.Logic;
using System.Collections.Generic;
using System.Xml;

namespace IdentityProviderDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ControlController : ControllerBase
    {
        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            var result = new Dictionary<string, object>();
            if (VerifyDataFolder(out var errorMsg))
            {
                // Simulate configuration and SP list population
                result["certificate"] = $"Currently using certificate: {IDPConfig.IDPCertificate.SubjectName.Name}";
                result["baseUrl"] = $"Current server base url (EntityId): {IDPConfig.ServerBaseUrl}";
                result["serviceProviders"] = IDPConfig.GetServiceProviderIdentifiers();
                result["error"] = null;
            }
            else
            {
                result["error"] = errorMsg;
            }
            return Ok(result);
        }

        [HttpPost("upload-metadata")]
        public IActionResult UploadMetadata([FromForm] IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            try
            {
                XmlDocument doc = new XmlDocument();
                doc.XmlResolver = null;
                doc.PreserveWhitespace = true;
                using (var stream = file.OpenReadStream())
                using (var reader = new StreamReader(stream))
                {
                    doc.Load(reader);
                }
                IDPConfig.AddServiceProvider(doc);
                return Ok("Metadata uploaded and service provider added.");
            }
            catch
            {
                return BadRequest("Unable to load metadata. File contents were not recognized as XML.");
            }
        }

        [HttpPost("clear-cert")]
        public IActionResult ClearCertificate()
        {
            IDPConfig.ClearCertificate();
            return Ok("Certificate cleared.");
        }

        [HttpPost("change-baseurl")]
        public IActionResult ChangeBaseUrl()
        {
            IDPConfig.ServerBaseUrl = null;
            return Ok("Base URL changed.");
        }

        private bool VerifyDataFolder(out string errorMsg)
        {
            string dataFolder = ConfigHelper.GetIdpDataDirectory();
            errorMsg = string.Empty;
            if (string.IsNullOrEmpty(dataFolder))
            {
                errorMsg = "Missing 'IDPDataDirectory' AppSetting value! Please provide a valid directory name.";
                return false;
            }
            if (!Directory.Exists(dataFolder))
            {
                errorMsg = $"The directory '{dataFolder}' does not exist. Please create it and make sure it is writeable.";
                return false;
            }
            try
            {
                using (var fs = File.Create(Path.Combine(dataFolder, Path.GetRandomFileName()), 1, FileOptions.DeleteOnClose))
                {
                    // Success
                }
                return true;
            }
            catch (Exception)
            {
                errorMsg = $"Windows identity running this website ({WindowsIdentity.GetCurrent().Name}) does not have access rights on the directory '{dataFolder}'. Please ensure the user has 'modify' permission.";
                return false;
            }
        }
    }
}
