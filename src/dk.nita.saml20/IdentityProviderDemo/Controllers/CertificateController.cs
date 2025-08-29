using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using IdentityProviderDemo.Logic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System;
using System.Collections.Generic;

namespace IdentityProviderDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CertificateController : ControllerBase
    {
        [HttpGet("stores")]
        public IActionResult GetCertificateStores()
        {
            var stores = Enum.GetValues(typeof(StoreName));
            var locations = Enum.GetValues(typeof(StoreLocation));
            return Ok(new { stores, locations });
        }

        [HttpGet("certificates")]
        public IActionResult GetCertificates([FromQuery] StoreName storeName, [FromQuery] StoreLocation storeLocation)
        {
            var result = new List<object>();
            X509Store store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    result.Add(new {
                        Subject = cert.SubjectName.Name,
                        Thumbprint = cert.Thumbprint,
                        HasPrivateKey = cert.HasPrivateKey
                    });
                }
                return Ok(result);
            }
            catch (CryptographicException ex)
            {
                return BadRequest(ex.Message);
            }
            finally
            {
                store.Close();
            }
        }

        [HttpPost("select")]
        public IActionResult SelectCertificate([FromBody] CertificateSelectionRequest request)
        {
            X509Store store = new X509Store(request.StoreName, request.StoreLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2 cert = null;
                foreach (X509Certificate2 c in store.Certificates)
                {
                    if (c.Thumbprint == request.Thumbprint)
                    {
                        cert = c;
                        break;
                    }
                }
                if (cert == null)
                    return BadRequest("Certificate not found.");
                if (!cert.HasPrivateKey)
                    return BadRequest("The selected certificate does not contain a private key.");
                try
                {
                    var key = cert.PrivateKey;
                }
                catch (CryptographicException)
                {
                    return BadRequest("The private key of the certificate cannot be accessed. Make sure the user has read access.");
                }
                IDPConfig.SetCertificate(cert, request.StoreName, request.StoreLocation);
                return Ok("Certificate selected and set.");
            }
            finally
            {
                store.Close();
            }
        }
    }

    public class CertificateSelectionRequest
    {
        public StoreName StoreName { get; set; }
        public StoreLocation StoreLocation { get; set; }
        public string Thumbprint { get; set; }
    }
}
