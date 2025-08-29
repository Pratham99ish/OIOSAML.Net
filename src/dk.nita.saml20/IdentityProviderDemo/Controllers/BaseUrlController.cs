using Microsoft.AspNetCore.Mvc;
using IdentityProviderDemo.Logic;

namespace IdentityProviderDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class BaseUrlController : ControllerBase
    {
        [HttpPost("set")]
        public IActionResult SetBaseUrl([FromBody] BaseUrlRequest req)
        {
            if (!Uri.IsWellFormedUriString(req.Url, UriKind.Absolute))
                return BadRequest("The provided URL is not a valid, absolute URL.");
            IDPConfig.ServerBaseUrl = req.Url;
            return Ok("Base URL set.");
        }
    }

    public class BaseUrlRequest
    {
        public string Url { get; set; }
    }
}
