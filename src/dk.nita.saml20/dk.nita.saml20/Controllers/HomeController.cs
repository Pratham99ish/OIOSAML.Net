using Microsoft.AspNetCore.Mvc;

namespace dk.nita.saml20.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("dk.nita.saml20 WebAPI running on .NET 8");
        }
    }
}
