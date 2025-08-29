using Microsoft.AspNetCore.Mvc;

namespace Identity.Saml.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Identity.Saml WebAPI running on .NET 8");
        }
    }
}
