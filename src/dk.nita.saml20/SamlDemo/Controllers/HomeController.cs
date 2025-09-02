using Microsoft.AspNetCore.Mvc;

namespace SamlDemo.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
