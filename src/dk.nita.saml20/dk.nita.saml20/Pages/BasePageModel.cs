using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Identity.Saml.Pages
{
    /// <summary>
    /// Base page model for shared page logic in ASP.NET Core Razor Pages.
    /// </summary>
    public abstract class BasePageModel : PageModel
    {
        /// <summary>
        /// Gets or sets the page title.
        /// </summary>
        public string TitleText { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the header text.
        /// </summary>
        public string HeaderText { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the footer text.
        /// </summary>
        public string FooterText { get; set; } = string.Empty;
    }
}
