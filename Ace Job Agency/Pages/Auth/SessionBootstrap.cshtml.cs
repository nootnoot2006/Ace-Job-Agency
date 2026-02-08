using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Ace_Job_Agency.Pages.Auth
{
    // This page captures sessionToken/tabId from the login redirect,
    // persist them (server session + optional cookies) and returns a small HTML page
    // that writes the values into sessionStorage in this tab and then navigates to /Index.
    public class SessionBootstrapModel : PageModel
    {
        [BindProperty(SupportsGet = true)]
        public string? SessionToken { get; set; }
        [BindProperty(SupportsGet = true)]
        public string? TabId { get; set; }

        public bool HasValues => !string.IsNullOrWhiteSpace(SessionToken) || !string.IsNullOrWhiteSpace(TabId);

        public IActionResult OnGet(string? sessionToken = null, string? tabId = null)
        {
            // If invoked without parameters, return200 OK to avoid interfering with background requests.
            if (string.IsNullOrWhiteSpace(sessionToken) && string.IsNullOrWhiteSpace(tabId))
            {
                return new OkResult();
            }

            // Persist to server session when present
            if (!string.IsNullOrWhiteSpace(sessionToken))
            {
                try { HttpContext.Session.SetString("SessionToken", sessionToken); } catch { }
                // set fallback cookie so manual navigation can still present the token (secure only on HTTPS)
                try
                {
                    var opts = new Microsoft.AspNetCore.Http.CookieOptions
                    {
                        HttpOnly = true,
                        Secure = HttpContext.Request.IsHttps,
                        SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax,
                        Expires = DateTimeOffset.UtcNow.AddMinutes(30)
                    };
                    Response.Cookies.Append("AJASessionToken", sessionToken, opts);
                }
                catch { }
            }

            if (!string.IsNullOrWhiteSpace(tabId))
            {
                try { HttpContext.Session.SetString("tabId", tabId); } catch { }
                try
                {
                    var opts = new Microsoft.AspNetCore.Http.CookieOptions
                    {
                        HttpOnly = true,
                        Secure = HttpContext.Request.IsHttps,
                        SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax,
                        Expires = DateTimeOffset.UtcNow.AddMinutes(30)
                    };
                    Response.Cookies.Append("AJATabId", tabId, opts);
                }
                catch { }
            }

            // Expose values to the page so the inline script can set sessionStorage for this tab.
            SessionToken = sessionToken;
            TabId = tabId;

            return Page();
        }
    }
}
