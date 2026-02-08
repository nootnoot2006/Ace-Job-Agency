using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;
using Ace_Job_Agency.Data;

namespace Ace_Job_Agency.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;
        private readonly AuthDbContext _db;

        public string? DecryptedNRIC { get; set; }
        public ApplicationUser? CurrentUser { get; set; }

        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, IDataProtectionProvider provider, AuthDbContext db)
        {
            _logger = logger;
            _userManager = userManager;
            _protector = provider.CreateProtector("NRICProtector");
            _db = db;
        }

        public async Task OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                CurrentUser = user;
                try
                {
                    if (!string.IsNullOrEmpty(user.NRICEncrypted))
                    {
                        DecryptedNRIC = _protector.Unprotect(user.NRICEncrypted);
                    }
                }
                catch
                {
                    DecryptedNRIC = "[Unable to decrypt]";
                }
            }
        }
    }
}
