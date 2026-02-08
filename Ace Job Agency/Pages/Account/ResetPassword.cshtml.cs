using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace Ace_Job_Agency.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IConfiguration _configuration;

        public ResetPasswordModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _db = db;
            _configuration = configuration;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required]
            public string Token { get; set; }
            [Required]
            [EmailAddress]
            public string Email { get; set; }
            [Required]
            [StringLength(100, MinimumLength = 12)]
            [DataType(DataType.Password)]
            public string NewPassword { get; set; }
            [DataType(DataType.Password)]
            [Compare("NewPassword")]
            public string ConfirmPassword { get; set; }
        }

        public void OnGet(string token = null, string email = null)
        {
            Input = new InputModel { Token = token, Email = email };
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();
            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null) return RedirectToPage("/Account/ResetPasswordConfirmation");

            // Capture the current password hash BEFORE any changes
            var currentPasswordHash = user.PasswordHash!;

            // HistoryCount = number of PREVIOUS passwords that cannot be reused
            var historyCount = _configuration.GetValue<int>("PasswordPolicy:HistoryCount", 2);

            // Check against current password (always blocked)
            var currentPasswordCheck = _userManager.PasswordHasher.VerifyHashedPassword(user, currentPasswordHash, Input.NewPassword);
            if (currentPasswordCheck != PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError(string.Empty, $"You cannot reuse your current password or last {historyCount} passwords.");
                return Page();
            }

            // Check against the last N passwords from history (previous passwords)
            var recentHistory = await _db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.CreatedAt)
                .Take(historyCount)
                .ToListAsync();

            foreach (var r in recentHistory)
            {
                var verify = _userManager.PasswordHasher.VerifyHashedPassword(user, r.PasswordHash, Input.NewPassword);
                if (verify != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError(string.Empty, $"You cannot reuse your current password or last {historyCount} passwords.");
                    return Page();
                }
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors) ModelState.AddModelError(string.Empty, e.Description);
                return Page();
            }

            // Store the OLD password (captured before reset) in history
            _db.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = currentPasswordHash,
                CreatedAt = DateTime.UtcNow
            });

            // Update LastPasswordChangedAt
            user.LastPasswordChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Audit log
            _db.AuditLogs.Add(new AuditLog
            {
                EventType = "PasswordReset",
                UserId = user.Id,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow
            });

            await _db.SaveChangesAsync();

            return RedirectToPage("/Account/ResetPasswordConfirmation");
        }
    }
}
