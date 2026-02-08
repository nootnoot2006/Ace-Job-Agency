using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using Ace_Job_Agency.Middleware;

namespace Ace_Job_Agency.Pages.Manage
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
    private readonly UserManager<ApplicationUser> _userManager;
     private readonly SignInManager<ApplicationUser> _signInManager;
  private readonly AuthDbContext _db;
        private readonly IConfiguration _configuration;
        private readonly PolicyModeConfig _policyMode;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
     SignInManager<ApplicationUser> signInManager,
       AuthDbContext db,
            IConfiguration configuration,
      PolicyModeConfig policyMode)
        {
            _userManager = userManager;
      _signInManager = signInManager;
      _db = db;
            _configuration = configuration;
            _policyMode = policyMode;
    }

        [BindProperty]
        public InputModel Input { get; set; }

        public bool IsExpiredFlow { get; set; }
        public string? Message { get; set; }

        public class InputModel
      {
 [Required]
            [DataType(DataType.Password)]
         public string OldPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12)]
            public string NewPassword { get; set; }

            [DataType(DataType.Password)]
     [Compare("NewPassword")]
  public string ConfirmPassword { get; set; }
      }

        public void OnGet(bool expired = false)
        {
            IsExpiredFlow = expired;
    if (expired)
            {
                Message = "Your password has expired. Please set a new password to continue.";
       }
        }

    public async Task<IActionResult> OnPostAsync()
  {
            if (!ModelState.IsValid) return Page();
   var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Login");

       // Capture the current password hash BEFORE any changes
  var currentPasswordHash = user.PasswordHash!;

            // Get password policy based on individual toggles
      TimeSpan minPasswordAge;
          if (_policyMode.MinPasswordAge_UseTestMode)
      {
   var minAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinAge_TestMinutes", 1);
         minPasswordAge = TimeSpan.FromMinutes(minAgeMinutes);
            }
 else
     {
    var minAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinAge_ProductionMinutes", 5);
            minPasswordAge = TimeSpan.FromMinutes(minAgeMinutes);
     }

     // HistoryCount = number of PREVIOUS passwords that cannot be reused
            // e.g., HistoryCount=2 means current + 2 previous = 3 passwords blocked total
            var historyCount = _configuration.GetValue<int>("PasswordPolicy:HistoryCount", 2);

            // Prevent changing password too soon (skip if password is expired)
      var lastChange = await _db.PasswordHistories.Where(p => p.UserId == user.Id).OrderByDescending(p => p.CreatedAt).FirstOrDefaultAsync();

var isExpiredFlow = Request.Query["expired"] == "true";
      if (!isExpiredFlow && lastChange != null && DateTime.UtcNow - lastChange.CreatedAt < minPasswordAge)
   {
       ModelState.AddModelError(string.Empty, $"You cannot change password yet. Please wait {minPasswordAge.TotalMinutes:F0} minutes between password changes.");
return Page();
     }

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

    var result = await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
  if (!result.Succeeded)
            {
  foreach (var e in result.Errors) ModelState.AddModelError(string.Empty, e.Description);
   return Page();
            }

   // Store the OLD password (captured before change) in history
       // This way history contains previous passwords that should be blocked
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
  EventType = "PasswordChanged",
    UserId = user.Id,
     IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
      UserAgent = Request.Headers["User-Agent"].ToString(),
         Timestamp = DateTime.UtcNow
  });

         await _db.SaveChangesAsync();

    await _signInManager.RefreshSignInAsync(user);

            TempData["SuccessMessage"] = "Your password has been changed successfully.";
    return RedirectToPage("/Index");
   }
    }
}
