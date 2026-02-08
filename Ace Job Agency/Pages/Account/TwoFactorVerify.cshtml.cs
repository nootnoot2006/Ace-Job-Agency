using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Ace_Job_Agency.Services;
using Ace_Job_Agency.Middleware;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace Ace_Job_Agency.Pages.Account
{
    public class TwoFactorVerifyModel : PageModel
    {
 private readonly AuthDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly SessionTimeoutConfig _timeoutCfg;

      public TwoFactorVerifyModel(AuthDbContext db, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEmailSender emailSender, SessionTimeoutConfig timeoutCfg)
        {
      _db = db;
       _userManager = userManager;
       _signInManager = signInManager;
    _emailSender = emailSender;
  _timeoutCfg = timeoutCfg;
        }

  [BindProperty]
   public InputModel Input { get; set; }
        
        public class InputModel
        {
            [Required]
  public string Code { get; set; }
        }

  public IActionResult OnGet()
    {
            // Check if we have a pending 2FA user
   var userId = HttpContext.Session.GetString("2fa_pending_user");
            if (string.IsNullOrEmpty(userId))
            {
return RedirectToPage("/Login");
     }
            return Page();
      }

        public async Task<IActionResult> OnPostAsync()
        {
      if (!ModelState.IsValid) return Page();

         // Get user ID from session (not TempData)
     var userId = HttpContext.Session.GetString("2fa_pending_user");
            if (string.IsNullOrEmpty(userId))
            {
     ModelState.AddModelError(string.Empty, "Session expired. Please log in again.");
      return Page();
    }

         var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
            {
      HttpContext.Session.Remove("2fa_pending_user");
return RedirectToPage("/Login");
            }

    var now = DateTime.UtcNow;
            var record = await _db.TwoFactorCodes
   .Where(t => t.UserId == user.Id && t.ExpiresAt > now)
      .OrderByDescending(t => t.ExpiresAt)
        .FirstOrDefaultAsync();

      if (record == null)
    {
             ModelState.AddModelError(string.Empty, "No valid 2FA code was found. Please log in again.");
         return Page();
         }

            using var sha = System.Security.Cryptography.SHA256.Create();
var codeHash = Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Input.Code)));
            
        if (codeHash != record.CodeHash)
     {
                record.Attempts++;
         await _db.SaveChangesAsync();

       if (record.Attempts >= 3)
                {
        _db.TwoFactorCodes.Remove(record);
    await _db.SaveChangesAsync();
       HttpContext.Session.Remove("2fa_pending_user");
      ModelState.AddModelError(string.Empty, "Too many failed attempts. Please log in again.");
     return Page();
                }

          ModelState.AddModelError(string.Empty, $"Invalid code. {3 - record.Attempts} attempts remaining.");
   return Page();
     }

    // Success - remove the code and pending user session
            _db.TwoFactorCodes.Remove(record);
         HttpContext.Session.Remove("2fa_pending_user");

       // Create ActiveSession and sign in
            var sessionGuid = Guid.NewGuid().ToString();

            _db.ActiveSessions.Add(new ActiveSession
{
             UserId = user.Id,
                SessionTokenHash = sessionGuid,
                UserAgent = Request.Headers["User-Agent"].ToString(),
        IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                ExpiresAt = DateTime.UtcNow.Add(_timeoutCfg.Timeout)
     });

            _db.AuditLogs.Add(new AuditLog
    {
          EventType = "LoginSuccess",
                UserId = user.Id,
          IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
 Timestamp = DateTime.UtcNow,
    Details = "2FA verification successful"
       });

      await _db.SaveChangesAsync();

       HttpContext.Session.SetString("SessionGuid", sessionGuid);

            await _signInManager.SignInAsync(user, isPersistent: false);

          return RedirectToPage("/Index");
        }
    }
}
