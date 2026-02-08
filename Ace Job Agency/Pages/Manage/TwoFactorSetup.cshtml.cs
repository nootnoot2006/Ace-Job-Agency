using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Ace_Job_Agency.Pages.Manage
{
 [Authorize]
 public class TwoFactorSetupModel : PageModel
 {
 private readonly UserManager<ApplicationUser> _userManager;
 private readonly AuthDbContext _db;

 public TwoFactorSetupModel(UserManager<ApplicationUser> userManager, AuthDbContext db)
 {
 _userManager = userManager;
 _db = db;
 }

 public bool TwoFactorEnabled { get; set; }

 public async Task OnGetAsync()
 {
 var user = await _userManager.GetUserAsync(User);
 if (user != null) TwoFactorEnabled = user.TwoFactorEnabled;
 }

 public async Task<IActionResult> OnPostEnableAsync()
 {
 var user = await _userManager.GetUserAsync(User);
 if (user == null) return RedirectToPage("/Login");
 user.TwoFactorEnabled = true;
 await _userManager.UpdateAsync(user);
 _db.AuditLogs.Add(new AuditLog { EventType = "TwoFactorEnabled", UserId = user.Id, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), UserAgent = Request.Headers["User-Agent"].ToString(), Timestamp = DateTime.UtcNow });
 await _db.SaveChangesAsync();
 return RedirectToPage();
 }

 public async Task<IActionResult> OnPostDisableAsync()
 {
 var user = await _userManager.GetUserAsync(User);
 if (user == null) return RedirectToPage("/Login");
 user.TwoFactorEnabled = false;
 await _userManager.UpdateAsync(user);
 _db.AuditLogs.Add(new AuditLog { EventType = "TwoFactorDisabled", UserId = user.Id, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), UserAgent = Request.Headers["User-Agent"].ToString(), Timestamp = DateTime.UtcNow });
 await _db.SaveChangesAsync();
 return RedirectToPage();
 }
 }
}
