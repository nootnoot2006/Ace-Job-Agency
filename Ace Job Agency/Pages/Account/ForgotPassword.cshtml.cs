using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Ace_Job_Agency.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.Net;

namespace Ace_Job_Agency.Pages.Account
{
 public class ForgotPasswordModel : PageModel
 {
 private readonly UserManager<ApplicationUser> _userManager;
 private readonly IEmailSender _emailSender;
 private readonly AuthDbContext _db;

 public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender, AuthDbContext db)
 {
 _userManager = userManager;
 _emailSender = emailSender;
 _db = db;
 }

 [BindProperty]
 public InputModel Input { get; set; }
 public class InputModel
 {
 [Required]
 [EmailAddress]
 public string Email { get; set; }
 }

 public void OnGet() { }

 public async Task<IActionResult> OnPostAsync()
 {
 if (!ModelState.IsValid) return Page();
 var user = await _userManager.FindByEmailAsync(Input.Email);
 if (user == null) return RedirectToPage("/Account/ForgotPasswordConfirmation");

 var token = await _userManager.GeneratePasswordResetTokenAsync(user);
 var encodedToken = WebUtility.UrlEncode(token);
 var resetLink = Url.Page("/Account/ResetPassword", null, new { token = encodedToken }, Request.Scheme);
 await _emailSender.SendEmailAsync(user.Email, "Reset Password", $"Click here to reset your password: {resetLink}");

 // audit log may record password reset request without PII
 _db.AuditLogs.Add(new AuditLog { EventType = "PasswordResetRequested", UserId = user.Id, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), UserAgent = Request.Headers["User-Agent"].ToString(), Timestamp = DateTime.UtcNow });
 await _db.SaveChangesAsync();

 return RedirectToPage("/Account/ForgotPasswordConfirmation");
 }
 }
}
