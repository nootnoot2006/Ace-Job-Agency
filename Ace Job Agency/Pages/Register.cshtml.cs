using Ace_Job_Agency.ViewModels;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.DataProtection;
using Ace_Job_Agency.Data;
using System.Net;
using Ace_Job_Agency.Middleware;

namespace Ace_Job_Agency.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IWebHostEnvironment environment;
        private readonly IDataProtector protector;
        private readonly AuthDbContext _db;
        private readonly SessionTimeoutConfig _timeoutCfg;

        [BindProperty]
        public Register RModel { get; set; } = new Register();

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IWebHostEnvironment environment,
            IDataProtectionProvider dataProtectionProvider,
            AuthDbContext db,
            SessionTimeoutConfig timeoutCfg)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.environment = environment;
            this.protector = dataProtectionProvider.CreateProtector("NRICProtector");
            this._db = db;
            this._timeoutCfg = timeoutCfg;
        }

        public void OnGet() { }

        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // server-side extra validation: date not in future
            if (RModel.DateOfBirth > DateTime.UtcNow.Date)
            {
                ModelState.AddModelError(nameof(RModel.DateOfBirth), "Date of birth cannot be in the future.");
                return Page();
            }

            // normalize and trim inputs
            RModel.Email = RModel.Email?.Trim();
            RModel.FirstName = RModel.FirstName?.Trim();
            RModel.LastName = RModel.LastName?.Trim();
            RModel.WhoAmI = RModel.WhoAmI?.Trim();

            // Check for duplicate email and rectify issue.
            var existingUser = await userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError(string.Empty, "This email is already registered. Please use a different email.");
                return Page();
            }

            // Validate resume file
            string? resumePath = null;
            if (RModel.Resume != null)
            {
                var allowedExtensions = new[] { ".pdf", ".docx", ".jpg", ".jpeg" };
                var allowedContentTypes = new[] { "application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/jpeg" };
                var extension = Path.GetExtension(RModel.Resume.FileName).ToLowerInvariant();
                
                if (!allowedExtensions.Contains(extension) || !allowedContentTypes.Contains(RModel.Resume.ContentType))
                {
                    ModelState.AddModelError("RModel.Resume", "Only .pdf, .docx, or .jpg files are allowed.");
                    return Page();
                }

                if (RModel.Resume.Length > 2 * 1024 * 1024)
                {
                    ModelState.AddModelError("RModel.Resume", "Resume too large (max 2 MB)");
                    return Page();
                }

                // Save resume file
                var uploadsFolder = Path.Combine(environment.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot"), "uploads", "resumes");
                if (!Directory.Exists(uploadsFolder))
                {
                    Directory.CreateDirectory(uploadsFolder);
                }

                var uniqueFileName = Guid.NewGuid().ToString() + extension;
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await RModel.Resume.CopyToAsync(fileStream);
                }

                resumePath = $"/uploads/resumes/{uniqueFileName}";
            }

            // Protect NRIC with DataProtector
            var protectedNRIC = protector.Protect(RModel.NRIC);

            // HTML-encode fields before saving to DB to avoid stored XSS
            var encodedFirstName = WebUtility.HtmlEncode(RModel.FirstName);
            var encodedLastName = WebUtility.HtmlEncode(RModel.LastName);
            var encodedWhoAmI = WebUtility.HtmlEncode(RModel.WhoAmI);

            // Create ApplicationUser
            var user = new ApplicationUser
            {
                UserName = RModel.Email,
                Email = RModel.Email,
                FirstName = encodedFirstName,
                LastName = encodedLastName,
                Gender = RModel.Gender,
                NRICEncrypted = protectedNRIC,
                DateOfBirth = RModel.DateOfBirth,
                ResumePath = resumePath,
                WhoAmI = encodedWhoAmI,
                LastPasswordChangedAt = DateTime.UtcNow // Set initial password date
            };

            // Create user with password
            var result = await userManager.CreateAsync(user, RModel.Password);
            
            if (result.Succeeded)
            {
                // Create Member role if it doesn't exist
                var roleExists = await roleManager.RoleExistsAsync("Member");
                if (!roleExists)
                {
                    await roleManager.CreateAsync(new IdentityRole("Member"));
                }

                // Assign user to Member role
                await userManager.AddToRoleAsync(user, "Member");

                _db.AuditLogs.Add(new AuditLog { 
                    EventType = "Register", 
                    UserId = user.Id, 
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), 
                    UserAgent = Request.Headers["User-Agent"].ToString(), 
                    Timestamp = DateTime.UtcNow });
                await _db.SaveChangesAsync();

                // Enforce single session for the new user (defensive) and create the active session
                var existingSessions = _db.ActiveSessions.Where(s => s.UserId == user.Id);
                _db.ActiveSessions.RemoveRange(existingSessions);

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
                    Details = "Auto-login after registration"
                });
                await _db.SaveChangesAsync();

                HttpContext.Session.SetString("SessionGuid", sessionGuid);
                await signInManager.SignInAsync(user, isPersistent: false);

                return RedirectToPage("Index");
            }

            // Add errors to ModelState
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }
}