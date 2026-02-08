using Ace_Job_Agency.ViewModels;
using Ace_Job_Agency.Models;
using Ace_Job_Agency.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using Ace_Job_Agency.Services;
using Ace_Job_Agency.Middleware;

namespace Ace_Job_Agency.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Login LModel { get; set; } = new Login();

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly AuthDbContext _db;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;
        private readonly SessionTimeoutConfig _timeoutCfg;
        private readonly PolicyModeConfig _policyMode;

        public string? Message { get; set; }

        // For password expired flow
        public bool PasswordExpired { get; set; }
        public string? ExpiredUserId { get; set; }

        // Confirmation flow (kept for UI compatibility; now not required)
        public bool ConfirmRequired { get; set; }
        public int ExistingSessionCount { get; set; }
        public string? PendingLoginToken { get; set; }
        public string? PendingUserId { get; set; }
        public string? PendingTabId { get; set; }

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            IEmailSender emailSender,
            SessionTimeoutConfig timeoutCfg,
            PolicyModeConfig policyMode)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this._db = db;
            this._httpClientFactory = httpClientFactory;
            this._configuration = configuration;
            this._emailSender = emailSender;
            this._timeoutCfg = timeoutCfg;
            this._policyMode = policyMode;
        }

        public void OnGet(string? reason = null)
        {
            if (!string.IsNullOrEmpty(reason))
            {
                // map reason codes to friendly messages
                Message = reason switch
                {
                    "SessionExpired" => "Your session has expired. Please log in again.",
                    "InvalidSession" => "You were signed out because you signed in somewhere else. Please log in again.",
                    "NoSessionToken" => "No active session was found. Please log in.",
                    "PasswordExpired" => "Your password has expired. Please change it to continue.",
                    _ => "Please log in."
                };
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Legacy confirmation flow (kept so existing markup doesn't break)
            if (Request.Form["confirm"] == "true")
            {
                return await HandleConfirmReplace();
            }

            if (!ModelState.IsValid)
                return Page();

            // Validate reCAPTCHA v3
            var captchaValid = await ValidateCaptchaAsync();
            if (!captchaValid)
            {
                ModelState.AddModelError(string.Empty, "Captcha validation failed. Please try again.");
                _db.AuditLogs.Add(new AuditLog { EventType = "CaptchaFail", UserId = null, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), UserAgent = Request.Headers["User-Agent"].ToString(), Timestamp = DateTime.UtcNow });
                await _db.SaveChangesAsync();
                return Page();
            }

            var foundUser = await userManager.FindByEmailAsync(LModel.Email);
            if (foundUser == null)
            {
                ModelState.AddModelError("", "Username or Password incorrect");
                _db.AuditLogs.Add(new AuditLog { EventType = "LoginFail", UserId = null, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), UserAgent = Request.Headers["User-Agent"].ToString(), Timestamp = DateTime.UtcNow });
                await _db.SaveChangesAsync();
                return Page();
            }

            // Check lockout
            if (await userManager.IsLockedOutAsync(foundUser))
            {
                ModelState.AddModelError("", "Account locked. Try again later.");
                return Page();
            }

            var result = await signInManager.CheckPasswordSignInAsync(foundUser, LModel.Password, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                // Check maximum password age based on individual policy toggle
                TimeSpan maxPasswordAge;
                if (_policyMode.MaxPasswordAge_UseTestMode)
                {
                    var maxAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MaxAge_TestMinutes", 2);
                    maxPasswordAge = TimeSpan.FromMinutes(maxAgeMinutes);
                }
                else
                {
                    var maxAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaxAge_ProductionDays", 90);
                    maxPasswordAge = TimeSpan.FromDays(maxAgeDays);
                }

                if (foundUser.LastPasswordChangedAt.HasValue)
                {
                    var passwordAge = DateTime.UtcNow - foundUser.LastPasswordChangedAt.Value;
                    if (passwordAge > maxPasswordAge)
                    {
                        _db.AuditLogs.Add(new AuditLog
                        {
                            EventType = "PasswordExpired",
                            UserId = foundUser.Id,
                            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                            UserAgent = Request.Headers["User-Agent"].ToString(),
                            Timestamp = DateTime.UtcNow,
                            Details = $"Password age: {passwordAge.TotalMinutes:F1} min (max: {maxPasswordAge.TotalMinutes:F1} min)"
                        });
                        await _db.SaveChangesAsync();

                        // Sign in temporarily to allow password change
                        await ReplaceExistingSessions(foundUser.Id);
                        await CreateSessionAndSignIn(foundUser, false);

                        return RedirectToPage("/Manage/ChangePassword", new { expired = true });
                    }
                }

                // ????????????????????????????????????????????????????????????????
                // 2FA CHECK - If user has 2FA enabled, send code and redirect
                // ????????????????????????????????????????????????????????????????
                if (foundUser.TwoFactorEnabled)
                {
                    // Generate a 6-digit code
                    var code = new Random().Next(100000, 999999).ToString();

                    // Hash the code for storage
                    using var sha = System.Security.Cryptography.SHA256.Create();
                    var codeHash = Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(code)));

                    // Remove any existing codes for this user
                    var existingCodes = await _db.TwoFactorCodes.Where(t => t.UserId == foundUser.Id).ToListAsync();
                    _db.TwoFactorCodes.RemoveRange(existingCodes);

                    // Store new code (expires in 5 minutes)
                    _db.TwoFactorCodes.Add(new TwoFactorCode
                    {
                        UserId = foundUser.Id,
                        CodeHash = codeHash,
                        ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                        Attempts = 0
                    });

                    _db.AuditLogs.Add(new AuditLog
                    {
                        EventType = "TwoFactorCodeSent",
                        UserId = foundUser.Id,
                        IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                        UserAgent = Request.Headers["User-Agent"].ToString(),
                        Timestamp = DateTime.UtcNow
                    });

                    await _db.SaveChangesAsync();

                    // Send code via email
                    await _emailSender.SendEmailAsync(
                        foundUser.Email!,
                        "Your Login Verification Code",
                        $@"<h2>Two-Factor Authentication</h2>
                         <p>Your verification code is:</p>
                      <h1 style='font-size: 2rem; letter-spacing: 0.5rem; color: #6366f1;'>{code}</h1>
                        <p>This code expires in 5 minutes.</p>
                              <p>If you didn't request this, please ignore this email.</p>"
                    );

                    // Store user ID in Session (not TempData) for the verification page
                    HttpContext.Session.SetString("2fa_pending_user", foundUser.Id);

                    return RedirectToPage("/Account/TwoFactorVerify");
                }

                // No 2FA - proceed with normal login
                await ReplaceExistingSessions(foundUser.Id);
                await CreateSessionAndSignIn(foundUser, LModel.RememberMe);
                return RedirectToPage("Index");
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Account locked due to multiple failed login attempts.");
            }
            else
            {
                ModelState.AddModelError("", "Username or Password incorrect");
                _db.AuditLogs.Add(new AuditLog { EventType = "LoginFail", UserId = foundUser.Id, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), UserAgent = Request.Headers["User-Agent"].ToString(), Timestamp = DateTime.UtcNow });
                await _db.SaveChangesAsync();
            }
            return Page();
        }

        private async Task ReplaceExistingSessions(string userId)
        {
            var existing = await _db.ActiveSessions.Where(s => s.UserId == userId).ToListAsync();
            if (!existing.Any()) return;

            _db.ActiveSessions.RemoveRange(existing);
            _db.AuditLogs.Add(new AuditLog
            {
                EventType = "SessionReplaced",
                UserId = userId,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow,
                Details = $"Replaced {existing.Count} existing session(s)"
            });
            await _db.SaveChangesAsync();
        }

        private async Task<IActionResult> HandleConfirmReplace()
        {
            var postedToken = Request.Form["pendingLoginToken"].FirstOrDefault();
            var pendingToken = HttpContext.Session.GetString("pendingLoginToken");
            if (string.IsNullOrEmpty(postedToken) || string.IsNullOrEmpty(pendingToken) || postedToken != pendingToken)
            {
                ModelState.AddModelError(string.Empty, "Confirmation expired or invalid. Please sign in again.");
                HttpContext.Session.Remove("pendingLoginToken");
                HttpContext.Session.Remove("pendingUserId");
                return Page();
            }

            var userId = HttpContext.Session.GetString("pendingUserId");
            var remember = (Request.Form["remember"] == "true") || (Request.Form["remember"] == "on");

            var targetUser = await userManager.FindByIdAsync(userId ?? "");
            if (targetUser == null)
            {
                ModelState.AddModelError(string.Empty, "User not found. Please sign in again.");
                return Page();
            }

            await ReplaceExistingSessions(targetUser.Id);

            HttpContext.Session.Remove("pendingLoginToken");
            HttpContext.Session.Remove("pendingUserId");

            await CreateSessionAndSignIn(targetUser, remember);
            return RedirectToPage("Index");
        }

        private async Task CreateSessionAndSignIn(ApplicationUser user, bool rememberMe)
        {
            // New per-login identifier shared between:
            // - ASP.NET Session ("SessionGuid")
            // - ActiveSessions table (SessionTokenHash)
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
                Timestamp = DateTime.UtcNow
            });

            await _db.SaveChangesAsync();

            HttpContext.Session.SetString("SessionGuid", sessionGuid);

            await signInManager.SignInAsync(user, rememberMe);
        }

        private async Task<bool> ValidateCaptchaAsync()
        {
            try
            {
                var form = await Request.ReadFormAsync();
                var captchaResponse = form["g-recaptcha-response"].FirstOrDefault() ?? form["token"].FirstOrDefault();
                if (string.IsNullOrEmpty(captchaResponse))
                    return false;

                var secret = _configuration["ReCaptcha:SecretKey"];
                if (string.IsNullOrEmpty(secret))
                    return false;

                var client = _httpClientFactory.CreateClient();
                var values = new List<KeyValuePair<string, string>>
                {
                    new("secret", secret),
                    new("response", captchaResponse),
                    new("remoteip", HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty)
                };
                var content = new FormUrlEncodedContent(values);
                var resp = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
                if (!resp.IsSuccessStatusCode)
                    return false;

                var json = await resp.Content.ReadAsStringAsync();
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var result = JsonSerializer.Deserialize<RecaptchaVerifyResponse>(json, options);
                if (result == null) return false;

                var minScore = 0.5;
                if (double.TryParse(_configuration["ReCaptcha:MinScore"], out var configured))
                    minScore = configured;

                if (!result.Success) return false;
                if (result.Score.HasValue && result.Score.Value < minScore) return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private class RecaptchaVerifyResponse
        {
            public bool Success { get; set; }
            public double? Score { get; set; }
            public string? Action { get; set; }
            public DateTime? Challenge_ts { get; set; }
            public string? Hostname { get; set; }
            public List<string>? Error_codes { get; set; }
        }
    }

    public class MyObject
    {
        public string success { get; set; }
        public List<string> ErrorMessage { get; set; }
    }
}
