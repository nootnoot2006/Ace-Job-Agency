using Ace_Job_Agency.Models;
using Ace_Job_Agency.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Ace_Job_Agency.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            // Capture these BEFORE sign-out so they are available
            string? userId = _userManager.GetUserId(User);
            string? sessionGuid = HttpContext.Session.GetString("SessionGuid");

            // Remove the ActiveSession row for this session
            bool removed = false;
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(sessionGuid))
            {
                var session = await _db.ActiveSessions
                    .FirstOrDefaultAsync(s => s.UserId == userId && s.SessionTokenHash == sessionGuid);
                if (session != null)
                {
                    _db.ActiveSessions.Remove(session);
                    removed = true;
                }
            }

            // Fallback: if we couldn't match by SessionGuid, remove ALL sessions for this user
            if (!removed && !string.IsNullOrEmpty(userId))
            {
                var sessions = await _db.ActiveSessions.Where(s => s.UserId == userId).ToListAsync();
                if (sessions.Count > 0)
                {
                    _db.ActiveSessions.RemoveRange(sessions);
                }
            }

            // Log audit
            _db.AuditLogs.Add(new AuditLog
            {
                EventType = "Logout",
                UserId = userId,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow,
                Details = removed ? $"Removed session {sessionGuid}" : "Removed all sessions (fallback)"
            });

            await _db.SaveChangesAsync();

            // Sign out and clear session
            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();

            return RedirectToPage("Login");
        }

        public IActionResult OnPostDontLogout()
        {
            return RedirectToPage("Index");
        }
    }
}
