using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Ace_Job_Agency.Pages.Account
{
    [Authorize]
    public class SessionsModel : PageModel
    {
        private readonly AuthDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        public List<SessionView> Sessions { get; set; } = new List<SessionView>();

        public SessionsModel(AuthDbContext db, UserManager<ApplicationUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var sessions = await _db.ActiveSessions.Where(s => s.UserId == user.Id).ToListAsync();

            var tz = GetSingaporeTimeZone();
            Sessions = sessions.Select(s => new SessionView
            {
                Id = s.Id,
                UserId = s.UserId,
                UserAgent = s.UserAgent,
                IpAddress = s.IpAddress,
                ExpiresAtUtc = s.ExpiresAt,
                ExpiresAtLocal = TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(s.ExpiresAt, DateTimeKind.Utc), tz)
            }).ToList();

            return Page();
        }

        public async Task<IActionResult> OnPostRevokeAsync(int id)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();
            var session = await _db.ActiveSessions.FirstOrDefaultAsync(s => s.Id == id && s.UserId == user.Id);
            if (session != null)
            {
                _db.ActiveSessions.Remove(session);
                _db.AuditLogs.Add(new AuditLog { 
                    EventType = "SessionRevoked", 
                    UserId = user.Id, 
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(), 
                    UserAgent = HttpContext.Request.Headers["User-Agent"].ToString(), 
                    Timestamp = DateTime.UtcNow, 
                    Details = $"Revoked session {id}" });
                await _db.SaveChangesAsync();
            }
            return RedirectToPage();
        }

        private static TimeZoneInfo GetSingaporeTimeZone()
        {
            // Windows uses 'Singapore Standard Time', Linux/macOS/containers may use 'Asia/Singapore'
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById("Singapore Standard Time");
            }
            catch (TimeZoneNotFoundException)
            {
                return TimeZoneInfo.FindSystemTimeZoneById("Asia/Singapore");
            }
            catch (InvalidTimeZoneException)
            {
                // last resort: fallback to UTC
                return TimeZoneInfo.Utc;
            }
        }

        // View model for sessions with local time
        public class SessionView
        {
            public int Id { get; set; }
            public string UserId { get; set; } = string.Empty;
            public string? UserAgent { get; set; }
            public string? IpAddress { get; set; }
            public DateTime ExpiresAtUtc { get; set; }
            public DateTime ExpiresAtLocal { get; set; }
        }
    }
}
