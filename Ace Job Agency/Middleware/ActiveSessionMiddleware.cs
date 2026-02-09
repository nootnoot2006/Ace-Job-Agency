using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Ace_Job_Agency.Middleware
{
    /// <summary>
    /// Simple session validation middleware.
    ///
    /// On login, a GUID ("SessionGuid") is stored in:
    /// 1. The ASP.NET server-side session
    /// 2. The ActiveSessions DB table (with UserId and ExpiresAt)
    ///
    /// This middleware checks every authenticated request:
    /// - Reads SessionGuid from server session
    /// - Looks it up in ActiveSessions for the current user
    /// - If missing or expired ? sign out + redirect to /Login
    /// - If valid ? slide the expiry forward
    ///
    /// No custom headers, no custom cookies, no per-tab JS needed.
    /// </summary>
    public class ActiveSessionMiddleware
    {
        private readonly RequestDelegate _next;

        private static readonly HashSet<string> SkipPaths = new(StringComparer.OrdinalIgnoreCase)
 {
 "/Login", "/Register", "/Logout", "/Error",
 "/Account/ForgotPassword", "/Account/ResetPassword",
 "/Account/AccessDenied", "/Account/TwoFactorVerify"
 };

        public ActiveSessionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;

            if (ShouldSkip(path))
            {
                await _next(context);
                return;
            }

            if (context.User?.Identity?.IsAuthenticated != true)
            {
                await _next(context);
                return;
            }

            var db = context.RequestServices.GetRequiredService<AuthDbContext>();
            var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
            var timeoutCfg = context.RequestServices.GetRequiredService<SessionTimeoutConfig>();

            var user = await userManager.GetUserAsync(context.User);
            if (user == null)
            {
                await SignOutAndRedirect(context, "InvalidSession");
                return;
            }

            // Token stored in ASP.NET session at login/registration
            var sessionGuid = context.Session.GetString("SessionGuid");

            // If the ASP.NET Session itself has expired, sessionGuid will be null.
            // In that case, remove all ActiveSessions for this user and log the timeout.
            if (string.IsNullOrEmpty(sessionGuid))
            {
                var userSessions = await db.ActiveSessions.Where(s => s.UserId == user.Id).ToListAsync();
                if (userSessions.Count > 0)
                {
                    db.ActiveSessions.RemoveRange(userSessions);
                }

                db.AuditLogs.Add(new AuditLog
                {
                    EventType = "SessionTimeout",
                    UserId = user.Id,
                    IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = context.Request.Headers["User-Agent"].ToString(),
                    Timestamp = DateTime.UtcNow,
                    Details = "ASP.NET Session expired (SessionGuid missing)"
                });
                try { await db.SaveChangesAsync(); } catch { }

                await SignOutAndRedirect(context, "SessionExpired");
                return;
            }

            var activeSession = await db.ActiveSessions
            .FirstOrDefaultAsync(s => s.UserId == user.Id && s.SessionTokenHash == sessionGuid);

            if (activeSession == null)
            {
                db.AuditLogs.Add(new AuditLog
                {
                    EventType = "SessionInvalidated",
                    UserId = user.Id,
                    IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = context.Request.Headers["User-Agent"].ToString(),
                    Timestamp = DateTime.UtcNow,
                    Details = "ActiveSession not found — likely replaced by another login"
                });
                try { await db.SaveChangesAsync(); } catch { }

                await SignOutAndRedirect(context, "InvalidSession");
                return;
            }

            if (activeSession.ExpiresAt < DateTime.UtcNow)
            {
                db.ActiveSessions.Remove(activeSession);
                db.AuditLogs.Add(new AuditLog
                {
                    EventType = "SessionTimeout",
                    UserId = user.Id,
                    IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = context.Request.Headers["User-Agent"].ToString(),
                    Timestamp = DateTime.UtcNow,
                    Details = "ActiveSession.ExpiresAt exceeded"
                });
                try { await db.SaveChangesAsync(); } catch { }

                await SignOutAndRedirect(context, "SessionExpired");
                return;
            }

            // Slide expiry using the globally configured timeout
            activeSession.ExpiresAt = DateTime.UtcNow.Add(timeoutCfg.Timeout);
            try { await db.SaveChangesAsync(); } catch { }

            await _next(context);
        }

        private static bool ShouldSkip(string path)
        {
            if (SkipPaths.Contains(path)) return true;

            if (path.StartsWith("/errors", StringComparison.OrdinalIgnoreCase)) return true;
            if (path.StartsWith("/Auth/", StringComparison.OrdinalIgnoreCase)) return true;

            if (path.StartsWith("/lib/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/css/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/js/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/images/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/_framework/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/_content/", StringComparison.OrdinalIgnoreCase))
                return true;

            var ext = Path.GetExtension(path);
            if (!string.IsNullOrEmpty(ext))
            {
                var staticExts = new[] { ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".ico", ".png", ".jpg", ".svg" };
                if (staticExts.Contains(ext, StringComparer.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static async Task SignOutAndRedirect(HttpContext context, string reason)
        {
            try { await context.SignOutAsync(IdentityConstants.ApplicationScheme); } catch { }
            try { context.Session.Clear(); } catch { }
            context.Response.Redirect("/Login?reason=" + Uri.EscapeDataString(reason));
        }
    }
}
