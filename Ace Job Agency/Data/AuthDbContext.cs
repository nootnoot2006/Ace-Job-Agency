using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Ace_Job_Agency.Models;

namespace Ace_Job_Agency.Data
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }

        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<ActiveSession> ActiveSessions { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }
        public DbSet<TwoFactorCode> TwoFactorCodes { get; set; }
    }
}
