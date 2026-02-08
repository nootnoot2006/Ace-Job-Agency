using Ace_Job_Agency.Data;
using Ace_Job_Agency.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;
using System.IO;
using Ace_Job_Agency.Middleware;
using Ace_Job_Agency.Services;

var builder = WebApplication.CreateBuilder(args);

// ??????????????????????????????????????????????????????????????????????????????
// POLICY MODE CONFIGURATION
// ??????????????????????????????????????????????????????????????????????????????
// Each policy can be toggled individually in appsettings.json under "PolicyMode":
 //   - SessionTimeout_UseTestMode
 //   - Lockout_UseTestMode
 //   - MinPasswordAge_UseTestMode
 //   - MaxPasswordAge_UseTestMode
// ??????????????????????????????????????????????????????????????????????????????

var sessionTimeoutTestMode = builder.Configuration.GetValue<bool>("PolicyMode:SessionTimeout_UseTestMode");
var lockoutTestMode = builder.Configuration.GetValue<bool>("PolicyMode:Lockout_UseTestMode");
var minPasswordAgeTestMode = builder.Configuration.GetValue<bool>("PolicyMode:MinPasswordAge_UseTestMode");
var maxPasswordAgeTestMode = builder.Configuration.GetValue<bool>("PolicyMode:MaxPasswordAge_UseTestMode");

// ??????????????????????????????????????????????????????????????????????????????
// SESSION TIMEOUT
// ??????????????????????????????????????????????????????????????????????????????
TimeSpan sessionTimeout;
if (sessionTimeoutTestMode)
{
    var seconds = builder.Configuration.GetValue<int>("SessionTimeout:TestSeconds", 10);
    sessionTimeout = TimeSpan.FromSeconds(seconds);
}
else
{
    var minutes = builder.Configuration.GetValue<int>("SessionTimeout:ProductionMinutes", 45);
    sessionTimeout = TimeSpan.FromMinutes(minutes);
}

// Identity cookie needs a slightly longer expiry so user is still "authenticated"
// when the ASP.NET Session expires, allowing middleware to clean up ActiveSessions.
var cookieTimeout = sessionTimeout.Add(TimeSpan.FromMinutes(5));

// ??????????????????????????????????????????????????????????????????????????????
// LOCKOUT POLICY
// ??????????????????????????????????????????????????????????????????????????????
var lockoutMaxAttempts = builder.Configuration.GetValue<int>("LockoutPolicy:MaxFailedAttempts", 3);
TimeSpan lockoutDuration;
if (lockoutTestMode)
{
    var minutes = builder.Configuration.GetValue<int>("LockoutPolicy:TestMinutes", 1);
    lockoutDuration = TimeSpan.FromMinutes(minutes);
}
else
{
    var minutes = builder.Configuration.GetValue<int>("LockoutPolicy:ProductionMinutes", 15);
    lockoutDuration = TimeSpan.FromMinutes(minutes);
}

// Add services to the container.
builder.Services.AddRazorPages();

// Add HttpClient factory (required for reCAPTCHA verification)
builder.Services.AddHttpClient();

// Configure DbContext with connection string
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

// Data Protection - persist keys to disk so protect/unprotect works across restarts
var keysFolder = Path.Combine(builder.Environment.ContentRootPath, "DataProtection-Keys");
if (!Directory.Exists(keysFolder)) Directory.CreateDirectory(keysFolder);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysFolder))
  .SetApplicationName("AceJobAgency");

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
 options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
  options.Password.RequiredLength = 12;
    options.User.RequireUniqueEmail = true;
    options.Lockout.MaxFailedAccessAttempts = lockoutMaxAttempts;
    options.Lockout.DefaultLockoutTimeSpan = lockoutDuration;
})
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Configure the Identity application cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.LogoutPath = "/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = cookieTimeout;
    options.SlidingExpiration = false;
    options.Events.OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync;
});

// Make SecurityStampValidator check more frequently (default is 30 min)
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromMinutes(1);
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("MustBelongToHRDepartment",
        policy => policy.RequireClaim("Department", "HR"));
});

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = sessionTimeout;
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
});

// register email sender
builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();

// Expose the session timeout so Login, Register, and Middleware can use it
builder.Services.AddSingleton(new SessionTimeoutConfig(sessionTimeout));

// Expose policy mode so pages can read test vs production settings
builder.Services.AddSingleton(new PolicyModeConfig(
    sessionTimeoutTestMode,
    lockoutTestMode,
    minPasswordAgeTestMode,
    maxPasswordAgeTestMode
));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Custom status code handling - only for 404 (Identity handles 401/403)
app.UseStatusCodePagesWithReExecute("/errors/{0}");

app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// Session validation middleware
app.UseMiddleware<ActiveSessionMiddleware>();

app.MapStaticAssets();
app.MapRazorPages()
    .WithStaticAssets();

app.Run();