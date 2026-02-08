namespace Ace_Job_Agency.Middleware
{
 /// <summary>
 /// Simple record that holds the configured session timeout.
 /// Registered as a singleton in Program.cs so Login, Register,
 /// and ActiveSessionMiddleware all use the same value.
 /// </summary>
 public record SessionTimeoutConfig(TimeSpan Timeout);
}
