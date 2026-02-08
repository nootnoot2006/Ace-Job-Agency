namespace Ace_Job_Agency.Middleware
{
    /// <summary>
    /// Holds individual policy mode toggles (test vs production) for each policy type.
    /// </summary>
    public record PolicyModeConfig(
        bool SessionTimeout_UseTestMode,
        bool Lockout_UseTestMode,
        bool MinPasswordAge_UseTestMode,
        bool MaxPasswordAge_UseTestMode
    );
}
