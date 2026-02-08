using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Ace_Job_Agency.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [PersonalData]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [PersonalData]
        public string LastName { get; set; } = string.Empty;

        [PersonalData]
        public string? Gender { get; set; }

        [Required]
        [PersonalData]
        public string NRICEncrypted { get; set; } = string.Empty;

        [PersonalData]
        public DateTime? DateOfBirth { get; set; }

        [PersonalData]
        public string? ResumePath { get; set; }

        [PersonalData]
        public string? WhoAmI { get; set; }

        // Two-factor enabled flag (email OTP)
        [PersonalData]
        public bool TwoFactorEnabled { get; set; } = false;

        // Track when password was last changed (for maximum password age policy)
        public DateTime? LastPasswordChangedAt { get; set; }
    }
}
