using System.ComponentModel.DataAnnotations;

namespace Ace_Job_Agency.Models
{
 public class ActiveSession
 {
 public int Id { get; set; }
 [Required]
 public string UserId { get; set; }
 [Required]
 public string SessionTokenHash { get; set; }
 public string? UserAgent { get; set; }
 public string? IpAddress { get; set; }
 public DateTime ExpiresAt { get; set; }
 }
}
