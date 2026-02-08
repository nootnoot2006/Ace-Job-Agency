using System.ComponentModel.DataAnnotations;

namespace Ace_Job_Agency.Models
{
 public class TwoFactorCode
 {
 public int Id { get; set; }
 [Required]
 public string UserId { get; set; }
 [Required]
 public string CodeHash { get; set; }
 public DateTime ExpiresAt { get; set; }
 public int Attempts { get; set; }
 }
}
