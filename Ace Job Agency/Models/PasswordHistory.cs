using System.ComponentModel.DataAnnotations;

namespace Ace_Job_Agency.Models
{
 public class PasswordHistory
 {
 public int Id { get; set; }
 [Required]
 public string UserId { get; set; }
 [Required]
 public string PasswordHash { get; set; }
 public DateTime CreatedAt { get; set; }
 }
}
