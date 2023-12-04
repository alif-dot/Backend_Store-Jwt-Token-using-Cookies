using System.ComponentModel.DataAnnotations;

namespace JWTAppYT.Models
{
    public class User
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Role { get; set; }
        [Required]
        public string BirthDay { get; set; }
        [Required]
        public byte[] PasswordSalt { get; set; }
        [Required]
        public byte[] PasswordHash { get; set; }

        public string Token { get; set; }
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}
