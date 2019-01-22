using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace PersonalPhotos.Models
{
    public class ChangePasswordViewModel
    {
        [Required]
        public string EmailAddress  { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Passsword { get; set; }
        [Required]
        public string Token { get; set; }
    }
}
