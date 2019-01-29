using System.ComponentModel.DataAnnotations;

namespace PersonalPhotos.Models
{
    public class MfaCreateViewModel
    {
        public string AuthKey { get; set; }

        [Required(ErrorMessage="You must enter a code for MFA!")]
        public string Code { get; set; }
    }
}