using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace OtopakSistemi.Models
{


    public class parkyeribulmaViewModel
    {
        public List<Park_Yeri> listp = new List<Park_Yeri>();
        public List<Park_Yeri> listppp = new List<Park_Yeri>();
        public int PID { get; set; }
    }


    public class parkyerieklemeViewModel
    {
        public string durumu { get; set; }
        public int park_ıd { get; set; }

        [Required]
        [Display(Name = "A Kapısına Uzaklığı")]
        public int a_kapısı { get; set; }
        [Required]
        [Display(Name = "B Kapısına Uzaklığı")]
        public int b_kapısı { get; set; }
        [Required]
        [Display(Name = "Hangi Katta")]
        public int katıd { get; set; }


    }
    public class kateklemeViewModel
    {
        [Required]
        [Display(Name = "Kat NO")]
        public int Kat_NO { get; set; }

        public int Kat_ID { get; set; }

        public string kategeri { get; set; }

    }


    public class kategorieklemeViewModel
    {
        [Required]
        [Display(Name = "Kategori:")]
        public string kategeri { get; set; }
        [Required]
        [Display(Name = "Kat NO")]
        public int Kat_ID { get; set; }

    }










        public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }

    public class ExternalLoginListViewModel
    {
        public string ReturnUrl { get; set; }
    }

    public class SendCodeViewModel
    {
        public string SelectedProvider { get; set; }
        public ICollection<System.Web.Mvc.SelectListItem> Providers { get; set; }
        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }

    public class VerifyCodeViewModel
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }

        [Display(Name = "Remember this browser?")]
        public bool RememberBrowser { get; set; }

        public bool RememberMe { get; set; }
    }

    public class ForgotViewModel
    {
        [Required]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }

    public class LoginViewModel
    {
        [Required]
        [Display(Name = "Email")]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public int Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public class RegisterViewModel
    {
        [Required]
        [Display(Name = "AD")]
        public string ad{ get; set; }

        [Required]
        [Display(Name = "Soyad")]
        public string soyad { get; set; }

        [Required]
        [Display(Name = "Telefon")]
        public int telefon{ get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [Display(Name = "Araç Plakası")]
        public string plaka { get; set; }

        [Required]
        [Display(Name = "Şifre")]
        public int Sifre{ get; set; }


    }

    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }

    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}
