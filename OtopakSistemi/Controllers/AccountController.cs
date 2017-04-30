using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using OtopakSistemi.Models;
using System.Collections.Generic;


namespace OtopakSistemi.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;


        [AllowAnonymous]
        public ActionResult SecimSayfası()
        {
            
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult SecimSayfası(parkyeribulmaViewModel p )
        {


            return View();
        }

        [AllowAnonymous]
        public ActionResult Kategoriler()
        {

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Kategoriler(parkyeribulmaViewModel p)
        {
            
            
            return View();
        }

        [AllowAnonymous]
        public ActionResult parkyeribulma(parkyeribulmaViewModel p)
        {
           
            otoparkEntities mod = new otoparkEntities();
            List<Park_Yeri> py = mod.Park_Yeri.Where(c => c.KatID == 1).ToList();
            
            p.listp = py;





            return View(p);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult parkyeribulma()
        {


            return View();
        }


        [AllowAnonymous]
        public ActionResult Kapıparkyeribulma(parkyeribulmaViewModel p)
        {
            int kat = 0;
            
            otoparkEntities mod = new otoparkEntities();
            for (int i = 0; i < 3; i++)
            {
                List<Park_Yeri> py = mod.Park_Yeri.Where(c => c.KatID == i).ToList();

                p.listppp = py;

                if(py.Count!=0)
                {
                    kat = i;
                    break;

                }

            }
            Park_Yeri min=p.listppp[0];

            for (int j = 0; j < p.listppp.Count; j++)
            {
                if (p.listppp[j].A_Kapı_uzaklığı<min.A_Kapı_uzaklığı)
                {
                    min=p.listppp[j];
                }


            }

            p.listp.Add(min);





            return View(p);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Kapıparkyeribulma()
        {


            return View();
        }





        [AllowAnonymous]
        public ActionResult Kategoriparkyeribulma(parkyeribulmaViewModel p,int kat,int kapı)
        {
            

            
            otoparkEntities mod = new otoparkEntities();
            for (int i=kat; i < 4;)
            {
                List<Park_Yeri> py = mod.Park_Yeri.Where(c => c.KatID == i).ToList();

                p.listppp = py;

                if (py.Count != 0)
                {
                    kat = i;
                    break;

                }
                
                i = (i+1)%3;

                if (i==kat)
                {
                    Response.Write("<script language='javascript'>alert('Şuanda Otoparkta Yer bulunmamaktadır');</script>");

                    return View();
                }


            }
            Park_Yeri min = p.listppp[0];


            if (kapı==1)
            {
                for (int j = 0; j < p.listppp.Count; j++)
                {
                    if (p.listppp[j].B_Kapı_uzaklığı < min.B_Kapı_uzaklığı)
                    {
                        min = p.listppp[j];
                    }


                }

                p.listp.Add(min);
            }
            else
            {
                for (int j = 0; j < p.listppp.Count; j++)
                {
                    if (p.listppp[j].A_Kapı_uzaklığı < min.A_Kapı_uzaklığı)
                    {
                        min = p.listppp[j];
                    }


                }

                p.listp.Add(min);

            }



            return View(p);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Kategoriparkyeribulma()
        {


            return View();
        }





        [AllowAnonymous]
        public ActionResult kroki1(parkyeribulmaViewModel p)
        {

            otoparkEntities mod = new otoparkEntities();
            List<Park_Yeri> py = mod.Park_Yeri.Where(c => c.KatID == 1).ToList();

            p.listp = py;





            return View(p);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult kroki1()
        {


            return View();
        }

        [AllowAnonymous]
        public ActionResult parkyeriekleme()
        {
            
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult parkyeriekleme(parkyerieklemeViewModel parkyeri)
        {
            otoparkEntities mod = new otoparkEntities();
            Park_Yeri p = new Park_Yeri();
            p.Durumu = "dolu";
            p.A_Kapı_uzaklığı = parkyeri.a_kapısı;
            p.B_Kapı_uzaklığı = parkyeri.b_kapısı;
            p.KatID = parkyeri.katıd;

           
            try
            {
            mod.Park_Yeri.Add(p);
            mod.SaveChanges();
            ViewData["Status"] = "Update Sucessful!";
            }
            catch
            {
                Response.Write("<script language='javascript'>alert('Böyle bir kat bulunmamaktadır.Lütfen tekrar deneyiniz');</script>");
                return View();
            }
            




            return View();

        }


        [AllowAnonymous]
        public ActionResult katekleme()
        {

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult katekleme(kateklemeViewModel kat)
        {
            otoparkEntities mod = new otoparkEntities();
            Katlar k = new Katlar();
            Kategori kg = new Kategori();
            k.Kat_No = kat.Kat_NO;
            

            mod.Katlar.Add(k);
            
            

            mod.SaveChanges();
            ViewData["Status"] = "Update Sucessful!";
            kg.Kategori_AD = kat.kategeri;
            kg.KatID = k.Kat_No;
            mod.Kategori.Add(kg);
            mod.SaveChanges();
            ViewData["Status"] = "Update Sucessful!";
            return View();
        }


        [AllowAnonymous]
        public ActionResult kategoriekleme()
        {

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult kategoriekleme(kategorieklemeViewModel kategori)
        {
            otoparkEntities mod = new otoparkEntities();
             
            Kategori kg = new Kategori();

            List<Katlar> kat = mod.Katlar.Where(c => c.Kat_No == kategori.Kat_ID).ToList();


            kg.Kategori_AD = kategori.kategeri;
            kg.KatID = kat[0].Kat_ID;
            mod.Kategori.Add(kg);
            mod.SaveChanges();
            ViewData["Status"] = "Update Sucessful!";
            return View();

            
        }



















        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {

            otoparkEntities mod = new otoparkEntities();
            List<Kullanıcı> kul = mod.Kullanıcı.Where(c => c.E_mail == model.Email && c.Sifre == model.Password).ToList();

            if (kul.Count == 1)
            {
                Session["Kullanıcı"] = kul[0];
                return RedirectToAction("SecimSayfası", "Account");




            }
            else
            {
                Response.Write("<script language='javascript'>alert('E_mail ve şifreniz çalınmıştır.Lütfen danışmaya bildiriniz');</script>");
                
                return RedirectToAction("Index", "Home");


            }








            

        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent:  model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterViewModel model)
        {
            otoparkEntities mod = new otoparkEntities();
            List<Kullanıcı> kullan = new List<Kullanıcı>();
            kullan = mod.Kullanıcı.Where(c => c.E_mail == model.Email).ToList();
            if (kullan.Count == 0)
            {
                
                Kullanıcı kul = new Kullanıcı();
                kul.Adı = model.ad;
                kul.Soyadı = model.soyad;
                kul.Tel = model.telefon;
                kul.E_mail = model.Email;
                kul.Arac_plaka = model.plaka;
                kul.Sifre = model.Sifre;

                mod.Kullanıcı.Add(kul);
                mod.SaveChanges();
                ViewData["Status"] = "Update Sucessful!";
                Session["Kullanıcı"] = kul;
                return RedirectToAction("SecimSayfası", "Account");
            }
            else
            {
                Response.Write("<script language='javascript'>alert('E-mail kullanılmaktadır.Lütfen başka bir E-mail kullanınız');</script>");
                
                return View();

            }
            
            

        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}