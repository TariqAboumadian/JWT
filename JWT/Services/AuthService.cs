using JWT.Hellpers;
using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.Services
{
    public class AuthService : IAuthServicec
    {
        private readonly UserManager<ApplicationUser> _usermanger;
        private readonly JwtHelper _jwt;
        public AuthService(UserManager<ApplicationUser> usermanger, IOptions<JwtHelper> jWT)
        {
            _usermanger = usermanger;
            _jwt = jWT.Value;
        }
        public async Task<AuthModeles> RegisterAsych(RegisterModel model)
        {
            if(await _usermanger.FindByEmailAsync(model.Email) is not null)
            {
                return new AuthModeles()
                {
                    Message = "Email Is Alreday Registered !"
                };
            }
            if (await _usermanger.FindByNameAsync(model.UserName) is not null)
            {
                return new AuthModeles()
                {
                    Message = "User Name Is Alreday Registered !"
                };
            }

            var user = new ApplicationUser()
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };
            var res=await _usermanger.CreateAsync(user,model.Password);
            if (!res.Succeeded)
            {
                StringBuilder strb = new StringBuilder();
                foreach(var error in res.Errors)
                {
                    strb.Append($"{error.Description} ,");
                }
                return new AuthModeles() { Message = strb.ToString() };
            }
            await _usermanger.AddToRoleAsync(user, "User");
            var jwtsecurityToken = await CreatJwtToken(user);
            return new AuthModeles()
            {
                Email=user.Email,
                Expireson= jwtsecurityToken.ValidTo,
                IsAuthinticated=true,
                Roles=new List<string>() { "User"},
                Token=new JwtSecurityTokenHandler().WriteToken(jwtsecurityToken),
                UserName=user.UserName
            };
        }
        private async Task<JwtSecurityToken> CreatJwtToken(ApplicationUser user)
        {
            var userClaims = await _usermanger.GetClaimsAsync(user);
            var roles = await _usermanger.GetRolesAsync(user);
            var RoleClaims = new List<Claim>();
            foreach(var role in  roles)
            {
                RoleClaims.Add(new Claim("roles", role));
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim("uid",user.Id)
            }.Union(userClaims).Union(RoleClaims);
            var SymitricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var siggingCaredentials = new SigningCredentials(SymitricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtsecuritytoken = new JwtSecurityToken(

                issuer: _jwt.Issure,
                audience: _jwt.Auddince,
                claims:claims,
                expires:DateTime.Now.AddDays(_jwt.DurationinDayes),
                signingCredentials:siggingCaredentials
            );
            return jwtsecuritytoken;
        }
    }
}
