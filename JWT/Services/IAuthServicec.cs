using JWT.Models;

namespace JWT.Services
{
    public interface IAuthServicec
    {
        Task<AuthModeles> RegisterAsych(RegisterModel model);
        Task<AuthModeles> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRolesAsync(AddRoleModel model);
    }
}
