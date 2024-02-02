using JWT.Models;
using JWT.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthServicec _authService;
        public AuthController(IAuthServicec authService)
        {
            _authService = authService;
        }
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody]RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var res = await _authService.RegisterAsych(model);
            if (!res.IsAuthinticated)
            {
                return BadRequest(res.Message);
            }
            return Ok(new {res.UserName,res.Expireson,res.Token});
        }
    }
}
