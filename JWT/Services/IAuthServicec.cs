﻿using JWT.Models;

namespace JWT.Services
{
    public interface IAuthServicec
    {
        Task<AuthModeles> RegisterAsych(RegisterModel model);
    }
}