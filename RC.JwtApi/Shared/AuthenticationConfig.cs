using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RC.JwtApi.Shared
{
    public static class AuthenticationConfig
    {
        internal static TokenValidationParameters tokenValidationParams;

        public static string GenerateJSONWebToken(string userName)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("B38BA274E398F7DF1C2075E9AAD2721E4E55FE65E6C7F7FBA080B65DAFCD4416"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("UserName", userName),
                new Claim("Role", "1")
            };

            var token = new JwtSecurityToken("xyz",
                "xyz",
                claims,
                DateTime.Now,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        public static void ConfigureJwtAuthentication(this IServiceCollection services)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("B38BA274E398F7DF1C2075E9AAD2721E4E55FE65E6C7F7FBA080B65DAFCD4416"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            tokenValidationParams = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                ValidIssuer = "xyz",
                ValidateLifetime = true,
                ValidAudience = "xyz",
                ValidateAudience = true,
                RequireSignedTokens = true,
                IssuerSigningKey = credentials.Key,
                ClockSkew = TimeSpan.FromMinutes(10)
            };
            services.AddAuthentication(option =>
            {
                option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = tokenValidationParams;
#if DEBUG
                options.IncludeErrorDetails = false;
#else
                option.RequireHttpsMetaData = false;
#endif
            });
        }
    }
}