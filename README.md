// ================================ // Projeto: AuthServer (API com OpenIddict e AD) // ================================

// Estrutura do projeto: // - AuthServer/ //   - Data/ //     - ApplicationDbContext.cs //   - Controllers/ //     - AuthorizationController.cs //   - Program.cs //   - appsettings.json // // ================================ // Passo 1: Criar o Projeto // ================================ // Execute no terminal: // dotnet new webapi -n AuthServer // cd AuthServer // dotnet add package OpenIddict // dotnet add package OpenIddict.AspNetCore // dotnet add package OpenIddict.EntityFrameworkCore // dotnet add package Microsoft.AspNetCore.Authentication.Negotiate // dotnet add package Microsoft.EntityFrameworkCore.SqlServer // dotnet add package System.DirectoryServices.AccountManagement

// ================================ // Arquivo: appsettings.json // ================================ { "ConnectionStrings": { "DefaultConnection": "Server=localhost;Database=AuthServerDB;Trusted_Connection=True;TrustServerCertificate=True;" }, "Logging": { "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" } }, "AllowedHosts": "*" }

// ================================ // Arquivo: Data/ApplicationDbContext.cs // ================================ using Microsoft.EntityFrameworkCore; using OpenIddict.EntityFrameworkCore.Models;

namespace AuthServer.Data { public class ApplicationDbContext : DbContext { public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

public DbSet<OpenIddictEntityFrameworkCoreApplication> Applications { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreAuthorization> Authorizations { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreScope> Scopes { get; set; }
    public DbSet<OpenIddictEntityFrameworkCoreToken> Tokens { get; set; }
}

}

// ================================ // Arquivo: Controllers/AuthorizationController.cs // ================================ using Microsoft.AspNetCore.Mvc; using OpenIddict.Abstractions; using System.DirectoryServices.AccountManagement; using System.Security.Claims; using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Controllers { [ApiController] [Route("connect")] public class AuthorizationController : ControllerBase { [HttpPost("token")] public IActionResult Exchange([FromForm] OpenIddictRequest request) { if (!request.IsPasswordGrantType()) { return BadRequest(new { error = "unsupported_grant_type" }); }

// Autenticação no Active Directory
        if (!AuthenticateWithAD("CORP", request.Username, request.Password))
        {
            return Unauthorized(new { error = "invalid_credentials" });
        }

        var claims = new List<Claim>
        {
            new Claim(Claims.Subject, request.Username),
            new Claim(Claims.Name, request.Username),
            new Claim(Claims.Email, $"{request.Username}@corp.com"),
            new Claim("groups", "TI"),
            new Claim("groups", "Financeiro")
        };

        var identity = new ClaimsIdentity(claims, "Password");
        var principal = new ClaimsPrincipal(identity);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private bool AuthenticateWithAD(string domain, string username, string password)
    {
        try
        {
            using var context = new PrincipalContext(ContextType.Domain, domain);
            return context.ValidateCredentials(username, password);
        }
        catch
        {
            return false;
        }
    }
}

}

// ================================ // Arquivo: Program.cs // ================================ using AuthServer.Data; using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Banco de dados builder.Services.AddDbContext<ApplicationDbContext>(options => { options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")); options.UseOpenIddict(); });

// OpenIddict configuração builder.Services.AddOpenIddict() .AddCore(options => { options.UseEntityFrameworkCore() .UseDbContext<ApplicationDbContext>(); }) .AddServer(options => { options.SetTokenEndpointUris("/connect/token"); options.AllowPasswordFlow(); options.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, "groups"); options.AddDevelopmentEncryptionCertificate() .AddDevelopmentSigningCertificate();

options.UseAspNetCore()
           .EnableTokenEndpointPassthrough();
})
.AddValidation(options =>
{
    options.UseLocalServer();
    options.UseAspNetCore();
});

// Autenticação via Negotiate (para uso com o AD) builder.Services.AddAuthentication("Negotiate") .AddNegotiate();

var app = builder.Build();

// Migração automática target using (var scope = app.Services.CreateScope()) { var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>(); dbContext.Database.Migrate(); }

app.UseAuthentication(); app.UseAuthorization(); app.MapControllers(); app.Run();

// ================================ // Como rodar o projeto: // ================================ // 1. Execute as migrações: //    dotnet ef migrations add InitialCreate //    dotnet ef database update // 2. Execute o projeto: //    dotnet run // // ================================ // Como testar: // ================================ // Faça uma requisição POST para /connect/token com os parâmetros: // - grant_type: password // - username: <usuário_do_AD> // - password: <senha_do_AD> // // Você receberá um token JWT com claims e grupos.

// ================================ // Segurança: // ================================ // - Em produção, substitua os certificados de desenvolvimento. // - Use HTTPS e configure corretamente o domínio. // - Proteja os endpoints com políticas de segurança adicionais.
 
