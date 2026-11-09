using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Configuration;
using SafeVault.Data;
using SafeVault.Endpoints;
using SafeVault.Helpers;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

// --- DI ---

var useInMemory = builder.Configuration.GetValue("Database:UseInMemory", defaultValue: true);

if (useInMemory)
    builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>(); // singleton → state persists
else
    builder.Services.AddScoped<IUserRepository, UserRepository>();    

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddProblemDetails();

// --- JWT bearer authentication ---
var jwt = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()!;
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer              = jwt.Issuer,
            ValidAudience            = jwt.Audience,
            IssuerSigningKey         = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            ClockSkew                = TimeSpan.FromSeconds(30),
            RoleClaimType            = System.Security.Claims.ClaimTypes.Role
        };
    });

// --- RBAC policies ---
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("AdminOnly",    p => p.RequireRole("Admin"));
    o.AddPolicy("UserOrAdmin",  p => p.RequireRole("User", "Admin"));
});

// --- HTTPS / HSTS ---
builder.Services.AddHsts(o =>
{
    o.Preload = true; o.IncludeSubDomains = true; o.MaxAge = TimeSpan.FromDays(365);
});

var app = builder.Build();

// --- security headers (unchanged) ---
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"]        = "DENY";
    ctx.Response.Headers["Referrer-Policy"]        = "no-referrer";
    ctx.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self';";
    await next();
});

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();

// --- static files (web form, login/admin pages) ---
var defaults = new DefaultFilesOptions();
defaults.DefaultFileNames.Clear();
defaults.DefaultFileNames.Add("webform.html");
app.UseDefaultFiles(defaults);
app.UseStaticFiles();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// --- ORDER MATTERS: Authentication must run before Authorization ---
app.UseAuthentication();
app.UseAuthorization();

// --- endpoints ---
app.MapWebForm();
app.MapAccountEndpoints();
app.MapAdminEndpoints();

// --- seed the first Admin once (rotate the password afterwards!) ---
await BootstrapAdminAsync(app);
app.Run();

static async Task BootstrapAdminAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var repo   = scope.ServiceProvider.GetRequiredService<IUserRepository>();
    var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();

    if (await repo.AnyAdminExistsAsync()) return;

    var u  = config["Bootstrap:AdminUsername"] ?? "admin";
    var e  = config["Bootstrap:AdminEmail"]    ?? "admin@safevault.local";
    var pw = config["Bootstrap:AdminPassword"] ?? throw new InvalidOperationException("Bootstrap admin password missing.");

    var hash = PasswordHasher.Hash(pw);
    await repo.CreateUserAsync(u, e, hash, "Admin");
    app.Logger.LogWarning("Seeded bootstrap admin '{User}'. Change the password immediately.", u);
}

public partial class Program { }   // visible to WebApplicationFactory<Program>