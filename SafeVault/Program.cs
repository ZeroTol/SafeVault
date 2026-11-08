using SafeVault.Data;
using SafeVault.Endpoints;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self';";
    await next();
});

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();

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

// ---- Endpoints ----
app.MapWebForm();
app.MapGroup("/api/account").WithTags("Account").MapAccountEndpoints();

app.Run();

public partial class Program { }