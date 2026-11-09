using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeVault.Data;

namespace SafeVault.Tests;

public static class TestFactory
{
    public static WebApplicationFactory<Program> Create() =>
        new WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.ConfigureServices(s =>
            {
                s.RemoveAll<IUserRepository>();
                s.AddSingleton<IUserRepository, InMemoryUserRepository>();
            }));
}