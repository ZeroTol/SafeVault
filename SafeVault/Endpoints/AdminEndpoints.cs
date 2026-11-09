using System.Security.Claims;
using SafeVault.Data;
using SafeVault.Models.Contracts;

namespace SafeVault.Endpoints;

public static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/admin")
            .RequireAuthorization("AdminOnly")
            .WithTags("Admin");

        admin.MapGet("/dashboard", (ClaimsPrincipal user) =>
            TypedResults.Ok(new
            {
                message    = $"Welcome, {user.Identity!.Name}",
                role       = user.FindFirstValue(ClaimTypes.Role),
                serverTime = DateTime.UtcNow
            }));

        admin.MapPost("/users/{username}/role",
            async Task<IResult> (string username, RoleUpdateRequest req, IUserRepository repo) =>
            {
                if (!new[] { "Admin", "User", "Guest" }.Contains(req.Role))
                    return TypedResults.BadRequest(new { error = "Invalid role." });

                return await repo.SetRoleAsync(username, req.Role)
                    ? TypedResults.Ok(new { username, role = req.Role })
                    : TypedResults.NotFound(new { error = "User not found." });
            });

        // Task 3 — audit trail viewer
        admin.MapGet("/audit/logins",
            async (IUserRepository repo, int take = 50) =>
            {
                var rows = await repo.GetRecentLoginsAsync(take);
                return TypedResults.Ok(rows);
            });

        return app;
    }
}