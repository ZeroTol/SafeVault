using System.Net;
using SafeVault.Helpers;

namespace SafeVault.Endpoints;

public static class WebFormEndpoints
{
    public static IEndpointRouteBuilder MapWebForm(this IEndpointRouteBuilder app)
    {
        app.MapPost("/submit", HandleSubmit);
        return app;
    }

    private static IResult HandleSubmit(HttpRequest request)
    {
        // Native form post → read form fields.
        var form = request.Form;
        var username = form["username"].ToString();
        var email    = form["email"].ToString();

        // Server-side validation — same helpers as the JSON API.
        var errors = new List<string>();

        if (!ValidationHelpers.IsValidInput(username))
            errors.Add("Username must be letters/digits only (max 50).");
        if (!XssProtection.IsSafeInput(username))
            errors.Add("Username contains disallowed content.");
        if (!ValidationHelpers.IsValidEmail(email))
            errors.Add("Email format is invalid.");
        if (!XssProtection.IsSafeInput(email))
            errors.Add("Email contains disallowed content.");

        return errors.Count == 0
            ? Results.Content(RenderSuccess(username, email), "text/html")
            : Results.Content(RenderPage(
                "Rejected", "Validation failed.",
                string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))),
                "text/html", statusCode: 400);
    }

    /// <summary>Success page. User values are always HTML-encoded (internal for tests).</summary>
    internal static string RenderSuccess(string username, string email) => RenderPage(
        "Success", "Input validated successfully.",
        $"Username: {WebUtility.HtmlEncode(username)}<br/>Email: {WebUtility.HtmlEncode(email)}");

    /// <summary>Minimal HTML page. <paramref name="body"/> is inserted as-is — callers must HTML-encode any user data in it.</summary>
    private static string RenderPage(string title, string heading, string body) => $"""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"/><title>{WebUtility.HtmlEncode(title)}</title></head>
        <body>
          <h2>{WebUtility.HtmlEncode(heading)}</h2>
          <p>{body}</p>
          <p><a href="/webform.html">Back to form</a></p>
        </body></html>
        """;
}