using System.Net;

namespace SnowrunnerMergerApi.Exceptions;

public class HttpResponseException : Exception
{
    public string Title = string.Empty;
    public object? Details = string.Empty;
    public Dictionary<string, object> Errors;
    public HttpStatusCode StatusCode { get; set; }

    public HttpResponseException(HttpStatusCode statusCode, string title, Dictionary<string, object> errors)
    {
        StatusCode = statusCode;
        Title = title;
        Errors = errors;
    }

    public HttpResponseException(HttpStatusCode statusCode, string title = "", object? details = null)
    {
        var errors = new Dictionary<string, object> { { "error", details ?? title } };

        StatusCode = statusCode;
        Title = title;
        Errors = errors;
    }

    public object GetValue => new
    {
        title = Title,
        status = StatusCode,
        errors = Errors
    };
}