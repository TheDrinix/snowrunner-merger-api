using System.Net;

namespace SnowrunnerMergerApi.Exceptions;

public class HttpResponseException : Exception
{
    public string Title = string.Empty;
    public object? Details = string.Empty;
    public List<string>? Errors = new List<string>();
    public HttpStatusCode StatusCode { get; set; }

    public HttpResponseException(HttpStatusCode statusCode, string title = "", object? details = null, List<string>? errors = null)
    {
        StatusCode = statusCode;
        Title = title;
        Details = details ?? title;
        Errors = errors;
    }

    public object GetValue => new
    {
        title = Title,
        status = StatusCode,
        message = Details,
        errors = Errors
    };
}