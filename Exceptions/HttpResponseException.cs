using System.Net;

namespace SnowrunnerMergerApi.Exceptions;

public class HttpResponseException : Exception
{
    public string Title = string.Empty;
    public object? Details = string.Empty;
    public HttpStatusCode StatusCode { get; set; }

    public HttpResponseException(HttpStatusCode statusCode, string title = "", object? details = null)
    {
        StatusCode = statusCode;
        Title = title;
        Details = details ?? title;
    }

    public object GetValue => new
    {
        title = Title,
        status = StatusCode,
        errors = new
        {
            error = Details
        }
    };
}