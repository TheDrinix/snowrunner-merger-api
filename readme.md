# Snowrunner Merger API

A .NET Web API service that handles save file merging functionality for Snowrunner game saves. The API provides endpoints for user authentication, group management, and save file operations.
As Snowrunner does not share progress when playing coop, this application allows players to merge their save files with their friends' save files to keep their progress in sync.

## Related Repositories
This is the backend API for the Snowrunner Merger project. For the frontend application, see [Snowrunner Merger Frontend](https://github.com/TheDrinix/snowrunner-merger-web).

## Technologies Used

- ASP.NET Core Web API (.NET 8.0)
- Entity Framework Core
- PostgreSQL with Npgsql
- JWT Bearer Authentication
- Google OAuth 2.0
- Swagger/OpenAPI
- Docker

## Prerequisites

- .NET 8.0 SDK (for development)
- PostgreSQL database server
- Google OAuth 2.0 credentials
    - Client ID
    - Client Secret
- Docker (for deployment)

## Configuration

Configure the application using environment variables, `appsettings.json` or secrets manager.
You can use the provided `appsettings.example.json` or `example.env` as a template.

### Authentication Configuration

Configure your Google OAuth 2.0 credentials and token secrets in `appsettings.json` or using environment variables:
```json
{
  "Google": {
    "ClientId": "your_google_client_id",
    "ClientSecret": "your_google_client_secret"
  },
  "JwtSecret": "jwt_secret",
  "RefreshSecret": "refresh_secret (Must be exactly 32 characters long)"
}
```

- Refresh secret must be exactly 32 characters long.

### SMTP Configuration

Configure your SMTP server settings in `appsettings.json` or using environment variables:
```json
{
  "SMTP": {
    "Host": "your_host",
    "Port": "host_port",
    "Username": "your_smtp_username",
    "Password": "your_smtp_password",
    "Address": "your_email_address"
  }
}
```

### Database Configuration

Configure your PostgreSQL connection string in `appsettings.json` or using environment variables:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=snowrunner_merger;Username=your_username;Password=your_password"
  }
}
```

## Development Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/snowrunner-merger-api.git
cd snowrunner-merger-api
```

2. Restore dependencies
```bash
dotnet restore
```

3. Configure the application using `appsettings.json` or environment variables

3. Update database with migrations
```bash
dotnet ef database update
```

4. Run the application
```bash
dotnet run
```

The API will be available at `https://localhost:5001` (or your configured port).

## Docker Deployment

### Building the Docker Image

```bash
docker build -t snowrunner-merger-api .
```

### Running the Container

```bash
docker run -d \
  -p 8080:80 \
  -e GOOGLE_CLIENT_ID=your_google_client_id \
  -e GOOGLE_CLIENT_SECRET=your_google_client_secret \
  -e ConnectionStrings__DefaultConnection="Host=db;Database=snowrunner_merger;Username=your_username;Password=your_password" \
  snowrunner-merger-api
```

## API Documentation

API documentation is available via Swagger UI at `/swagger` when running the application in development mode.

### Authentication

The API uses JWT Bearer authentication. To access protected endpoints:
1. Authenticate using username and password or Google OAuth
2. Include the JWT token in the Authorization header of subsequent requests:
```
Authorization: Bearer <your_jwt_token>
```

## Development

### Adding New Migrations

When making changes to the data model:
```bash
dotnet ef migrations add YourMigrationName
dotnet ef database update
```

### Building
```bash
dotnet build
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please [create an issue here](https://github.com/TheDrinix/snowrunner-merger-api/issues).