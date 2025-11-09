# Stage 1: Restore & Build
# This stage downloads dependencies and builds the application.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /source

# Copy solution and project files to leverage Docker layer caching.
# This way, 'dotnet restore' is only re-run when project dependencies change.
COPY *.sln .
COPY cmsAuth.API/*.csproj ./cmsAuth.API/
COPY cmsAuth.Application/*.csproj ./cmsAuth.Application/
COPY cmsAuth.Infrastructure/*.csproj ./cmsAuth.Infrastructure/
COPY cms.Domain/*.csproj ./cms.Domain/
COPY ClassLibrary1/*.csproj ./ClassLibrary1/

# Restore NuGet packages for the entire solution.
RUN dotnet restore "./cmsAuth.sln"

# Copy the rest of the source code.
COPY . .

# Publish the application, creating a release-ready output.
# The output is placed in the /app/publish directory.
RUN dotnet publish "./cmsAuth.API/cmsAuth.API.csproj" -c Release -o /app/publish --no-restore

# Stage 2: Final Image
# This stage creates the final, lightweight production image.
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# Copy the published output from the 'build' stage.
COPY --from=build /app/publish .

# Expose port 8080. ASP.NET Core apps in containers default to listening on this port.
# Ensure your application is configured to listen on http://*:8080
EXPOSE 8080

# Set the entry point to run the application.
ENTRYPOINT ["dotnet", "cmsAuth.API.dll"]