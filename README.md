API:
    cd api
    dotnet dev-certs https --trust

    dotnet user-secrets (sent privately)

    dotnet restore
    dotnet run --urls "https://localhost:50886"

UI:
    cd ui
    npm install
    ng serve

User seeds:
    Admin: admin@example.com / Admin123!
    User: user@example.com / User123!