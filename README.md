# ASP.NET Authentication & Authorization Web App

This repository hosts an ASP.NET Core web application that demonstrates authentication and authorization functionalities. The application includes user login, registration, and role-based access control using ASP.NET Identity.

## Project Overview

This web app is built with ASP.NET Core and utilizes ASP.NET Identity for managing user authentication and authorization. Key features include:

- **User Registration and Login**: Users can sign up and log into their accounts using default registration, Google or Microsoft accounts.
- **User Authentication and Password Change via mail**: Users can verify their account or change their password using mail links, sent to their corresponding address.
- **Role-Based Authorization**: Specific pages or actions are accessible only to users with certain roles (e.g., Admin, User).
- **ASP.NET Identity**: Integration with ASP.NET Identity for managing users, roles, and claims.

## Features

- **User Authentication**: Secure login and registration functionality using ASP.NET Identity.
- **Authentication and Change Password**: Authentication and Password change through SendGrid email confirmation link using session token.
- **Role-Based Access Control**: Restrict access to certain pages or resources based on the user's role.
- **Claims-Based Authorization**: Fine-grained control of access using user claims.
- **Secure Password Management**: Password hashing and validation via ASP.NET Identity.
- **Session Management**: Manages user sessions securely.

### Prerequisites

- **.NET SDK**: Ensure you have .NET SDK 6.0 or later installed. You can download it from [here](https://dotnet.microsoft.com/download).
- **SQL Server**: The application uses SQL Server for the database. You can use SQL Server Express or configure it to use a different database in `appsettings.json`.
