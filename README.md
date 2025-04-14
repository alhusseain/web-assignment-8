# Authentication and Authorization Demo with Node.js

## Introduction

This demo illustrates how to implement **authentication** and **authorization** in a Node.js application. It covers how users can register and log in, how passwords are securely hashed, and how JSON Web Tokens (JWT) are used for authentication. It also demonstrates how role-based access control (RBAC) can be used to protect routes based on user roles.

## Getting Started

### Installation

```bash
npm install
```

Create a `.env` file in the root of the project:

```
JWT_SECRET=your_super_secret_key
```

This secret is used to sign and verify JWT tokens. Never hard-code secrets in code — always store them in environment variables, especially in production.

### Run the server

```bash
npm start
```

Server runs at: `http://localhost:3000`

## Comprehension

- **Authentication**: Verifying who the user is (via login with bcrypt and JWT).
- **Authorization**: Verifying what the user can do (via role-based access control on protected routes).

## Experimentation

### Register

`POST /register`

```json
{
  "username": "alice",
  "password": "password123",
  "role": "admin"
}
```

### Login

`POST /login`

```json
{
  "username": "alice",
  "password": "password123"
}
```

Returns a JWT token.

### Protected Route

`GET /dashboard`  
Requires `Authorization: Bearer <token>`

### Admin Route (RBAC)

`GET /admin`  
Requires role `admin`
