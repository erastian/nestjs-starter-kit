<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

# Nestjs Starter Kit

Ready to Use NestJS Application. Requires a little preconfiguration before use =)

## Description

This is a starter kit for NestJS application with GraphQL Apollo adapter, Prisma service as ORM, Authentication with
JWT tokens and Google OAuth(HttpOnly refresh cookie strategy), Mailer service with handlebars templates. Also include
Swagger UI (disabled by default).
In this repository you can find also unit and e2e tests.

## Installation

```bash
$ npm install
```

Rename the .env.example file to .env. Set up your DB credentials in .env file. After execute the following command

```bash
# push DB structure in your DB
$ prisma db push
```

You can use any of your .env files like .env.prod or .env.dev, configuration service will load them automatically by
predefined list.

## Compile and run the project

```bash
# development
$ npm run start:dev

# watch mode (nodemon)
$ npm run start

# production mode
$ npm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

NOTE: e2e tests uses [Testcontainers](https://testcontainers.com/) for testing purposes. This means that e2e tests
require ``Docker`` installed and running to run. Depending on the performance of your hardware, `Docker` sometimes fails to
get out of energy-saving mode in time to run tests. Therefore, in case of an error, it is sometimes necessary to run the
test twice. After each test suite, the DB data will be cleared.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS](https://github.com/nestjs/nest) to learn more about the framework.
- Visit the [Prisma](https://github.com/prisma/prisma) to learn more about the ORM.