# Gripe (GraphQL for Stripe)

This is a project that generates a GraphQL server from Stripe's openapi spec.

## Developing

Install `go` 1.20, then do `go run .` in the root directory.

You can view graphiql at `http://localhost:8092/graphql`

In the headers tab at the bottom, add your Stripe token (e.g. `{"X-Stripe-Token": "$YOUR_STRIPE_TOKEN_HERE"}`) to make authenticated queries.

## Deploying

There is a Dockerfile in the root directory.

Deploying with fly.io is as simple as:

```
brew install flyctl

flyctl launch
```

Send graphql queries to $your-domain/graphql. To send authenticated requests to Stripe, add an `X-Stripe-Token` header with your Stripe token.

## Updating the openapi schema to a newer version

Stripe's openapi schema is checked out as a submodule to a specific version in the openapi directory. Update the submodule to build the schema with a newer version.

Updating the schema will likely require code changes to make things work.
