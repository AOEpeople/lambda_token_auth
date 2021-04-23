
# About

This implements a AWS Lambda handler which takes a JWT-Token, validates it and then performs a Aws:Sts:AssumeRole based on preconfigured rules. It's similar to the existing (offical) TokenAuthorizer but allows more complexity in it's configuration.

Practical usage could e.g. allow to authenticate a Gitlab-CI pipeline through the [`CI_JOB_JWT` token](https://docs.gitlab.com/ee/ci/secrets/index.html) without requiring additional long-term authentication credentials. The [claims within the token](https://docs.gitlab.com/ee/ci/examples/authenticating-with-hashicorp-vault/#how-it-works) allow very fine grained control which is not possible otherwise.  

## Configuration

The lambda function is configured through environment variables, and a JSON document stored within S3.

### Environment variables

* `CONFIG_BUCKET` - (required) the S3 bucket name which contains the related configuration object
* `CONFIG_KEY` - (required) the S3 object key which contains the JSON configuration
* `LOGLEVEL` - (optional) loglevel - allowed values: Trace, Debug, Info, Warning, Error, Fatal and Panic 

### JSON configuration

```
{
    "jwks_url":"https://gitlab.com/-/jwks",                          // URL which contains required JWKs key information
    "rules":[                                                        // List of rules which would allow the AssumeRole for certain tokens
        {
            "claim_values":{                                         // The required values which the token should present
                "namespace_id":"4"
            },
            "duration":1800,                                         // Duration of the created session
            "region":"us-east-1",
            "role":"arn:aws:iam::124567910112:role/some-role-arn"    // Arn of the role which we Assume for valid tokens
        }
    ]
}
```
