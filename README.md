
# About

This implements a AWS Lambda handler which takes a JWT-Token, validates it and then performs a Aws:Sts:AssumeRole based on preconfigured rules. It's similar to the exsiting (offical) TokenAuthorizer but allows more complixity in it's configuration.