

https://docs.gitlab.com/ee/ci/examples/authenticating-with-hashicorp-vault/


```
{
  "jti": "c82eeb0c-5c6f-4a33-abf5-4c474b92b558", # Unique identifier for this token
  "iss": "gitlab.example.com",                   # Issuer, the domain of your GitLab instance
  "iat": 1585710286,                             # Issued at
  "nbf": 1585798372,                             # Not valid before
  "exp": 1585713886,                             # Expire at
  "sub": "job_1212",                             # Subject (job id)
  "namespace_id": "1",                           # Use this to scope to group or user level namespace by id
  "namespace_path": "mygroup",                   # Use this to scope to group or user level namespace by path
  "project_id": "22",                            #
  "project_path": "mygroup/myproject",           #
  "user_id": "42",                               # Id of the user executing the job
  "user_login": "myuser"                         # GitLab @username
  "user_email": "myuser@example.com",            # Email of the user executing the job
  "pipeline_id": "1212",                         #
  "job_id": "1212",                              #
  "ref": "auto-deploy-2020-04-01",               # Git ref for this job
  "ref_type": "branch",                          # Git ref type, branch or tag
  "ref_protected": "true",                       # true if this git ref is protected, false otherwise
  "environment": "production",                   # Environment this job deploys to, if present (GitLab 13.9 and later)
  "environment_protected": "true"                # true if deployed environment is protected, false otherwise (GitLab 13.9 and later)
}
```