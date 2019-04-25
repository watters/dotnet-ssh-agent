# SSHAgent Client/Proxy for .NET Core

## Usage

```
var socketPath = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
var endpoint = new UnixDomainSocketEndPoint(socketPath);
using (var client = new SSHAgentClient(endpoint)) {
    var identities = client.List() // retrieve a list of identities
    
    byte[] input = Encoding.UTF8.GetBytes("Hello, World!");
    
    var key = identities.First();
    byte[] signature = client.Sign(key, input);
}
```

## Building & Running Tests

Install the most recent [.NET Core](https://www.microsoft.com/net/core)

### Ensure you an RSA key in PEM format

```
ssh-keygen -m PEM -t rsa -b 2048 -f ~/.ssh/my_test_key
```

### Add it to ssh-agent

```
ssh-add ~/.ssh/my_test_key
```

In the root of the repo, run

```
export TEST_KEY_PATH="${HOME}/.ssh/my_test_key"
export MD5_FINGERPRINT=$(ssh-keygen -E md5 -lf ${TEST_KEY_PATH}.pub | awk '{print $2}')
export SHA256_FINGERPRINT=$(ssh-keygen -E sha256 -lf ${TEST_KEY_PATH}.pub | awk '{print $2}')

dotnet restore
dotnet test tests/Watters.SSHAgent.Client.Tests
```

The tests depend on a few things being true, so if they fail, you may need to do
some/all of the following