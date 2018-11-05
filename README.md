# SSHAgent Client/Proxy for .NET Core

## Building & Running Tests

Install the most recent [.NET Core](https://www.microsoft.com/net/core)

In the root of the repo, run

```
export MD5_FINGERPRINT=$(ssh-keygen -E md5 -lf ~/.ssh/id_rsa.pub | awk '{print $2}')
export SHA256_FINGERPRINT=$(ssh-keygen -E sha256 -lf ~/.ssh/id_rsa.pub | awk '{print $2}')

dotnet restore
dotnet test tests/Watters.SSHAgent.Client.Tests
```

The tests depend on a few things being true, so if they fail, you may need to do some/all of the following

### Create an RSA key at `~/.ssh/id_rsa`, if you haven't already got one

```
ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa
```

### Add it to ssh-agent

```
ssh-add ~/.ssh/id_rsa
```
