<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

# The atPlatform for Python developers - (Alpha Version)

This repo contains library, samples and examples for developers who wish
to work with the atPlatform from Python code.

## Getting Started
### 1. Installation
```
pip install -r requirements.txt
pip install .
```



### 2. Setting up your `.atKeys`
To run the examples save .atKeys file in the '~/.atsign/keys/' directory.

### 3. Sending and Receiving Data
There are 3 ways in which data can be sent to at server.
1. Using PublicKey
    ```python
    from at_client.common import AtSign, AtClient
    from at_client.common.keys import PublicKey

    atsign = AtSign("@bob")
    atclient = AtClient(atsign)
    pk = PublicKey("key", atsign)

    # Sending data
    response = atclient.put(pk, "value")
    print(response)

    # Receiving Data
    response = atclient.get(pk)
    print(response)

    # Deleting data
    response = atclient.delete(pk)
    print(response)

    ```

2. Using SelfKey
    ```python
    from at_client.common import AtSign, AtClient
    from at_client.common.keys import SelfKey

    atsign = AtSign("@bob")
    atclient = AtClient(atsign)
    sk = SelfKey("key", atsign)

    # Sending data
    response = atclient.put(sk, "value")
    print(response)

    # Receiving Data
    response = atclient.get(sk)
    print(response)

    # Deleting data
    response = atclient.delete(sk)
    print(response)

    ```

3. Using SharedKey
    ```python
    from at_client.common import AtSign, AtClient
    from at_client.common.keys import SharedKey

    bob = AtSign("@bob")
    alice = AtSign("@alice")
    bob_atclient = AtClient(bob)
    sk = SharedKey("key", bob, alice)

    # Sending data
    response = bob_atclient.put(sk, "value")
    print(response)

    # Receiving Data
    alice_atclient = AtClient(alice)
    response = alice_atclient.get(sk)
    print(response)

    # Deleting data
    response = bob_atclient.delete(sk)
    print(response)

    ```

## Open source usage and contributions

This is open source code, so feel free to use it as is, suggest changes or
enhancements or create your own version. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for detailed guidance on how to setup tools, tests and make a pull request.

## Maintainers

This project is created and maintained by [Umang Shah](https://github.com/shahumang19)