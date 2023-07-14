<img width=250px src="https://atsign.dev/assets/img/atPlatform_logo_gray.svg?sanitize=true">

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_python/badge)](https://api.securityscorecards.dev/projects/github.com/atsign-foundation/at_python)

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
There are 3 ways in which data can be sent and received from at server.
1. Using PublicKey
    ```python
    from at_client import AtClient
    from at_client.common import AtSign
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
    from at_client import AtClient
    from at_client.common import AtSign
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
    from at_client import AtClient
    from at_client.common import AtSign
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

	
### CLI Tools
* **REPL** - you can use this to type atPlatform commands and see responses; but the best thing about the REPL currently is that it shows the data notifications as they are received. The REPL code has the essentials of what a 'receiving' client needs to do - i.e.
	* create an AtClient (assigning a Queue object to its queue parameter)
	* start two new threads
        * one for the AtClient.start_monitor() task: receives data update/delete notification events (the event data contains the ciphertext)
        * the other one calls handle_event() method, which will read the upcoming events in the queue and handle them: 
			* calling AtClient.handle_event() (to decrypt the notifications and introducing the result as a new event in the queue) 
			* reading the new event, which contains the decrypted result 
	* Instructions to run the REPL:
		1) Run repl.py and choose an atSign using option `1`
		2) Select option `2`. REPL will start and activate monitor mode automatically in a different thread. You can still send commands/verbs. You will start seeing your own notifications (from yourself to yourself) and heartbeat working (noop verb is sent from time to time as a keepalive)
		3) Use `at_talk` or any other tool to send notifications to your atSign from a different atSign. You should be able to see the complete notification, and the encrypted and decrypted value of it.

## Open source usage and contributions

This is open source code, so feel free to use it as is, suggest changes or
enhancements or create your own version. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for detailed guidance on how to setup tools, tests and make a pull request.

## Maintainers

This project is created and maintained by [Umang Shah](https://github.com/shahumang19)
