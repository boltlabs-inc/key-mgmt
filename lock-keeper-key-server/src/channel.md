## Lock-Keeper Channel Infrastructure
Here we provide a high-level overview of the channel infrastructure in Lock-Keeper. For details see code-level documentation in `lock-keeper-key-server/src/server/channel.rs`.

## Communication in Lock-Keeper
Lock-Keeper uses gRPC methods for receiving request from a client. These are implemented on top of the Rust [`tonic`](https://github.com/hyperium/tonic) library. `tonic` allows for
bidirectional streaming of messages between client and server. Our server itself is implemented using `tokio`. `tonic` is able to utilize `tokio`'s MPSC channels to create this
bidirectional channel abstraction. Our `Channel` type abstracts over these implementation details to provide a simple interface for sending and receiving
messages to/from client and server.

These channels facilitate the implementation of cryptographic protocols provided by Lock-Keeper. Specifically: The cryptographic protocols are specified in terms of back and forth
messages and computation done by the client and server, our implementation is able to map this into code in a straightforward way.

## The `Channel` type
The `Channel` type implements straightforward, async, `send` and `receive` methods. These methods can send/receive any kind of data that implements our `ConvertMessage` trait. This trait
is a thin wrapper around anything that is serializable. So it should be easy to implement for your own data type.

Our channels are generic over an authentication mechanism: `Channel<Auth>`. The implementation currently has two types which fill this generic: `Authenticated` and `Unauthenticated`.
These types represent whether we are handling a request which requires authentication, e.g: sign, generate, delete, etc. Or a request
which requires no authentication, like `login` (hitting the `login` endpoint does not require you to be logged in). `Authenticated` provides encryption and decryption of all messages
sent over `Channel`s.

## Setting up Channels in Client and Server
Some ceremony is required to set up these channels. `Channel`s are implemented in terms of two unidirectional channels:
- Channel 1: Server holds receiving end and client holds sending end.
- Channel 2: Server holds sending end and client holds receiving end. 

Channel 1 is instantiated by the client when making the initial gRPC call. The receiver end is kept by the client, the
sending end is sent along with the initial `Request`. When the server receives this request, it saves the receiver end
that the client sent. The server then creates a new channel: The server keeps the sender end and is expected to send the
receiver end back to the client. At this point the server must do two things:
1) Send the receiver end back to the client.
2) Service the request from the client.

The only way to send the `receiver` end from server to client is to return it as the response from the gRPC function call.
But how can we do the request if we need to return the `receiver` first? We spawn a `tokio` task to handle the request on a different
thread while the current thread returns immediately with the `receiver`.

Note: It may seem magical that sending channel ends over `tonic` works, even though channel ends know nothing about `tonic` and they
are being sent over the network. This is magical as it kinda "just works".
