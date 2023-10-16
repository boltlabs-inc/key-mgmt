(function() {var implementors = {
"lock_keeper":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.str.html\">str</a>&gt; for <a class=\"struct\" href=\"lock_keeper/types/database/account/struct.AccountName.html\" title=\"struct lock_keeper::types::database::account::AccountName\">AccountName</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/serde_json/1.0.104/serde_json/error/struct.Error.html\" title=\"struct serde_json::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper/crypto/generic/enum.CryptoError.html\" title=\"enum lock_keeper::crypto::generic::CryptoError\">CryptoError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"struct\" href=\"lock_keeper/crypto/cryptor/struct.CryptorContext.html\" title=\"struct lock_keeper::crypto::cryptor::CryptorContext\">CryptorContext</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/types/database/account/struct.UserId.html\" title=\"struct lock_keeper::types::database::account::UserId\">UserId</a>&gt; for <a class=\"struct\" href=\"lock_keeper/types/database/struct.HexBytes.html\" title=\"struct lock_keeper::types::database::HexBytes\">HexBytes</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/metadata/encoding/struct.InvalidMetadataValueBytes.html\" title=\"struct tonic::metadata::encoding::InvalidMetadataValueBytes\">InvalidMetadataValueBytes</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/rpc/struct.Message.html\" title=\"struct lock_keeper::rpc::Message\">Message</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>]&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;T&gt; for <a class=\"struct\" href=\"lock_keeper/types/database/struct.HexBytes.html\" title=\"struct lock_keeper::types::database::HexBytes\">HexBytes</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.SigningKeyPair.html\" title=\"struct lock_keeper::crypto::signing_key::SigningKeyPair\">SigningKeyPair</a>&gt; for <a class=\"struct\" href=\"lock_keeper/crypto/struct.Export.html\" title=\"struct lock_keeper::crypto::Export\">Export</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;VerifyingKey&lt;Secp256k1&gt;&gt; for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.SigningPublicKey.html\" title=\"struct lock_keeper::crypto::signing_key::SigningPublicKey\">SigningPublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper/crypto/generic/enum.CryptoError.html\" title=\"enum lock_keeper::crypto::generic::CryptoError\">CryptoError</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/hex/0.4.3/hex/error/enum.FromHexError.html\" title=\"enum hex::error::FromHexError\">FromHexError</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/types/database/account/struct.AccountName.html\" title=\"struct lock_keeper::types::database::account::AccountName\">AccountName</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/types/database/account/struct.AccountId.html\" title=\"struct lock_keeper::types::database::account::AccountId\">AccountId</a>&gt; for <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.i64.html\">i64</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/cryptor/struct.CryptorContext.html\" title=\"struct lock_keeper::crypto::cryptor::CryptorContext\">CryptorContext</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>&gt;"],["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"lock_keeper/crypto/generic/struct.AssociatedData.html\" title=\"struct lock_keeper::crypto::generic::AssociatedData\">AssociatedData</a>&gt; for &amp;'a [<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>]"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ProtocolError&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/generic/struct.AssociatedData.html\" title=\"struct lock_keeper::crypto::generic::AssociatedData\">AssociatedData</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>&gt; for <a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.i64.html\">i64</a>&gt; for <a class=\"struct\" href=\"lock_keeper/types/database/account/struct.AccountId.html\" title=\"struct lock_keeper::types::database::account::AccountId\">AccountId</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"struct\" href=\"lock_keeper/rpc/struct.Message.html\" title=\"struct lock_keeper::rpc::Message\">Message</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/arbitrary_secret/struct.Secret.html\" title=\"struct lock_keeper::crypto::arbitrary_secret::Secret\">Secret</a>&gt; for <a class=\"struct\" href=\"lock_keeper/crypto/struct.Export.html\" title=\"struct lock_keeper::crypto::Export\">Export</a>"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SendError&lt;T&gt;&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt; for <a class=\"enum\" href=\"lock_keeper/crypto/generic/enum.CryptoError.html\" title=\"enum lock_keeper::crypto::generic::CryptoError\">CryptoError</a>"]],
"lock_keeper_client":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;CryptoError&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://briansmith.org/rustdoc/webpki/error/enum.Error.html\" title=\"enum webpki::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/http/0.2.9/http/uri/struct.InvalidUri.html\" title=\"struct http::uri::InvalidUri\">InvalidUri</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;LockKeeperError&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ProtocolError&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/transport/error/struct.Error.html\" title=\"struct tonic::transport::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>"]],
"lock_keeper_client_cli":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;KeyId&gt; for <a class=\"struct\" href=\"lock_keeper_client_cli/storage/struct.Entry.html\" title=\"struct lock_keeper_client_cli::storage::Entry\">Entry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;GenerateResult&gt; for <a class=\"struct\" href=\"lock_keeper_client_cli/storage/struct.Entry.html\" title=\"struct lock_keeper_client_cli::storage::Entry\">Entry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;(KeyId, LocalStorage&lt;Secret&gt;)&gt; for <a class=\"struct\" href=\"lock_keeper_client_cli/storage/struct.Entry.html\" title=\"struct lock_keeper_client_cli::storage::Entry\">Entry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;(KeyId, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.71.0/std/primitive.u8.html\">u8</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;)&gt; for <a class=\"struct\" href=\"lock_keeper_client_cli/storage/struct.Entry.html\" title=\"struct lock_keeper_client_cli::storage::Entry\">Entry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;(KeyId, <a class=\"enum\" href=\"https://doc.rust-lang.org/1.71.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;LocalStorage&lt;Secret&gt;&gt;)&gt; for <a class=\"struct\" href=\"lock_keeper_client_cli/storage/struct.Entry.html\" title=\"struct lock_keeper_client_cli::storage::Entry\">Entry</a>"]],
"lock_keeper_key_server":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>&gt; for <a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ParseError&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_key_server/server/database/enum.DatabaseError.html\" title=\"enum lock_keeper_key_server::server::database::DatabaseError\">DatabaseError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.71.0/std/env/enum.VarError.html\" title=\"enum std::env::VarError\">VarError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;<a class=\"enum\" href=\"https://docs.rs/bincode/1.3.3/bincode/error/enum.ErrorKind.html\" title=\"enum bincode::error::ErrorKind\">ErrorKind</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ProtocolError&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_key_server/server/session_cache/enum.SessionCacheError.html\" title=\"enum lock_keeper_key_server::server::session_cache::SessionCacheError\">SessionCacheError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_key_server/server/database/enum.DatabaseError.html\" title=\"enum lock_keeper_key_server::server::database::DatabaseError\">DatabaseError</a>&gt; for <a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.3/tonic/transport/error/struct.Error.html\" title=\"struct tonic::transport::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://briansmith.org/rustdoc/webpki/error/enum.Error.html\" title=\"enum webpki::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;LockKeeperError&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>"]],
"lock_keeper_postgres":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;StoredSecret&gt; for <a class=\"struct\" href=\"lock_keeper_postgres/types/struct.SecretDB.html\" title=\"struct lock_keeper_postgres::types::SecretDB\">SecretDB</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_postgres/error/enum.ConfigError.html\" title=\"enum lock_keeper_postgres::error::ConfigError\">ConfigError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_postgres/error/enum.ConfigError.html\" title=\"enum lock_keeper_postgres::error::ConfigError\">ConfigError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_postgres/error/enum.PostgresError.html\" title=\"enum lock_keeper_postgres::error::PostgresError\">PostgresError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_postgres/error/enum.PostgresError.html\" title=\"enum lock_keeper_postgres::error::PostgresError\">PostgresError</a>&gt; for DatabaseError"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_postgres/error/enum.PostgresError.html\" title=\"enum lock_keeper_postgres::error::PostgresError\">PostgresError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;<a class=\"enum\" href=\"https://docs.rs/bincode/1.3.3/bincode/error/enum.ErrorKind.html\" title=\"enum bincode::error::ErrorKind\">ErrorKind</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_postgres/error/enum.PostgresError.html\" title=\"enum lock_keeper_postgres::error::PostgresError\">PostgresError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/core/array/struct.TryFromSliceError.html\" title=\"struct core::array::TryFromSliceError\">TryFromSliceError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_postgres/error/enum.PostgresError.html\" title=\"enum lock_keeper_postgres::error::PostgresError\">PostgresError</a>"]],
"lock_keeper_session_cache_sql":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>&gt; for SessionCacheError"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.ConfigError.html\" title=\"enum lock_keeper_session_cache_sql::error::ConfigError\">ConfigError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.ConfigError.html\" title=\"enum lock_keeper_session_cache_sql::error::ConfigError\">ConfigError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/core/array/struct.TryFromSliceError.html\" title=\"struct core::array::TryFromSliceError\">TryFromSliceError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;<a class=\"enum\" href=\"https://docs.rs/bincode/1.3.3/bincode/error/enum.ErrorKind.html\" title=\"enum bincode::error::ErrorKind\">ErrorKind</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/std/time/struct.SystemTimeError.html\" title=\"struct std::time::SystemTimeError\">SystemTimeError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_session_cache_sql/error/enum.Error.html\" title=\"enum lock_keeper_session_cache_sql::error::Error\">Error</a>"]],
"lock_keeper_tests":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;LockKeeperServerError&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"struct\" href=\"lock_keeper_tests/config/struct.TestFilters.html\" title=\"struct lock_keeper_tests::config::TestFilters\">TestFilters</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;DatabaseError&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;LockKeeperError&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;PostgresError&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://rust-random.github.io/rand/rand_core/error/struct.Error.html\" title=\"struct rand_core::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;LockKeeperClientError&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.71.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.71.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SessionCacheError&gt; for <a class=\"enum\" href=\"lock_keeper_tests/error/enum.LockKeeperTestError.html\" title=\"enum lock_keeper_tests::error::LockKeeperTestError\">LockKeeperTestError</a>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()