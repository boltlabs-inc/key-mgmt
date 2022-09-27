(function() {var implementors = {};
implementors["lock_keeper"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/struct.Secret.html\" title=\"struct lock_keeper::crypto::Secret\">Secret</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/std/primitive.u8.html\">u8</a>&gt;","synthetic":false,"types":["alloc::vec::Vec"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/struct.SigningKeyPair.html\" title=\"struct lock_keeper::crypto::SigningKeyPair\">SigningKeyPair</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/std/primitive.u8.html\">u8</a>&gt;","synthetic":false,"types":["alloc::vec::Vec"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;GenericArray&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/std/primitive.u8.html\">u8</a>, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;&gt;&gt; for <a class=\"struct\" href=\"lock_keeper/crypto/struct.OpaqueSessionKey.html\" title=\"struct lock_keeper::crypto::OpaqueSessionKey\">OpaqueSessionKey</a>","synthetic":false,"types":["lock_keeper::crypto::OpaqueSessionKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;GenericArray&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/std/primitive.u8.html\">u8</a>, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;<a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;, <a class=\"struct\" href=\"https://docs.rs/typenum/1.15.0/typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>&gt;&gt;&gt; for <a class=\"struct\" href=\"lock_keeper/crypto/struct.OpaqueExportKey.html\" title=\"struct lock_keeper::crypto::OpaqueExportKey\">OpaqueExportKey</a>","synthetic":false,"types":["lock_keeper::crypto::OpaqueExportKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/crypto/struct.StorageKey.html\" title=\"struct lock_keeper::crypto::StorageKey\">StorageKey</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/std/primitive.u8.html\">u8</a>&gt;","synthetic":false,"types":["alloc::vec::Vec"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper/crypto/enum.CryptoError.html\" title=\"enum lock_keeper::crypto::CryptoError\">CryptoError</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;<a class=\"enum\" href=\"https://docs.rs/bincode/1.3.3/bincode/error/enum.ErrorKind.html\" title=\"enum bincode::error::ErrorKind\">ErrorKind</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/alloc/alloc/struct.Global.html\" title=\"struct alloc::alloc::Global\">Global</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/http/0.2.8/http/uri/struct.InvalidUri.html\" title=\"struct http::uri::InvalidUri\">InvalidUri</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/toml/0.5/toml/de/struct.Error.html\" title=\"struct toml::de::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://briansmith.org/rustdoc/webpki/error/enum.Error.html\" title=\"enum webpki::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ProtocolError&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;SendError&lt;T&gt;&gt; for <a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>","synthetic":false,"types":["lock_keeper::error::LockKeeperError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>&gt; for <a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>","synthetic":false,"types":["tonic::status::Status"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"lock_keeper/user/struct.UserId.html\" title=\"struct lock_keeper::user::UserId\">UserId</a>&gt; for <a class=\"enum\" href=\"https://docs.rs/bson/2.3.0/bson/bson/enum.Bson.html\" title=\"enum bson::bson::Bson\">Bson</a>","synthetic":false,"types":["bson::bson::Bson"]}];
implementors["lock_keeper_client"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper/crypto/generic/enum.CryptoError.html\" title=\"enum lock_keeper::crypto::generic::CryptoError\">CryptoError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>","synthetic":false,"types":["lock_keeper_client::error::LockKeeperClientError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/metadata/encoding/struct.InvalidMetadataValue.html\" title=\"struct tonic::metadata::encoding::InvalidMetadataValue\">InvalidMetadataValue</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>","synthetic":false,"types":["lock_keeper_client::error::LockKeeperClientError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/transport/error/struct.Error.html\" title=\"struct tonic::transport::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>","synthetic":false,"types":["lock_keeper_client::error::LockKeeperClientError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ProtocolError&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>","synthetic":false,"types":["lock_keeper_client::error::LockKeeperClientError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>","synthetic":false,"types":["lock_keeper_client::error::LockKeeperClientError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper/error/enum.LockKeeperError.html\" title=\"enum lock_keeper::error::LockKeeperError\">LockKeeperError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_client/error/enum.LockKeeperClientError.html\" title=\"enum lock_keeper_client::error::LockKeeperClientError\">LockKeeperClientError</a>","synthetic":false,"types":["lock_keeper_client::error::LockKeeperClientError"]}];
implementors["lock_keeper_key_server"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;LockKeeperError&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;Error&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.64.0/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/bson/2.3.0/bson/ser/error/enum.Error.html\" title=\"enum bson::ser::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/transport/error/struct.Error.html\" title=\"struct tonic::transport::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.64.0/std/env/enum.VarError.html\" title=\"enum std::env::VarError\">VarError</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/mongodb/2.3.0/mongodb/error/struct.Error.html\" title=\"struct mongodb::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;ProtocolError&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/enum.Infallible.html\" title=\"enum core::convert::Infallible\">Infallible</a>&gt;&gt; for <a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>","synthetic":false,"types":["lock_keeper_key_server::error::LockKeeperServerError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"lock_keeper_key_server/error/enum.LockKeeperServerError.html\" title=\"enum lock_keeper_key_server::error::LockKeeperServerError\">LockKeeperServerError</a>&gt; for <a class=\"struct\" href=\"https://docs.rs/tonic/0.8.1/tonic/status/struct.Status.html\" title=\"struct tonic::status::Status\">Status</a>","synthetic":false,"types":["tonic::status::Status"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()