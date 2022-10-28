(function() {var implementors = {};
implementors["lock_keeper"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/config/client/struct.Config.html\" title=\"struct lock_keeper::config::client::Config\">Config</a>","synthetic":false,"types":["lock_keeper::config::client::Config"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/config/server/struct.Config.html\" title=\"struct lock_keeper::config::server::Config\">Config</a>","synthetic":false,"types":["lock_keeper::config::server::Config"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/config/server/struct.DatabaseSpec.html\" title=\"struct lock_keeper::config::server::DatabaseSpec\">DatabaseSpec</a>","synthetic":false,"types":["lock_keeper::config::server::DatabaseSpec"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/config/server/struct.Service.html\" title=\"struct lock_keeper::config::server::Service\">Service</a>","synthetic":false,"types":["lock_keeper::config::server::Service"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/arbitrary_secret/struct.Secret.html\" title=\"struct lock_keeper::crypto::arbitrary_secret::Secret\">Secret</a>","synthetic":false,"types":["lock_keeper::crypto::arbitrary_secret::Secret"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"lock_keeper/crypto/generic/enum.CryptoError.html\" title=\"enum lock_keeper::crypto::generic::CryptoError\">CryptoError</a>","synthetic":false,"types":["lock_keeper::crypto::generic::CryptoError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/generic/struct.AssociatedData.html\" title=\"struct lock_keeper::crypto::generic::AssociatedData\">AssociatedData</a>","synthetic":false,"types":["lock_keeper::crypto::generic::AssociatedData"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/generic/struct.Encrypted.html\" title=\"struct lock_keeper::crypto::generic::Encrypted\">Encrypted</a>&lt;T&gt;","synthetic":false,"types":["lock_keeper::crypto::generic::Encrypted"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/generic/struct.EncryptionKey.html\" title=\"struct lock_keeper::crypto::generic::EncryptionKey\">EncryptionKey</a>","synthetic":false,"types":["lock_keeper::crypto::generic::EncryptionKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/generic/struct.Secret.html\" title=\"struct lock_keeper::crypto::generic::Secret\">Secret</a>","synthetic":false,"types":["lock_keeper::crypto::generic::Secret"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.SignableBytes.html\" title=\"struct lock_keeper::crypto::signing_key::SignableBytes\">SignableBytes</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::SignableBytes"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.SigningKeyPair.html\" title=\"struct lock_keeper::crypto::signing_key::SigningKeyPair\">SigningKeyPair</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::SigningKeyPair"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.SigningPublicKey.html\" title=\"struct lock_keeper::crypto::signing_key::SigningPublicKey\">SigningPublicKey</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::SigningPublicKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.PlaceholderEncryptedSigningKeyPair.html\" title=\"struct lock_keeper::crypto::signing_key::PlaceholderEncryptedSigningKeyPair\">PlaceholderEncryptedSigningKeyPair</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::PlaceholderEncryptedSigningKeyPair"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.Import.html\" title=\"struct lock_keeper::crypto::signing_key::Import\">Import</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::Import"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.Export.html\" title=\"struct lock_keeper::crypto::signing_key::Export\">Export</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::Export"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/signing_key/struct.Signature.html\" title=\"struct lock_keeper::crypto::signing_key::Signature\">Signature</a>","synthetic":false,"types":["lock_keeper::crypto::signing_key::Signature"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/struct.OpaqueSessionKey.html\" title=\"struct lock_keeper::crypto::OpaqueSessionKey\">OpaqueSessionKey</a>","synthetic":false,"types":["lock_keeper::crypto::OpaqueSessionKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/struct.OpaqueExportKey.html\" title=\"struct lock_keeper::crypto::OpaqueExportKey\">OpaqueExportKey</a>","synthetic":false,"types":["lock_keeper::crypto::OpaqueExportKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/struct.StorageKey.html\" title=\"struct lock_keeper::crypto::StorageKey\">StorageKey</a>","synthetic":false,"types":["lock_keeper::crypto::StorageKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/crypto/struct.KeyId.html\" title=\"struct lock_keeper::crypto::KeyId\">KeyId</a>","synthetic":false,"types":["lock_keeper::crypto::KeyId"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"lock_keeper/types/audit_event/enum.EventStatus.html\" title=\"enum lock_keeper::types::audit_event::EventStatus\">EventStatus</a>","synthetic":false,"types":["lock_keeper::types::audit_event::EventStatus"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/types/database/user/struct.UserId.html\" title=\"struct lock_keeper::types::database::user::UserId\">UserId</a>","synthetic":false,"types":["lock_keeper::types::database::user::UserId"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/types/database/user/struct.AccountName.html\" title=\"struct lock_keeper::types::database::user::AccountName\">AccountName</a>","synthetic":false,"types":["lock_keeper::types::database::user::AccountName"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"lock_keeper/types/operations/retrieve/enum.RetrieveContext.html\" title=\"enum lock_keeper::types::operations::retrieve::RetrieveContext\">RetrieveContext</a>","synthetic":false,"types":["lock_keeper::types::operations::retrieve::RetrieveContext"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"lock_keeper/types/operations/enum.ClientAction.html\" title=\"enum lock_keeper::types::operations::ClientAction\">ClientAction</a>","synthetic":false,"types":["lock_keeper::types::operations::ClientAction"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/types/operations/struct.ClientActionIter.html\" title=\"struct lock_keeper::types::operations::ClientActionIter\">ClientActionIter</a>","synthetic":false,"types":["lock_keeper::types::operations::ClientActionIter"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/rpc/struct.Message.html\" title=\"struct lock_keeper::rpc::Message\">Message</a>","synthetic":false,"types":["lock_keeper::rpc::Message"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/rpc/struct.HealthCheck.html\" title=\"struct lock_keeper::rpc::HealthCheck\">HealthCheck</a>","synthetic":false,"types":["lock_keeper::rpc::HealthCheck"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/rpc/lock_keeper_rpc_client/struct.LockKeeperRpcClient.html\" title=\"struct lock_keeper::rpc::lock_keeper_rpc_client::LockKeeperRpcClient\">LockKeeperRpcClient</a>&lt;T&gt;","synthetic":false,"types":["lock_keeper::rpc::lock_keeper_rpc_client::LockKeeperRpcClient"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"lock_keeper/rpc/lock_keeper_rpc_server/trait.LockKeeperRpc.html\" title=\"trait lock_keeper::rpc::lock_keeper_rpc_server::LockKeeperRpc\">LockKeeperRpc</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/rpc/lock_keeper_rpc_server/struct.LockKeeperRpcServer.html\" title=\"struct lock_keeper::rpc::lock_keeper_rpc_server::LockKeeperRpcServer\">LockKeeperRpcServer</a>&lt;T&gt;","synthetic":false,"types":["lock_keeper::rpc::lock_keeper_rpc_server::LockKeeperRpcServer"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"lock_keeper/rpc/lock_keeper_rpc_server/trait.LockKeeperRpc.html\" title=\"trait lock_keeper::rpc::lock_keeper_rpc_server::LockKeeperRpc\">LockKeeperRpc</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper/rpc/lock_keeper_rpc_server/struct._Inner.html\" title=\"struct lock_keeper::rpc::lock_keeper_rpc_server::_Inner\">_Inner</a>&lt;T&gt;","synthetic":false,"types":["lock_keeper::rpc::lock_keeper_rpc_server::_Inner"]}];
implementors["lock_keeper_key_server"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper_key_server/database/struct.Database.html\" title=\"struct lock_keeper_key_server::database::Database\">Database</a>","synthetic":false,"types":["lock_keeper_key_server::database::Database"]}];
implementors["lock_keeper_tests"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"lock_keeper_tests/database/struct.TestDatabase.html\" title=\"struct lock_keeper_tests::database::TestDatabase\">TestDatabase</a>","synthetic":false,"types":["lock_keeper_tests::database::TestDatabase"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"lock_keeper_tests/utils/enum.TestResult.html\" title=\"enum lock_keeper_tests::utils::TestResult\">TestResult</a>","synthetic":false,"types":["lock_keeper_tests::utils::TestResult"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"lock_keeper_tests/enum.TestType.html\" title=\"enum lock_keeper_tests::TestType\">TestType</a>","synthetic":false,"types":["lock_keeper_tests::TestType"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()