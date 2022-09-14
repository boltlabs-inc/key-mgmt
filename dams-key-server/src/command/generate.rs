use crate::{server::Context, DamsServerError};

use crate::error::LogExt;
use dams::{
    channel::ServerChannel,
    crypto::KeyId,
    types::{
        generate::{client, server},
        Message, MessageStream,
    },
    user::UserId,
    ClientAction,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response};

#[derive(Debug)]
pub struct Generate;

impl Generate {
    pub async fn run<'a>(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, DamsServerError> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            // Generate step: receive UserId and reply with new KeyId
            let (key_id, user_id) = generate(&mut channel, &context).await?;
            // Store step: receive ciphertext from client and store in DB
            store(&mut channel, &context, &key_id)
                .await
                .log(&context.db, &user_id, Some(key_id), ClientAction::Generate)
                .await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn generate(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(KeyId, UserId), DamsServerError> {
    // Receive UserId from client
    let generate_message: client::Generate = channel.receive().await?;
    // Generate new KeyId
    let key_id = {
        let mut rng = context.rng.lock().await;
        KeyId::generate(&mut *rng, &generate_message.user_id)?
    };
    // Serialize KeyId and send to client
    let reply = server::Generate {
        key_id: key_id.clone(),
    };
    channel.send(reply).await?;
    Ok((key_id, generate_message.user_id))
}

async fn store(
    channel: &mut ServerChannel,
    context: &Context,
    key_id: &KeyId,
) -> Result<(), DamsServerError> {
    // Receive Encrypted<Secret> from client
    let store_message: client::Store = channel.receive().await?;

    // Check validity of ciphertext and store in DB
    context
        .db
        .add_user_secret(
            &store_message.user_id,
            store_message.ciphertext,
            key_id.clone(),
        )
        .await?;

    // Reply with the success:true if successful
    let reply = server::Store { success: true };
    channel.send(reply).await?;

    // TODO #67 (implementation): Log that a new key was generated and stored

    Ok(())
}
