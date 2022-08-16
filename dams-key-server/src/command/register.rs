use crate::database::user as User;
use std::sync::{Arc, Mutex};

use dams::{
    config::{opaque::OpaqueCipherSuite, server::Service},
    dams_rpc::{
        client_register::Step as ClientStep, server_register::Step as ServerStep, ClientRegister,
        ClientRegisterFinish, ClientRegisterStart, ServerRegister, ServerRegisterFinish,
        ServerRegisterStart,
    },
    opaque_storage::create_or_retrieve_server_key_opaque,
};
use mongodb::Database;
use opaque_ke::{
    keypair::PrivateKey, RegistrationRequest, RegistrationUpload, Ristretto255, ServerRegistration,
    ServerSetup,
};
use rand::rngs::StdRng;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct Register;

pub type RegisterStream = ReceiverStream<Result<ServerRegister, Status>>;

impl Register {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        request: Request<tonic::Streaming<ClientRegister>>,
        db: &Database,
        rng: Arc<Mutex<StdRng>>,
        service: &Service,
    ) -> Result<Response<RegisterStream>, Status> {
        let (tx, rx) = mpsc::channel(2);
        let mut stream = request.into_inner();

        // Get server key for OPAQUE
        let server_setup = {
            let mut rng = rng
                .lock()
                .map_err(|_| Status::unavailable("Unable to access RNG"))?;

            create_or_retrieve_server_key_opaque(&mut rng, service)
                .map_err(|_| Status::aborted("could not find/create server key"))?
        };

        // Clone db outside of thread to prevent lifetime errors
        let db = db.clone();

        let _ = tokio::spawn(async move {
            // Process start step
            if let Some(message) = stream.next().await {
                let message = message?;

                let start_message = Self::unwrap_client_start_step(message.step)?;
                let response = Self::handle_register_start(&db, start_message, &server_setup).await;
                tx.send(response)
                    .await
                    .map_err(|e| Status::aborted(e.to_string()))?;
            }

            // Process finish step
            if let Some(message) = stream.next().await {
                let message = message?;

                let finish_message = Self::unwrap_client_finish_step(message.step)?;
                let response = Self::handle_register_finish(&db, finish_message).await;
                tx.send(response)
                    .await
                    .map_err(|e| Status::aborted(e.to_string()))?;
            }

            Ok::<(), Status>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /*
     * Helper functions to clean up message ordering
     */

    fn unwrap_client_start_step(step: Option<ClientStep>) -> Result<ClientRegisterStart, Status> {
        match step {
            Some(ClientStep::Start(start_message)) => Ok(start_message),
            Some(ClientStep::Finish(_)) => {
                Err(Status::invalid_argument("Message received out of order"))
            }
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    async fn handle_register_start(
        db: &Database,
        message: ClientRegisterStart,
        server_setup: &ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>,
    ) -> Result<ServerRegister, Status> {
        // Convert user_id from message to str and then to UserId
        let uid = super::user_id_from_message(&message.user_id)?;
        let registration_request_message: RegistrationRequest<OpaqueCipherSuite> =
            dams::deserialize_from_bytes(&message.client_register_start_message[..])?;
        // Abort registration if UserId already exists
        if User::find_user(db, &uid)
            .await
            .map_err(|_| Status::aborted("MongoDB error"))?
            .is_some()
        {
            Err(Status::already_exists("UserID already exists"))
        } else {
            // Registration can continue if user ID doesn't exist yet
            let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
                server_setup,
                registration_request_message,
                uid.as_bytes(),
            )
            .map_err(|_| Status::aborted("Could not start server registration"))?;

            let server_register_start_message =
                dams::serialize_to_bytes(&server_registration_start_result.message)?;
            let reply = ServerRegister {
                step: Some(ServerStep::Start(ServerRegisterStart {
                    server_register_start_message,
                })),
            };
            Ok(reply)
        }
    }

    fn unwrap_client_finish_step(step: Option<ClientStep>) -> Result<ClientRegisterFinish, Status> {
        match step {
            Some(ClientStep::Start(_)) => {
                Err(Status::invalid_argument("Message received out of order"))
            }
            Some(ClientStep::Finish(finish_message)) => Ok(finish_message),
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    async fn handle_register_finish(
        db: &Database,
        message: ClientRegisterFinish,
    ) -> Result<ServerRegister, Status> {
        // Convert user_id from message to str and then to UserId
        let uid = super::user_id_from_message(&message.user_id)?;

        // deserialize client message into RegistrationUpload OPAQUE type
        let register_finish: RegistrationUpload<OpaqueCipherSuite> =
            dams::deserialize_from_bytes(&message.client_register_finish_message[..])?;
        // run the finish step for OPAQUE
        let server_registration = ServerRegistration::<OpaqueCipherSuite>::finish(register_finish);
        // add the new user to the DB
        let _ = User::create_user(db, &uid, server_registration)
            .await
            .map_err(|_| Status::aborted("Unable to create user"));

        // reply with the success:true if successful
        let reply = ServerRegister {
            step: Some(ServerStep::Finish(ServerRegisterFinish { success: true })),
        };
        Ok(reply)
    }
}
