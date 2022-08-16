use crate::database::user as User;

use dams::{
    config::{opaque::OpaqueCipherSuite, server::Service},
    dams_rpc::{
        client_authenticate::Step as ClientStep, server_authenticate::Step as ServerStep,
        ClientAuthenticate, ClientAuthenticateFinish, ClientAuthenticateStart, ServerAuthenticate,
        ServerAuthenticateFinish, ServerAuthenticateStart,
    },
    opaque_storage::create_or_retrieve_server_key_opaque,
};
use mongodb::Database;
use opaque_ke::{
    keypair::PrivateKey, CredentialFinalization, CredentialRequest, Ristretto255, ServerLogin,
    ServerLoginStartParameters, ServerLoginStartResult, ServerSetup,
};
use rand::rngs::StdRng;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{Request, Response, Status};

struct AuthStartResult {
    result: Result<ServerAuthenticate, Status>,
    server_message: ServerLoginStartResult<OpaqueCipherSuite>,
}

#[derive(Debug)]
pub struct Authenticate;

pub type AuthenticateStream = ReceiverStream<Result<ServerAuthenticate, Status>>;

impl Authenticate {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        request: Request<tonic::Streaming<ClientAuthenticate>>,
        db: &Database,
        rng: Arc<Mutex<StdRng>>,
        service: &Service,
    ) -> Result<Response<AuthenticateStream>, Status> {
        let (tx, rx) = mpsc::channel(2);
        let mut stream = request.into_inner();

        let server_setup = {
            let mut local_rng = rng
                .lock()
                .map_err(|_| Status::unavailable("Unable to access RNG"))?;
            create_or_retrieve_server_key_opaque(&mut local_rng, service)
                .map_err(|_| Status::aborted("could not find/create server key"))?
        };

        // Clone db outside of thread to prevent lifetime errors
        let db = db.clone();
        // let server_setup = server_setup.clone();

        let _ = tokio::spawn(async move {
            let mut server_login_result: Option<ServerLoginStartResult<OpaqueCipherSuite>> = None;
            // Process start step
            if let Some(message) = stream.next().await {
                let message = message?;
                let start_message = Self::unwrap_client_start_step(message.step)?;
                let response =
                    Self::handle_authenticate_start(&db, start_message, rng, &server_setup).await?;
                server_login_result = Some(response.server_message);
                tx.send(response.result)
                    .await
                    .map_err(|e| Status::aborted(e.to_string()))?;
            }

            // Process finish step
            if let Some(message) = stream.next().await {
                let message = message?;

                let finish_message = Self::unwrap_client_finish_step(message.step)?;
                let response =
                    Self::handle_authenticate_finish(finish_message, server_login_result).await;
                let _ = tx
                    .send(response)
                    .await
                    .map_err(|e| Status::aborted(e.to_string()));
            }

            Ok::<(), Status>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /*
     * Helper functions to clean up message ordering
     */

    fn unwrap_client_start_step(
        step: Option<ClientStep>,
    ) -> Result<ClientAuthenticateStart, Status> {
        match step {
            Some(ClientStep::Start(start_message)) => Ok(start_message),
            Some(ClientStep::Finish(_)) => {
                Err(Status::invalid_argument("Message received out of order"))
            }
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    async fn handle_authenticate_start(
        db: &Database,
        message: ClientAuthenticateStart,
        rng: Arc<Mutex<StdRng>>,
        server_setup: &ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>,
    ) -> Result<AuthStartResult, Status> {
        // Convert user_id from message to str and then to UserId
        let uid = super::user_id_from_message(&message.user_id)?;

        let server_registration = match User::find_user(db, &uid)
            .await
            .map_err(|_| Status::aborted("MongoDB error"))?
        {
            Some(user) => user.into_server_registration(),
            None => return Err(Status::already_exists("UserId already exists")),
        };
        let credential_request: CredentialRequest<OpaqueCipherSuite> =
            dams::deserialize_from_bytes(&message.client_authenticate_start_message[..])?;

        let server_login_start_result = {
            let mut local_rng = rng
                .lock()
                .map_err(|_| Status::unavailable("Unable to access RNG"))?;

            match ServerLogin::start(
                &mut *local_rng,
                server_setup,
                Some(server_registration),
                credential_request,
                uid.as_bytes(),
                ServerLoginStartParameters::default(),
            ) {
                Ok(server_login_start_result) => server_login_start_result,
                Err(_) => return Err(Status::aborted("Server error")),
            }
        };

        let server_authenticate_start_message =
            dams::serialize_to_bytes(&server_login_start_result.message)?;
        let reply = ServerAuthenticate {
            step: Some(ServerStep::Start(ServerAuthenticateStart {
                server_authenticate_start_message,
            })),
        };
        Ok(AuthStartResult {
            result: Ok(reply),
            server_message: server_login_start_result,
        })
    }

    fn unwrap_client_finish_step(
        step: Option<ClientStep>,
    ) -> Result<ClientAuthenticateFinish, Status> {
        match step {
            Some(ClientStep::Start(_)) => {
                Err(Status::invalid_argument("Message received out of order"))
            }
            Some(ClientStep::Finish(finish_message)) => Ok(finish_message),
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    async fn handle_authenticate_finish(
        message: ClientAuthenticateFinish,
        server_login_result: Option<ServerLoginStartResult<OpaqueCipherSuite>>,
    ) -> Result<ServerAuthenticate, Status> {
        let server_login_result = match server_login_result {
            Some(res) => res,
            None => return Err(Status::aborted("No login result found")),
        };
        // deserialize client message into RegistrationUpload OPAQUE type
        let auth_finish: CredentialFinalization<OpaqueCipherSuite> =
            dams::deserialize_from_bytes(&message.client_authenticate_finish_message[..])?;
        match server_login_result.state.finish(auth_finish) {
            Ok(_) => {
                let reply = ServerAuthenticate {
                    step: Some(ServerStep::Finish(ServerAuthenticateFinish {
                        success: true,
                    })),
                };
                Ok(reply)
            }
            Err(_) => Err(Status::unauthenticated("Could not authenticate")),
        }
    }
}
